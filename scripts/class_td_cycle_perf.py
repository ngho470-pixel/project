#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import statistics
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / 'custom_filter' / 'custom_filter.so')
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / 'artifact_builder' / 'artifact_builder.so')

OUT_CSV = REPO_ROOT / 'logs' / 'class_td_cycle_stage45_perf.csv'
OUT_MD = REPO_ROOT / 'logs' / 'class_td_cycle_stage45_perf.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'class_td_cycle_policy.txt'


@dataclass(frozen=True)
class Policy:
    code: str
    line: str
    target: str


@dataclass(frozen=True)
class PerfCase:
    policy_code: str
    query_id: str
    expect_route: str


POLICIES: Tuple[Policy, ...] = (
    Policy('TDC1', "1. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND lineitem.l_quantity > 10 AND partsupp.ps_availqty > 10", 'lineitem'),
    Policy('TDC2', "3. lineitem: lineitem.l_suppkey = supplier.s_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_nationkey = supplier.s_nationkey AND lineitem.l_quantity > 10 AND supplier.s_suppkey <= 1000 AND customer.c_custkey <= 50000 AND orders.o_orderkey <= 200000", 'lineitem'),
    Policy('TDR1', "5. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem'),
    Policy('TDC3', "7. lineitem: lineitem.l_suppkey = supplier.s_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_nationkey = supplier.s_nationkey AND lineitem.l_orderkey >= orders.o_orderkey AND lineitem.l_quantity > 10 AND orders.o_orderkey <= 10000 AND customer.c_custkey <= 5000 AND supplier.s_suppkey <= 1000", 'lineitem'),
)

CASES: Tuple[PerfCase, ...] = (
    PerfCase('TDC1', '6', 'td_cycle'),
    PerfCase('TDC2', '1', 'td_cycle'),
    PerfCase('TDR1', '6', 'cycle_rect'),
    PerfCase('TDC3', '1', 'td_cycle'),
)


@contextmanager
def strict_env():
    old_pgoptions = os.environ.get('PGOPTIONS')
    old_cf_strict = os.environ.get('CF_POLICY_STRICT_MODE')
    os.environ['PGOPTIONS'] = '-c custom_filter.strict_mode=on'
    os.environ['CF_POLICY_STRICT_MODE'] = '1'
    try:
        yield
    finally:
        if old_pgoptions is None:
            os.environ.pop('PGOPTIONS', None)
        else:
            os.environ['PGOPTIONS'] = old_pgoptions
        if old_cf_strict is None:
            os.environ.pop('CF_POLICY_STRICT_MODE', None)
        else:
            os.environ['CF_POLICY_STRICT_MODE'] = old_cf_strict


def run_hygiene(db: str) -> None:
    cmd = [sys.executable, str(REPO_ROOT / 'scripts' / 'pg_hygiene.py'), '--db', db, '--kill-nonidle', '--fail-loud']
    subprocess.run(cmd, check=True)


def write_policy_file() -> None:
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text('\n'.join(p.line for p in POLICIES) + '\n', encoding='utf-8')


def qmap() -> Dict[str, str]:
    return {qid: q for qid, q in h.load_queries(REPO_ROOT / 'queries.txt')}


def pol(code: str) -> Policy:
    return next(p for p in POLICIES if p.code == code)


def run_count_hash(db: str, baseline: str, qid: str, qsql: str, enabled_path: Path, timeout_ms: int):
    conn = None
    try:
        conn = h.connect(db, h.role_for_baseline(baseline))
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, timeout_ms)
            if baseline in ('rls', 'rls_with_index'):
                cur.execute('SET row_security = on;')
            cnt, hh = h.result_count_and_hash_in_session(cur, qid, qsql)
            return int(cnt), str(hh or ''), ''
    except Exception as exc:  # noqa: BLE001
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
    finally:
        if conn is not None:
            conn.close()


def run_profile_probe(db: str, qid: str, qsql: str, enabled_path: Path, timeout_ms: int, profile_k: int):
    try:
        with strict_env():
            m, _payload, _kv, _cnt, notices = h.run_ours_profile_capture(
                db,
                qsql,
                enabled_path,
                timeout_ms,
                ours_profile_rescan=False,
                ours_debug_mode='trace',
                query_id=qid,
                profile_k=profile_k,
                profile_query=qid,
            )
        _pp_payload, pp_kv, _pp_cnt = h.extract_policy_profile(notices)
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        saw_empty_mode = any(("scan_mode_decision:" in ln and "mode=EMPTY" in ln) for ln in notices)
        err = '' if m.status == 'ok' else (m.error_msg or 'profile capture failed')
        return ppq_kv, pp_kv, saw_empty_mode, err
    except Exception as exc:  # noqa: BLE001
        return {}, {}, False, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]


def avg_hot_ms(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [x.elapsed_ms for x in hots if x.status == 'ok']
    return (sum(vals) / len(vals)) if vals else None


def avg_hot_rss_kb(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [float(x.peak_rss_kb) for x in hots if x.status == 'ok']
    return (sum(vals) / len(vals)) if vals else None


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description='Class-engine TD-cycle perf probe')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--statement-timeout', default='30min')
    ap.add_argument('--hot-runs', type=int, default=1)
    ap.add_argument('--out-csv', default=str(OUT_CSV))
    ap.add_argument('--out-md', default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = qmap()
    write_policy_file()

    cols = [
        'db', 'policy_code', 'policy_target', 'query_id', 'expect_route', 'enabled_policy_id',
        'ours_hot_avg_ms', 'rls_hot_avg_ms', 'ours_vs_rls_ratio',
        'ours_hot_avg_peak_rss_kb', 'rls_hot_avg_peak_rss_kb',
        'correctness', 'status', 'error_type', 'error_msg',
        'ours_rows', 'ours_hash', 'gt_rows', 'gt_hash',
        'class_td_terms_total', 'class_td_terms_supported', 'class_td_width_max', 'class_td_bags',
        'class_td_build_ms', 'class_td_dp_ms', 'class_td_msg_entries_total', 'class_td_msg_bytes_total',
        'class_td_msg_pairs_total', 'class_td_join_ms', 'class_td_project_ms',
        'class_td_reduction_passes', 'class_td_reduction_ms', 'class_td_reduction_removed_pairs',
        'class_td_pairs_before', 'class_td_pairs_after', 'class_td_elim_order',
        'class_td_peak_msg_pairs', 'class_td_peak_msg_bytes',
        'class_td_cmp_filter_ms', 'class_td_cmp_filter_removed_pairs',
        'class_td_fail_width',
        'class_route_cycle_rect', 'class_route_td_cycle',
        'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
        'scan_mode_empty_tables', 'empty_short_circuit_tables', 'empty_short_circuit_ms', 'scan_mode_empty_seen',
        'query_short_circuit_empty', 'query_short_circuit_reason', 'query_short_circuit_ms', 'query_short_circuit_hits',
    ]
    rows: List[Dict[str, str]] = []

    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qsql = queries[c.query_id]
        enabled = Path('/tmp') / f'class_td_cycle_perf_{c.policy_code}_{c.query_id}.txt'
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)

        row = {k: '' for k in cols}
        row.update({
            'db': db,
            'policy_code': p.code,
            'policy_target': p.target,
            'query_id': c.query_id,
            'expect_route': c.expect_route,
            'enabled_policy_id': p.line.split('.', 1)[0].strip(),
            'status': 'error',
        })

        try:
            run_hygiene(db)
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
            h.clear_rls_indexes_and_policies(db)
            h.apply_rls_policies_for_k(db, [p.line])
            h.create_rls_indexes_for_k(db, idx, [p.line], timeout_ms)

            with strict_env():
                _ours_cold, ours_hots = h.run_query_series(
                    db, 'ours', qsql, args.hot_runs, enabled, timeout_ms, query_id=c.query_id
                )
            _rls_cold, rls_hots = h.run_query_series(
                db, 'rls_with_index', qsql, args.hot_runs, enabled, timeout_ms, query_id=c.query_id
            )

            ours_avg = avg_hot_ms(ours_hots)
            rls_avg = avg_hot_ms(rls_hots)
            ratio = (ours_avg / rls_avg) if (ours_avg is not None and rls_avg not in (None, 0.0)) else None
            row['ours_hot_avg_ms'] = '' if ours_avg is None else f"{ours_avg:.3f}"
            row['rls_hot_avg_ms'] = '' if rls_avg is None else f"{rls_avg:.3f}"
            row['ours_vs_rls_ratio'] = '' if ratio is None else f"{ratio:.3f}"
            row['ours_hot_avg_peak_rss_kb'] = '' if (v := avg_hot_rss_kb(ours_hots)) is None else f"{v:.0f}"
            row['rls_hot_avg_peak_rss_kb'] = '' if (v := avg_hot_rss_kb(rls_hots)) is None else f"{v:.0f}"

            with strict_env():
                oc, oh, oerr = run_count_hash(db, 'ours', c.query_id, qsql, enabled, timeout_ms)
            gc, gh, gerr = run_count_hash(db, 'rls_with_index', c.query_id, qsql, enabled, timeout_ms)
            row['ours_rows'] = '' if oc is None else str(oc)
            row['ours_hash'] = '' if oh is None else str(oh)
            row['gt_rows'] = '' if gc is None else str(gc)
            row['gt_hash'] = '' if gh is None else str(gh)

            ppq, pp, saw_empty_mode, perr = run_profile_probe(db, c.query_id, qsql, enabled, timeout_ms, idx)
            for k in [
                'class_td_terms_total', 'class_td_terms_supported', 'class_td_width_max', 'class_td_bags',
                'class_td_build_ms', 'class_td_dp_ms', 'class_td_msg_entries_total', 'class_td_msg_bytes_total',
                'class_td_msg_pairs_total', 'class_td_join_ms', 'class_td_project_ms',
                'class_td_reduction_passes', 'class_td_reduction_ms', 'class_td_reduction_removed_pairs',
                'class_td_pairs_before', 'class_td_pairs_after', 'class_td_elim_order',
                'class_td_peak_msg_pairs', 'class_td_peak_msg_bytes',
                'class_td_cmp_filter_ms', 'class_td_cmp_filter_removed_pairs',
                'class_td_fail_width',
                'class_route_cycle_rect', 'class_route_td_cycle',
                'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
            ]:
                row[k] = ppq.get(k, '')
            row['scan_mode_empty_tables'] = pp.get('scan_mode_empty_tables', '')
            row['empty_short_circuit_tables'] = pp.get('empty_short_circuit_tables', '')
            row['empty_short_circuit_ms'] = pp.get('empty_short_circuit_ms', '')
            row['scan_mode_empty_seen'] = '1' if saw_empty_mode else '0'
            row['query_short_circuit_empty'] = pp.get('query_short_circuit_empty', '')
            row['query_short_circuit_reason'] = pp.get('query_short_circuit_reason', '')
            row['query_short_circuit_ms'] = pp.get('query_short_circuit_ms', '')
            row['query_short_circuit_hits'] = pp.get('query_short_circuit_hits', '')

            if None in (oc, oh, gc, gh):
                row['status'] = 'error'
                row['error_type'] = 'runtime'
                row['error_msg'] = f"ours={oerr if oc is None else ''} gt={gerr if gc is None else ''}".strip()
                row['correctness'] = 'ERROR'
            else:
                row['correctness'] = 'PASS' if (int(oc) == int(gc) and str(oh) == str(gh)) else 'FAIL'
                row['status'] = 'ok' if row['correctness'] == 'PASS' else 'fail'
                if row['correctness'] != 'PASS':
                    row['error_type'] = 'mismatch'
                    row['error_msg'] = 'rows/hash mismatch'

            for inv in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                if str(row.get(inv, '0')) not in ('0', '0.000', ''):
                    row['status'] = 'fail'
                    row['correctness'] = 'FAIL'
                    row['error_type'] = 'invariant'
                    row['error_msg'] = f'{inv}={row.get(inv)}'
                    break

            if row['status'] == 'ok':
                if c.expect_route == 'td_cycle' and str(row.get('class_route_td_cycle', '0')) in ('', '0'):
                    row['status'] = 'fail'
                    row['correctness'] = 'FAIL'
                    row['error_type'] = 'route'
                    row['error_msg'] = 'missing class_route_td_cycle'
                if c.expect_route == 'cycle_rect' and str(row.get('class_route_cycle_rect', '0')) in ('', '0'):
                    row['status'] = 'fail'
                    row['correctness'] = 'FAIL'
                    row['error_type'] = 'route'
                    row['error_msg'] = 'missing class_route_cycle_rect'
            if row['status'] == 'ok' and row.get('ours_vs_rls_ratio'):
                ratio_v = float(row['ours_vs_rls_ratio'])
                if c.policy_code in ('TDC2', 'TDC3') and ratio_v > 0.85:
                    row['status'] = 'fail'
                    row['correctness'] = 'FAIL'
                    row['error_type'] = 'perf_gate'
                    row['error_msg'] = f'{c.policy_code} ratio {ratio_v:.3f} > 0.85'
                if c.policy_code == 'TDC2':
                    mp = row.get('class_td_msg_pairs_total', '')
                    if mp and int(mp) > 300000:
                        row['status'] = 'fail'
                        row['correctness'] = 'FAIL'
                        row['error_type'] = 'perf_gate'
                        row['error_msg'] = f'TDC2 class_td_msg_pairs_total {mp} > 300000'
                if c.policy_code == 'TDC3':
                    empty_tables = int(row.get('scan_mode_empty_tables') or 0)
                    empty_seen = row.get('scan_mode_empty_seen', '0') == '1'
                    q_sc = int(row.get('query_short_circuit_empty') or 0)
                    q_hits = int(row.get('query_short_circuit_hits') or 0)
                    if not empty_seen and empty_tables < 1 and (q_sc == 0 or q_hits < 1):
                        row['status'] = 'fail'
                        row['correctness'] = 'FAIL'
                        row['error_type'] = 'evidence'
                        row['error_msg'] = 'missing EMPTY/QUERY short-circuit evidence on TDC3'

            if perr and row['status'] == 'ok':
                row['status'] = 'error'
                row['error_type'] = 'profile'
                row['error_msg'] = perr
        except Exception as exc:  # noqa: BLE001
            row['status'] = 'error'
            row['correctness'] = 'ERROR'
            row['error_type'] = 'exception'
            row['error_msg'] = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
        finally:
            try:
                h.clear_artifacts(db)
            except Exception:
                pass
            try:
                h.clear_rls_indexes_and_policies(db)
            except Exception:
                pass

        rows.append(row)
        print(f"[class_td_cycle_perf] {p.code} q{c.query_id} status={row['status']} correctness={row.get('correctness','')}")

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    ratios = [float(r['ours_vs_rls_ratio']) for r in rows if r.get('ours_vs_rls_ratio')]
    median_ratio = statistics.median(ratios) if ratios else float('nan')

    lines = [
        '# Class Engine TD-Cycle Scan-Cut Perf',
        '',
        f"- db: `{db}`",
        '- mode: `strict_mode=on`',
        f"- cases: {len(rows)}",
        f"- median ours/rls hot-time ratio: {median_ratio:.3f} (target <= 0.75)" if ratios else '- median ours/rls hot-time ratio: n/a',
        '',
        '## Cases',
    ]
    for r in rows:
        lines.append(
            f"- {r['policy_code']} target={r['policy_target']} q{r['query_id']}: "
            f"status={r['status']} correctness={r.get('correctness','')} ours={r.get('ours_hot_avg_ms','')}ms "
            f"rls={r.get('rls_hot_avg_ms','')}ms ours/rls={r.get('ours_vs_rls_ratio','')} "
            f"route(td/rect)={r.get('class_route_td_cycle','')}/{r.get('class_route_cycle_rect','')} "
            f"empty(mode_seen/tables/short/ms)={r.get('scan_mode_empty_seen','')}/{r.get('scan_mode_empty_tables','')}/{r.get('empty_short_circuit_tables','')}/{r.get('empty_short_circuit_ms','')} "
            f"query_sc(empty/reason/ms/hits)={r.get('query_short_circuit_empty','')}/{r.get('query_short_circuit_reason','')}/{r.get('query_short_circuit_ms','')}/{r.get('query_short_circuit_hits','')} "
            f"td(width/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm/build/dp)="
            f"{r.get('class_td_width_max','')}/{r.get('class_td_bags','')}/{r.get('class_td_msg_entries_total','')}/{r.get('class_td_msg_bytes_total','')}/{r.get('class_td_msg_pairs_total','')}/{r.get('class_td_join_ms','')}/{r.get('class_td_project_ms','')}/{r.get('class_td_reduction_ms','')}/{r.get('class_td_reduction_passes','')}/{r.get('class_td_reduction_removed_pairs','')}/{r.get('class_td_pairs_before','')}/{r.get('class_td_pairs_after','')}/{r.get('class_td_elim_order','')}/{r.get('class_td_peak_msg_pairs','')}/{r.get('class_td_peak_msg_bytes','')}/{r.get('class_td_cmp_filter_ms','')}/{r.get('class_td_cmp_filter_removed_pairs','')}/{r.get('class_td_build_ms','')}/{r.get('class_td_dp_ms','')} "
            f"proj_sig/mask/rid={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"err={r.get('error_msg','')}"
        )
    if ratios:
        if median_ratio > 0.75:
            lines.append('')
            lines.append(f"- PERF_GATE_FAIL: median ours/rls {median_ratio:.3f} > 0.75")
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
