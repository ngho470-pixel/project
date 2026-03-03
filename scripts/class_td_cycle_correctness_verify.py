#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / 'custom_filter' / 'custom_filter.so')
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / 'artifact_builder' / 'artifact_builder.so')

OUT_CSV = REPO_ROOT / 'logs' / 'class_td_cycle_stage45_correctness.csv'
OUT_MD = REPO_ROOT / 'logs' / 'class_td_cycle_stage45_correctness.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'class_td_cycle_policy.txt'


@dataclass(frozen=True)
class Policy:
    code: str
    line: str
    target: str
    notes: str


@dataclass(frozen=True)
class Case:
    policy_code: str
    query_id: str
    expect_route: str  # td_cycle | cycle_rect


POLICIES: Tuple[Policy, ...] = (
    Policy(
        'TDC1',
        "1. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND lineitem.l_quantity > 10 AND partsupp.ps_availqty > 10",
        'lineitem',
        'two-table/two-domain cyclic join (non-rectangle comparator-free)',
    ),
    Policy(
        'TDC2',
        "3. lineitem: lineitem.l_suppkey = supplier.s_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_nationkey = supplier.s_nationkey AND lineitem.l_quantity > 10 AND supplier.s_suppkey <= 1000 AND customer.c_custkey <= 50000 AND orders.o_orderkey <= 200000",
        'lineitem',
        'four-table ring cycle (width 2 target)',
    ),
    Policy(
        'TDR1',
        "5. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity <= partsupp.ps_availqty)",
        'lineitem',
        'rectangle comparator case should stay on cycle_rect fast path',
    ),
    Policy(
        'TDC3',
        "7. lineitem: lineitem.l_suppkey = supplier.s_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_nationkey = supplier.s_nationkey AND lineitem.l_orderkey >= orders.o_orderkey AND lineitem.l_quantity > 10 AND orders.o_orderkey <= 10000 AND customer.c_custkey <= 5000 AND supplier.s_suppkey <= 1000",
        'lineitem',
        'ring cycle with non-rectangle comparator factor routed through td_cycle',
    ),
)

CASES: Tuple[Case, ...] = (
    Case('TDC1', '6', 'td_cycle'),
    Case('TDC2', '6', 'td_cycle'),
    Case('TDC2', '1', 'td_cycle'),
    Case('TDR1', '6', 'cycle_rect'),
    Case('TDC3', '1', 'td_cycle'),
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
        return m, ppq_kv, pp_kv, saw_empty_mode, ''
    except Exception as exc:  # noqa: BLE001
        return None, {}, {}, False, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description='Class-engine TD-cycle correctness verifier')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--statement-timeout', default='30min')
    ap.add_argument('--out-csv', default=str(OUT_CSV))
    ap.add_argument('--out-md', default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = qmap()
    write_policy_file()

    cols = [
        'db', 'policy_code', 'policy_target', 'policy_notes', 'query_id', 'enabled_policy_id',
        'expect_route', 'status', 'reason',
        'ours_rows', 'ours_hash', 'gt_rows', 'gt_hash',
        'class_td_terms_total', 'class_td_terms_supported', 'class_td_width_max', 'class_td_bags',
        'class_td_build_ms', 'class_td_dp_ms', 'class_td_msg_entries_total', 'class_td_fail_width',
        'class_td_msg_bytes_total', 'class_td_msg_pairs_total', 'class_td_join_ms', 'class_td_project_ms',
        'class_td_reduction_passes', 'class_td_reduction_ms', 'class_td_reduction_removed_pairs',
        'class_td_pairs_before', 'class_td_pairs_after', 'class_td_elim_order',
        'class_td_peak_msg_pairs', 'class_td_peak_msg_bytes',
        'class_td_cmp_filter_ms', 'class_td_cmp_filter_removed_pairs',
        'scan_mode_empty_tables', 'empty_short_circuit_tables', 'empty_short_circuit_ms', 'scan_mode_empty_seen',
        'query_short_circuit_empty', 'query_short_circuit_reason', 'query_short_circuit_ms', 'query_short_circuit_hits',
        'class_route_tree', 'class_route_cycle_rect', 'class_route_td_cycle',
        'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
    ]
    rows: List[Dict[str, str]] = []

    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qid, qsql = c.query_id, queries[c.query_id]
        enabled = Path('/tmp') / f'class_td_cycle_enabled_{p.code}_q{qid}.txt'
        enabled.parent.mkdir(parents=True, exist_ok=True)
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)
        pid = h.parse_policy_entry_with_id(p.line)[0] or 0

        row = {k: '' for k in cols}
        row.update({
            'db': db,
            'policy_code': p.code,
            'policy_target': p.target,
            'policy_notes': p.notes,
            'query_id': qid,
            'enabled_policy_id': str(pid),
            'expect_route': c.expect_route,
            'status': 'PASS',
            'reason': '',
        })

        try:
            run_hygiene(db)
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
                oc, oh, oerr = run_count_hash(db, 'ours', qid, qsql, enabled, timeout_ms)
            m, ppq, pp, saw_empty_mode, perr = run_profile_probe(db, qid, qsql, enabled, timeout_ms, idx)

            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [p.line])
            h.create_rls_indexes_for_k(db, idx, [p.line], timeout_ms)
            gc, gh, gerr = run_count_hash(db, 'rls_with_index', qid, qsql, enabled, timeout_ms)
            h.clear_rls_indexes_and_policies(db)

            if None in (oc, oh, gc, gh):
                row['status'] = 'ERROR'
                row['reason'] = f"ours={oerr if oc is None else ''} gt={gerr if gc is None else ''}".strip()
            elif int(oc) != int(gc) or str(oh) != str(gh):
                row['status'] = 'FAIL'
                row['reason'] = 'rows/hash mismatch'
            elif perr:
                row['status'] = 'ERROR'
                row['reason'] = f'profile_probe={perr}'
            else:
                for k in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                    if str(ppq.get(k, '0')) not in ('0', '0.000', ''):
                        row['status'] = 'FAIL'
                        row['reason'] = f'strict invariant broken: {k}={ppq.get(k)}'
                        break

            if row['status'] == 'PASS':
                if c.expect_route == 'td_cycle' and str(ppq.get('class_route_td_cycle', '0')) in ('', '0'):
                    row['status'] = 'FAIL'
                    row['reason'] = 'missing class_route_td_cycle'
                if c.expect_route == 'cycle_rect' and str(ppq.get('class_route_cycle_rect', '0')) in ('', '0'):
                    row['status'] = 'FAIL'
                    row['reason'] = 'missing class_route_cycle_rect'
                if c.expect_route == 'td_cycle' and str(ppq.get('class_td_terms_supported', '0')) in ('', '0'):
                    row['status'] = 'FAIL'
                    row['reason'] = 'missing class_td_terms_supported'

            row.update({
                'ours_rows': '' if oc is None else str(oc),
                'ours_hash': '' if oh is None else str(oh),
                'gt_rows': '' if gc is None else str(gc),
                'gt_hash': '' if gh is None else str(gh),
            })
            for k in cols:
                if k in row:
                    continue
            for k in [
                'class_td_terms_total', 'class_td_terms_supported', 'class_td_width_max', 'class_td_bags',
                'class_td_build_ms', 'class_td_dp_ms', 'class_td_msg_entries_total', 'class_td_fail_width',
                'class_td_msg_bytes_total', 'class_td_msg_pairs_total', 'class_td_join_ms', 'class_td_project_ms',
                'class_td_reduction_passes', 'class_td_reduction_ms', 'class_td_reduction_removed_pairs',
                'class_td_pairs_before', 'class_td_pairs_after', 'class_td_elim_order',
                'class_td_peak_msg_pairs', 'class_td_peak_msg_bytes',
                'class_td_cmp_filter_ms', 'class_td_cmp_filter_removed_pairs',
                'class_route_tree', 'class_route_cycle_rect', 'class_route_td_cycle',
                'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
            ]:
                row[k] = ppq.get(k, row.get(k, ''))
            row['scan_mode_empty_tables'] = pp.get('scan_mode_empty_tables', '')
            row['empty_short_circuit_tables'] = pp.get('empty_short_circuit_tables', '')
            row['empty_short_circuit_ms'] = pp.get('empty_short_circuit_ms', '')
            row['scan_mode_empty_seen'] = '1' if saw_empty_mode else '0'
            row['query_short_circuit_empty'] = pp.get('query_short_circuit_empty', '')
            row['query_short_circuit_reason'] = pp.get('query_short_circuit_reason', '')
            row['query_short_circuit_ms'] = pp.get('query_short_circuit_ms', '')
            row['query_short_circuit_hits'] = pp.get('query_short_circuit_hits', '')
        except Exception as exc:  # noqa: BLE001
            row['status'] = 'ERROR'
            row['reason'] = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
            try:
                h.clear_artifacts(db)
            except Exception:
                pass
            try:
                h.clear_rls_indexes_and_policies(db)
            except Exception:
                pass

        rows.append(row)
        print(f"[class_td_cycle_correctness] {p.code} q{qid} status={row['status']}")

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    pass_n = sum(1 for r in rows if r['status'] == 'PASS')
    fail_n = sum(1 for r in rows if r['status'] == 'FAIL')
    err_n = sum(1 for r in rows if r['status'] == 'ERROR')

    lines = [
        '# Class Engine TD-Cycle Scan-Cut Correctness',
        '',
        f"- db: `{db}`",
        '- mode: `strict_mode=on`',
        f"- cases: {len(rows)}",
        f"- PASS: {pass_n}, FAIL: {fail_n}, ERROR: {err_n}",
        '',
        '## Cases',
    ]
    for r in rows:
        lines.append(
            f"- {r['policy_code']} q{r['query_id']}: status={r['status']} ours=({r.get('ours_rows','')},{r.get('ours_hash','')}) "
            f"gt=({r.get('gt_rows','')},{r.get('gt_hash','')}) route(td/tree/rect)="
            f"{r.get('class_route_td_cycle','')}/{r.get('class_route_tree','')}/{r.get('class_route_cycle_rect','')} "
            f"empty(mode_seen/tables/short/ms)={r.get('scan_mode_empty_seen','')}/{r.get('scan_mode_empty_tables','')}/{r.get('empty_short_circuit_tables','')}/{r.get('empty_short_circuit_ms','')} "
            f"query_sc(empty/reason/ms/hits)={r.get('query_short_circuit_empty','')}/{r.get('query_short_circuit_reason','')}/{r.get('query_short_circuit_ms','')}/{r.get('query_short_circuit_hits','')} "
            f"td(w/bags/msg/msg_bytes/msg_pairs/join/project/reduce_ms/reduce_passes/reduce_rm/pairs_before/pairs_after/elim/peak_pairs/peak_bytes/cmp_ms/cmp_rm)="
            f"{r.get('class_td_width_max','')}/{r.get('class_td_bags','')}/{r.get('class_td_msg_entries_total','')}/{r.get('class_td_msg_bytes_total','')}/{r.get('class_td_msg_pairs_total','')}/{r.get('class_td_join_ms','')}/{r.get('class_td_project_ms','')}/{r.get('class_td_reduction_ms','')}/{r.get('class_td_reduction_passes','')}/{r.get('class_td_reduction_removed_pairs','')}/{r.get('class_td_pairs_before','')}/{r.get('class_td_pairs_after','')}/{r.get('class_td_elim_order','')}/{r.get('class_td_peak_msg_pairs','')}/{r.get('class_td_peak_msg_bytes','')}/{r.get('class_td_cmp_filter_ms','')}/{r.get('class_td_cmp_filter_removed_pairs','')} "
            f"proj_sig/mask/rid={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"reason={r.get('reason','')}"
        )
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
