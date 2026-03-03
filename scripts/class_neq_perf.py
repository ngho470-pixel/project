#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import statistics
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

OUT_CSV = REPO_ROOT / 'logs' / 'class_neq_perf.csv'
OUT_MD = REPO_ROOT / 'logs' / 'class_neq_perf.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'class_neq_policy.txt'


@dataclass(frozen=True)
class Policy:
    code: str
    line: str
    target: str


@dataclass(frozen=True)
class PerfCase:
    policy_code: str
    query_id: str


POLICIES: Tuple[Policy, ...] = (
    Policy('N1', "1. lineitem: lineitem.l_returnflag != 'R'", 'lineitem'),
    Policy('N2', '3. lineitem: lineitem.l_commitdate != lineitem.l_receiptdate', 'lineitem'),
    Policy('N4', '7. orders: orders.o_custkey = customer.c_custkey AND (orders.o_totalprice != customer.c_acctbal)', 'orders'),
    Policy('N5', '9. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity != partsupp.ps_availqty)', 'lineitem'),
)

CASES: Tuple[PerfCase, ...] = (
    PerfCase('N4', '3'),
    PerfCase('N4', '10'),
    PerfCase('N5', '6'),
    PerfCase('N5', '9'),
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
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:300]
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
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        err = '' if m.status == 'ok' else (m.error_msg or 'profile capture failed')
        return ppq_kv, err
    except Exception as exc:  # noqa: BLE001
        return {}, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:400]


def avg_hot_ms(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [x.elapsed_ms for x in hots if x.status == 'ok']
    return (sum(vals) / len(vals)) if vals else None


def avg_hot_rss_kb(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [float(x.peak_rss_kb) for x in hots if x.status == 'ok']
    return (sum(vals) / len(vals)) if vals else None


def setup_rls_with_index(db: str, enabled_policy_lines: List[str], k: int, timeout_ms: int) -> None:
    h.clear_rls_indexes_and_policies(db)
    h.apply_rls_policies_for_k(db, enabled_policy_lines)
    h.create_rls_indexes_for_k(db, k, enabled_policy_lines, timeout_ms)


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description='Class-engine != perf runner')
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
        'db', 'policy_code', 'policy_target', 'query_id', 'enabled_policy_id',
        'ours_hot_avg_ms', 'rls_hot_avg_ms', 'ours_vs_rls_ratio',
        'ours_hot_avg_peak_rss_kb', 'rls_hot_avg_peak_rss_kb',
        'correctness', 'status', 'error_type', 'error_msg',
        'ours_rows', 'ours_hash', 'gt_rows', 'gt_hash',
        'policy_total_ms', 'project_ms', 'project_row_ms',
        'pf2_cmp_total', 'pf2_cmp_supported', 'pf2_cmp_key_arity_max',
        'pf2_cmp_summary_build_ms', 'pf2_cmp_summary_keys_total',
        'pf2_cmp_checks_total', 'pf2_cmp_rejects_total',
        'pf2_cmp_key2_entries', 'pf2_cmp_key2_build_ms', 'pf2_cmp_key2_lookups',
        'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
    ]
    rows: List[Dict[str, str]] = []

    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qsql = queries[c.query_id]
        enabled = Path('/tmp') / f'class_neq_perf_{c.policy_code}_{c.query_id}.txt'
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)

        row = {k: '' for k in cols}
        row.update({
            'db': db,
            'policy_code': p.code,
            'policy_target': p.target,
            'query_id': c.query_id,
            'enabled_policy_id': p.line.split('.', 1)[0].strip(),
            'status': 'ERROR',
        })

        try:
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
            setup_rls_with_index(db, [p.line], idx, timeout_ms)

            with strict_env():
                _ours_cold, ours_hots = h.run_query_series(
                    db, 'ours', qsql, args.hot_runs, enabled, timeout_ms, query_id=c.query_id
                )
            _rls_cold, rls_hots = h.run_query_series(
                db, 'rls_with_index', qsql, args.hot_runs, enabled, timeout_ms, query_id=c.query_id
            )
            ppq_kv, prof_err = run_profile_probe(db, c.query_id, qsql, enabled, timeout_ms, idx)

            ours_avg = avg_hot_ms(ours_hots)
            rls_avg = avg_hot_ms(rls_hots)
            ours_rss = avg_hot_rss_kb(ours_hots)
            rls_rss = avg_hot_rss_kb(rls_hots)
            ratio = (ours_avg / rls_avg) if (ours_avg is not None and rls_avg not in (None, 0)) else None

            ours_rows, ours_hash, ours_err = run_count_hash(db, 'ours', c.query_id, qsql, enabled, timeout_ms)
            gt_rows, gt_hash, gt_err = run_count_hash(db, 'rls_with_index', c.query_id, qsql, enabled, timeout_ms)

            if ours_rows is None or gt_rows is None:
                row['status'] = 'error'
                row['error_type'] = 'query_error'
                row['error_msg'] = '; '.join(x for x in [ours_err, gt_err] if x)
            else:
                row['ours_rows'] = str(ours_rows)
                row['ours_hash'] = str(ours_hash)
                row['gt_rows'] = str(gt_rows)
                row['gt_hash'] = str(gt_hash)
                row['correctness'] = 'PASS' if (ours_rows == gt_rows and str(ours_hash) == str(gt_hash)) else 'FAIL'
                row['status'] = 'ok'
                if row['correctness'] != 'PASS':
                    row['error_type'] = 'correctness'
                    row['error_msg'] = 'rows/hash mismatch'
                elif prof_err:
                    row['error_type'] = 'profile'
                    row['error_msg'] = prof_err

            for k in cols:
                if k in row:
                    continue
                if k in ppq_kv:
                    row[k] = str(ppq_kv[k])
            for k in (
                'policy_total_ms', 'project_ms', 'project_row_ms',
                'pf2_cmp_total', 'pf2_cmp_supported', 'pf2_cmp_key_arity_max',
                'pf2_cmp_summary_build_ms', 'pf2_cmp_summary_keys_total',
                'pf2_cmp_checks_total', 'pf2_cmp_rejects_total',
                'pf2_cmp_key2_entries', 'pf2_cmp_key2_build_ms', 'pf2_cmp_key2_lookups',
                'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
            ):
                if k in ppq_kv:
                    row[k] = str(ppq_kv[k])

            if ours_avg is not None:
                row['ours_hot_avg_ms'] = f'{ours_avg:.3f}'
            if rls_avg is not None:
                row['rls_hot_avg_ms'] = f'{rls_avg:.3f}'
            if ratio is not None:
                row['ours_vs_rls_ratio'] = f'{ratio:.3f}'
            if ours_rss is not None:
                row['ours_hot_avg_peak_rss_kb'] = f'{ours_rss:.0f}'
            if rls_rss is not None:
                row['rls_hot_avg_peak_rss_kb'] = f'{rls_rss:.0f}'

            for invk in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                v = str(row.get(invk, '0'))
                if v not in ('', '0', '0.000'):
                    row['status'] = 'error'
                    row['error_type'] = 'invariant'
                    row['error_msg'] = (row.get('error_msg') + '; ' if row.get('error_msg') else '') + f'{invk}={v}'

        except Exception as exc:  # noqa: BLE001
            row['status'] = 'error'
            row['error_type'] = 'exception'
            row['error_msg'] = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:300]
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
        print(f"[class_neq_perf] case={p.code} q{c.query_id} status={row['status']} correctness={row.get('correctness','')}")

    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    ratios = [float(r['ours_vs_rls_ratio']) for r in rows if r.get('ours_vs_rls_ratio')]
    med = statistics.median(ratios) if ratios else None

    md_lines: List[str] = [
        '# Class Engine `!=` Perf',
        '',
        f'- db: `{db}`',
        '- mode: `strict_mode=on`',
        f'- cases: {len(rows)}',
    ]
    if med is not None:
        md_lines.append(f'- median ours/rls hot-time ratio: {med:.3f} (target <= 0.8)')
    md_lines += ['', '## Cases']
    for r in rows:
        md_lines.append(
            f"- {r['policy_code']} target={r['policy_target']} q{r['query_id']}: "
            f"status={r.get('status','')} correctness={r.get('correctness','')} "
            f"ours={r.get('ours_hot_avg_ms','')}ms rls={r.get('rls_hot_avg_ms','')}ms "
            f"ours/rls={r.get('ours_vs_rls_ratio','')} "
            f"cmp={r.get('pf2_cmp_total','')}/{r.get('pf2_cmp_supported','')} "
            f"key_arity_max={r.get('pf2_cmp_key_arity_max','')} "
            f"cmp_build={r.get('pf2_cmp_summary_build_ms','')} checks/rejects={r.get('pf2_cmp_checks_total','')}/{r.get('pf2_cmp_rejects_total','')} "
            f"proj_sig/mask/rid={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"err={r.get('error_msg','')}"
        )

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    print(f'[done] csv={out_csv} md={out_md}')


if __name__ == '__main__':
    main()
