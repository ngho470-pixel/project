#!/usr/bin/env python3
from __future__ import annotations
import csv, os, statistics, sys
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
POLICY_FILE = REPO_ROOT / 'logs' / 'pf_v2_7_policy.txt'
OUT_CSV = REPO_ROOT / 'logs' / 'pf_v2_7_perf.csv'
OUT_MD = REPO_ROOT / 'logs' / 'pf_v2_7_perf.md'


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
    Policy('P29', "1. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem'),
    Policy('P29F', "3. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND partsupp.ps_supplycost > 500 AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem'),
    Policy('P29T', "5. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND lineitem.l_discount <= 0.05 AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem'),
    Policy('P29G', "7. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity >= partsupp.ps_availqty)", 'lineitem'),
)

CASES: Tuple[PerfCase, ...] = (
    PerfCase('P29', '1'),
    PerfCase('P29', '6'),
    PerfCase('P29', '9'),
    PerfCase('P29F', '6'),
    PerfCase('P29T', '1'),
    PerfCase('P29G', '6'),
)


@contextmanager
def pf27_env():
    old_pgoptions = os.environ.get('PGOPTIONS')
    old_cf_strict = os.environ.get('CF_POLICY_STRICT_MODE')
    os.environ['PGOPTIONS'] = ' '.join([
        '-c custom_filter.strict_mode=on',
    ])
    os.environ['CF_POLICY_STRICT_MODE'] = '1'
    try:
        yield
    finally:
        if old_pgoptions is None: os.environ.pop('PGOPTIONS', None)
        else: os.environ['PGOPTIONS'] = old_pgoptions
        if old_cf_strict is None: os.environ.pop('CF_POLICY_STRICT_MODE', None)
        else: os.environ['CF_POLICY_STRICT_MODE'] = old_cf_strict


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
            if baseline in ('rls','rls_with_index'):
                cur.execute('SET row_security = on;')
            cnt, hh = h.result_count_and_hash_in_session(cur, qid, qsql)
            return int(cnt), str(hh or ''), ''
    except Exception as exc:  # noqa: BLE001
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:240]
    finally:
        if conn is not None:
            conn.close()


def avg_hot_ms(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [x.elapsed_ms for x in hots if x.status == 'ok']
    return (sum(vals)/len(vals)) if vals else None


def avg_hot_rss_kb(hots: List[h.RunMetrics]) -> Optional[float]:
    vals = [float(x.peak_rss_kb) for x in hots if x.status == 'ok']
    return (sum(vals)/len(vals)) if vals else None


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PF-V2.7 perf runner (curated cyclic policy29-shape cases)')
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
        'db','policy_code','policy_target','query_id','enabled_policy_id','ours_hot_avg_ms','rls_hot_avg_ms','ours_vs_rls_ratio',
        'ours_hot_avg_peak_rss_kb','rls_hot_avg_peak_rss_kb','correctness','status','error_type','error_msg',
        'ours_rows','ours_hash','gt_rows','gt_hash',
        'policy_total_ms','project_ms','project_row_ms','pf2_cmp_total','pf2_cmp_supported','pf2_cmp_key_arity_max',
        'pf2_cmp_summary_build_ms','pf2_cmp_key2_entries','pf2_cmp_key2_dense_bytes','pf2_cmp_key2_build_ms',
        'pf2_cmp_key2_rows_scanned','pf2_cmp_key2_updates','pf2_cmp_key2_lookups',
        'pf2_cmp_checks_total','pf2_cmp_rejects_total','pf2_project_bin_rids_total','pf2_project_ms','pf2_total_ms',
        'proj_sig_count','proj_mask_or_ops','proj_rid_iters'
    ]
    rows: List[Dict[str, str]] = []
    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qid = c.query_id
        qsql = queries[qid]
        pid = h.parse_policy_entry_with_id(p.line)[0] or 0
        enabled = Path('/tmp') / f'pf_v2_7_perf_enabled_{p.code}_q{qid}.txt'
        enabled.parent.mkdir(parents=True, exist_ok=True)
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)
        row = {k: '' for k in cols}
        row.update({'db': db, 'policy_code': p.code, 'policy_target': p.target, 'query_id': qid, 'enabled_policy_id': str(pid),
                    'status': 'ok', 'error_type': '', 'error_msg': ''})
        try:
            h.clear_artifacts(db); h.clear_rls_indexes_and_policies(db)
            with pf27_env():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
                prof_m, _payload, prof_kv, _cnt, notices = h.run_ours_profile_capture(
                    db, qsql, enabled, timeout_ms,
                    ours_profile_rescan=False, ours_debug_mode='trace',
                    query_id=qid, profile_k=idx, profile_query=qid,
                )
                _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
                _cold_ours, hots_ours = h.run_query_series(db, 'ours', qsql, int(args.hot_runs), enabled, timeout_ms, query_id=qid)
                oc, oh, oerr = run_count_hash(db, 'ours', qid, qsql, enabled, timeout_ms)
            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [p.line])
            h.create_rls_indexes_for_k(db, idx, [p.line], timeout_ms)
            _cold_rls, hots_rls = h.run_query_series(db, 'rls_with_index', qsql, int(args.hot_runs), enabled, timeout_ms, query_id=qid)
            gc, gh, gerr = run_count_hash(db, 'rls_with_index', qid, qsql, enabled, timeout_ms)
            h.clear_rls_indexes_and_policies(db)

            ours_hot = avg_hot_ms(hots_ours); rls_hot = avg_hot_ms(hots_rls)
            ours_rss = avg_hot_rss_kb(hots_ours); rls_rss = avg_hot_rss_kb(hots_rls)
            if ours_hot is not None: row['ours_hot_avg_ms'] = f'{ours_hot:.3f}'
            if rls_hot is not None: row['rls_hot_avg_ms'] = f'{rls_hot:.3f}'
            if ours_hot and rls_hot and rls_hot > 0: row['ours_vs_rls_ratio'] = f'{ours_hot/rls_hot:.3f}'
            if ours_rss is not None: row['ours_hot_avg_peak_rss_kb'] = f'{ours_rss:.1f}'
            if rls_rss is not None: row['rls_hot_avg_peak_rss_kb'] = f'{rls_rss:.1f}'

            if None in (oc, oh, gc, gh):
                row.update({'correctness': 'ERROR', 'status': 'error', 'error_type': 'count_hash',
                            'error_msg': f"ours={oerr if oc is None else ''} gt={gerr if gc is None else ''}".strip()})
            else:
                row.update({'ours_rows': str(oc), 'ours_hash': str(oh), 'gt_rows': str(gc), 'gt_hash': str(gh)})
                if oc == gc and oh == gh:
                    row['correctness'] = 'PASS'
                else:
                    row.update({'correctness': 'FAIL', 'status': 'error', 'error_type': 'mismatch', 'error_msg': 'rows/hash mismatch'})

            src = {**prof_kv, **ppq_kv}
            for k in [
                'policy_total_ms','project_ms','project_row_ms','pf2_cmp_total','pf2_cmp_supported','pf2_cmp_key_arity_max',
                'pf2_cmp_summary_build_ms','pf2_cmp_key2_entries','pf2_cmp_key2_dense_bytes','pf2_cmp_key2_build_ms',
                'pf2_cmp_key2_rows_scanned','pf2_cmp_key2_updates','pf2_cmp_key2_lookups',
                'pf2_cmp_checks_total','pf2_cmp_rejects_total','pf2_project_bin_rids_total','pf2_project_ms','pf2_total_ms',
                'proj_sig_count','proj_mask_or_ops','proj_rid_iters'
            ]:
                row[k] = src.get(k, '')

            for invk in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                if row.get(invk, '0') not in ('', '0', '0.000'):
                    row.update({'status': 'error', 'error_type': 'pf_invariant', 'error_msg': f'{invk}={row.get(invk)}'})
                    break
            if prof_m.status != 'ok' and row['status'] == 'ok':
                row.update({'status': 'error', 'error_type': 'profile', 'error_msg': prof_m.error_msg or 'profile capture failed'})
        except Exception as exc:  # noqa: BLE001
            row.update({'status': 'error', 'error_type': 'exception',
                        'error_msg': (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]})
            try: h.clear_artifacts(db)
            except Exception: pass
            try: h.clear_rls_indexes_and_policies(db)
            except Exception: pass

        rows.append(row)
        print(f"[pf2.7_perf] {p.code} q{qid} status={row['status']} correctness={row.get('correctness','')}")

    out_csv = Path(args.out_csv); out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    ratios = []
    for r in rows:
        try:
            if r.get('status') == 'ok' and r.get('correctness') == 'PASS' and r.get('ours_vs_rls_ratio'):
                ratios.append(float(r['ours_vs_rls_ratio']))
        except Exception:
            pass
    med = statistics.median(ratios) if ratios else None
    lines = [
        '# PF-V2.7 Perf', '',
        f'- db: `{db}`',
        f'- policy_file: `{POLICY_FILE}`',
        '- mode: `strict_mode=on`',
        f'- cases: {len(rows)}', '', '## Per Case'
    ]
    for r in rows:
        lines.append(
            f"- {r['policy_code']} target={r['policy_target']} q{r['query_id']}: status={r['status']} correctness={r.get('correctness','')} "
            f"ours={r.get('ours_hot_avg_ms','')}ms rls={r.get('rls_hot_avg_ms','')}ms ours/rls={r.get('ours_vs_rls_ratio','')} "
            f"policy_total={r.get('policy_total_ms','')} project={r.get('project_ms','')} pf2_cmp={r.get('pf2_cmp_total','')}/{r.get('pf2_cmp_supported','')} "
            f"cmp_build_ms={r.get('pf2_cmp_summary_build_ms','')} key2(entries/build/lookups)={r.get('pf2_cmp_key2_entries','')}/{r.get('pf2_cmp_key2_build_ms','')}/{r.get('pf2_cmp_key2_lookups','')} "
            f"cmp_checks/rejects={r.get('pf2_cmp_checks_total','')}/{r.get('pf2_cmp_rejects_total','')} pf2_project={r.get('pf2_project_ms','')} pf2_total={r.get('pf2_total_ms','')} "
            f"proj_sig={r.get('proj_sig_count','')} proj_mask_or={r.get('proj_mask_or_ops','')} proj_rid={r.get('proj_rid_iters','')}"
        )
    if med is not None:
        lines += ['', f'- median ours/rls hot-time ratio: {med:.3f} (target <= 0.7)']
    lines += ['']
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'[done] csv={out_csv} md={out_md}')


if __name__ == '__main__':
    main()
