#!/usr/bin/env python3
from __future__ import annotations
import csv, os, sys
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

LOG_CSV = REPO_ROOT / 'logs' / 'pf_v2_6_correctness.csv'
LOG_MD = REPO_ROOT / 'logs' / 'pf_v2_6_correctness.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'pf_v2_6_policy.txt'

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

POLICIES: Tuple[Policy, ...] = (
    Policy('P26', "1. orders: orders.o_custkey = customer.c_custkey AND (orders.o_totalprice >= customer.c_acctbal)", 'orders', 'policy26 pattern, cross-table >= keyed by custkey'),
    Policy('P27', "3. lineitem: lineitem.l_orderkey = orders.o_orderkey AND (lineitem.l_extendedprice <= orders.o_totalprice)", 'lineitem', 'policy27 pattern, cross-table <= keyed by orderkey'),
    Policy('P28', "5. partsupp: partsupp.ps_partkey = part.p_partkey AND (part.p_retailprice >= partsupp.ps_supplycost)", 'partsupp', 'policy28 pattern, cross-table >= keyed by partkey'),
    Policy('P30', "7. supplier: supplier.s_nationkey = customer.c_nationkey AND (supplier.s_acctbal >= customer.c_acctbal)", 'supplier', 'policy30 pattern, cross-table >= keyed by nationkey'),
    Policy('P27F', "9. lineitem: lineitem.l_orderkey = orders.o_orderkey AND orders.o_orderstatus = 'F' AND (lineitem.l_extendedprice <= orders.o_totalprice)", 'lineitem', 'policy27 + witness local predicate'),
    Policy('P62', "11. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND partsupp.ps_suppkey = supplier.s_suppkey AND (lineitem.l_suppkey <= supplier.s_suppkey)", 'lineitem', 'PF-V2.6 arity-2 comparator keyed by (partkey,suppkey) on acyclic tree'),
)

CASES: Tuple[Case, ...] = (
    Case('P62', '1'), Case('P62', '6'),
    Case('P26', '3'), Case('P26', '10'),
    Case('P27', '1'), Case('P27', '6'),
    Case('P28', '9'), Case('P28', '11'),
    Case('P30', '5'), Case('P27F', '6'),
)

@contextmanager
def pf26_env(strict: bool = True, force: bool = True):
    old_pgoptions = os.environ.get('PGOPTIONS')
    old_cf_strict = os.environ.get('CF_POLICY_STRICT_MODE')
    opts = []
    if strict:
        opts.append('-c custom_filter.strict_mode=on')
    os.environ['PGOPTIONS'] = ' '.join(opts)
    if strict:
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
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n',' ').strip()[:320]
    finally:
        if conn is not None:
            conn.close()

def run_profile_probe(db: str, qid: str, qsql: str, enabled_path: Path, timeout_ms: int, profile_k: int):
    try:
        with pf26_env(strict=True, force=True):
            m, _payload, _kv, _cnt, notices = h.run_ours_profile_capture(
                db, qsql, enabled_path, timeout_ms,
                ours_profile_rescan=False, ours_debug_mode='trace',
                query_id=qid, profile_k=profile_k, profile_query=qid,
            )
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        return ppq_kv, '' if m.status == 'ok' else (m.error_msg or 'profile capture failed')
    except Exception as exc:  # noqa: BLE001
        return {}, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n',' ').strip()[:320]

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PF-V2.6 correctness verifier (arity-2 comparator tree subset)')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--statement-timeout', default='30min')
    ap.add_argument('--out-csv', default=str(LOG_CSV))
    ap.add_argument('--out-md', default=str(LOG_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = qmap()
    write_policy_file()

    cols = [
        'db','policy_code','policy_target','policy_notes','query_id','enabled_policy_ids',
        'ours_rows','ours_hash','gt_rows','gt_hash','status','reason',
        'pf2_terms_tree','pf2_cmp_total','pf2_cmp_supported','pf2_cmp_key_arity_max',
        'pf2_cmp_summary_build_ms','pf2_cmp_summary_keys_total','pf2_cmp_checks_total','pf2_cmp_rejects_total',
        'pf2_cmp_key2_entries','pf2_cmp_key2_dense_bytes','pf2_cmp_key2_build_ms',
        'pf2_cmp_key2_rows_scanned','pf2_cmp_key2_updates','pf2_cmp_key2_lookups',
        'proj_sig_count','proj_mask_or_ops','proj_rid_iters'
    ]
    out_rows: List[Dict[str, str]] = []
    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qid, qsql = c.query_id, queries[c.query_id]
        enabled = Path('/tmp') / f'pf_v2_6_enabled_{p.code}_q{qid}.txt'
        enabled.parent.mkdir(parents=True, exist_ok=True)
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)
        ours_rows = ours_hash = gt_rows = gt_hash = None
        status = 'PASS'
        reason = ''
        ppq: Dict[str, str] = {}
        oerr = gerr = ''
        try:
            h.clear_artifacts(db); h.clear_rls_indexes_and_policies(db)
            with pf26_env(strict=True, force=True):
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
                ours_rows, ours_hash, oerr = run_count_hash(db, 'ours', qid, qsql, enabled, timeout_ms)
            ppq, perr = run_profile_probe(db, qid, qsql, enabled, timeout_ms, idx)
            if perr and not reason:
                reason = f'profile_probe={perr}'
            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [p.line])
            h.create_rls_indexes_for_k(db, idx, [p.line], timeout_ms)
            gt_rows, gt_hash, gerr = run_count_hash(db, 'rls_with_index', qid, qsql, enabled, timeout_ms)
            h.clear_rls_indexes_and_policies(db)
            if None in (ours_rows, ours_hash, gt_rows, gt_hash):
                status, reason = 'ERROR', f"ours={oerr if ours_rows is None else ''} gt={gerr if gt_rows is None else ''}".strip()
            elif int(ours_rows) != int(gt_rows) or str(ours_hash) != str(gt_hash):
                status, reason = 'FAIL', 'rows/hash mismatch'
        except Exception as exc:  # noqa: BLE001
            status = 'ERROR'
            reason = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n',' ').strip()[:320]
            try: h.clear_artifacts(db)
            except Exception: pass
            try: h.clear_rls_indexes_and_policies(db)
            except Exception: pass

        out_rows.append({
            'db': db, 'policy_code': p.code, 'policy_target': p.target, 'policy_notes': p.notes,
            'query_id': qid, 'enabled_policy_ids': str(h.parse_policy_entry_with_id(p.line)[0] or ''),
            'ours_rows': '' if ours_rows is None else str(ours_rows),
            'ours_hash': '' if ours_hash is None else str(ours_hash),
            'gt_rows': '' if gt_rows is None else str(gt_rows),
            'gt_hash': '' if gt_hash is None else str(gt_hash),
            'status': status, 'reason': reason,
            'pf2_terms_tree': ppq.get('pf2_terms_tree',''),
            'pf2_cmp_total': ppq.get('pf2_cmp_total',''),
            'pf2_cmp_supported': ppq.get('pf2_cmp_supported',''),
            'pf2_cmp_key_arity_max': ppq.get('pf2_cmp_key_arity_max',''),
            'pf2_cmp_summary_build_ms': ppq.get('pf2_cmp_summary_build_ms',''),
            'pf2_cmp_summary_keys_total': ppq.get('pf2_cmp_summary_keys_total',''),
            'pf2_cmp_checks_total': ppq.get('pf2_cmp_checks_total',''),
            'pf2_cmp_rejects_total': ppq.get('pf2_cmp_rejects_total',''),
            'pf2_cmp_key2_entries': ppq.get('pf2_cmp_key2_entries',''),
            'pf2_cmp_key2_dense_bytes': ppq.get('pf2_cmp_key2_dense_bytes',''),
            'pf2_cmp_key2_build_ms': ppq.get('pf2_cmp_key2_build_ms',''),
            'pf2_cmp_key2_rows_scanned': ppq.get('pf2_cmp_key2_rows_scanned',''),
            'pf2_cmp_key2_updates': ppq.get('pf2_cmp_key2_updates',''),
            'pf2_cmp_key2_lookups': ppq.get('pf2_cmp_key2_lookups',''),
            'proj_sig_count': ppq.get('proj_sig_count',''),
            'proj_mask_or_ops': ppq.get('proj_mask_or_ops',''),
            'proj_rid_iters': ppq.get('proj_rid_iters',''),
        })
        print(f"[pf2.6_correctness] {p.code} q{qid} status={status}")

    out_csv = Path(args.out_csv); out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(out_rows)
    pass_n = sum(1 for r in out_rows if r['status']=='PASS')
    fail_n = sum(1 for r in out_rows if r['status']=='FAIL')
    err_n = sum(1 for r in out_rows if r['status']=='ERROR')
    lines = [
        '# PF-V2.6 Correctness', '',
        f'- db: `{db}`',
        '- mode: `strict_mode=on`',
        f'- cases: {len(out_rows)}',
        f'- result: PASS={pass_n} FAIL={fail_n} ERROR={err_n}', '', '## Cases'
    ]
    for r in out_rows:
        lines.append(
            f"- {r['policy_code']} target={r['policy_target']} q{r['query_id']}: {r['status']} rows/hash ours={r['ours_rows']}/{r['ours_hash']} gt={r['gt_rows']}/{r['gt_hash']} cmp_total/supported={r['pf2_cmp_total']}/{r['pf2_cmp_supported']} cmp_key_arity_max={r['pf2_cmp_key_arity_max']} key2(entries/build/lookups)={r['pf2_cmp_key2_entries']}/{r['pf2_cmp_key2_build_ms']}/{r['pf2_cmp_key2_lookups']} proj_sig/mask/rid={r['proj_sig_count']}/{r['proj_mask_or_ops']}/{r['proj_rid_iters']} reason={r['reason']}"
        )
    out_md.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(f'[done] csv={out_csv} md={out_md}')

if __name__ == '__main__':
    main()
