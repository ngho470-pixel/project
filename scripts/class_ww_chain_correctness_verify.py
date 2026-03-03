#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
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

LOG_CSV = REPO_ROOT / 'logs' / 'class_ww_chain_correctness.csv'
LOG_MD = REPO_ROOT / 'logs' / 'class_ww_chain_correctness.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'class_ww_chain_policy.txt'


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
    expect_error: bool = False


POLICIES: Tuple[Policy, ...] = (
    Policy(
        'C0',
        "1. partsupp: partsupp.ps_suppkey = supplier.s_suppkey AND supplier.s_nationkey = customer.c_nationkey AND customer.c_custkey = orders.o_custkey AND lineitem.l_suppkey = supplier.s_suppkey AND partsupp.ps_suppkey <= 100 AND supplier.s_suppkey <= 100 AND customer.c_custkey <= 5000 AND orders.o_orderkey <= 10000 AND lineitem.l_orderkey <= 10000",
        'partsupp',
        'no comparator baseline for multi-hop chain effect check',
    ),
    Policy(
        'C1',
        "3. partsupp: partsupp.ps_suppkey = supplier.s_suppkey AND supplier.s_nationkey = customer.c_nationkey AND customer.c_custkey = orders.o_custkey AND lineitem.l_suppkey = supplier.s_suppkey AND partsupp.ps_suppkey <= 100 AND supplier.s_suppkey <= 100 AND customer.c_custkey <= 5000 AND orders.o_orderkey <= 10000 AND lineitem.l_orderkey <= 10000 AND (orders.o_orderkey >= lineitem.l_orderkey)",
        'partsupp',
        'ordered witness-witness chain comparator, non-adjacent endpoints over 2 bridges',
    ),
    Policy(
        'C2',
        "5. partsupp: partsupp.ps_suppkey = supplier.s_suppkey AND supplier.s_nationkey = customer.c_nationkey AND customer.c_custkey = orders.o_custkey AND lineitem.l_suppkey = supplier.s_suppkey AND partsupp.ps_suppkey <= 100 AND supplier.s_suppkey <= 100 AND customer.c_custkey <= 5000 AND orders.o_orderkey <= 10000 AND lineitem.l_orderkey <= 10000 AND (orders.o_orderkey != lineitem.l_orderkey)",
        'partsupp',
        '!= witness-witness chain comparator, non-adjacent endpoints over 2 bridges',
    ),
    Policy(
        'F1',
        "7. partsupp: partsupp.ps_suppkey = supplier.s_suppkey AND supplier.s_nationkey = customer.c_nationkey AND customer.c_custkey = orders.o_custkey AND partsupp.ps_suppkey <= 100 AND supplier.s_suppkey <= 100 AND customer.c_custkey <= 5000 AND orders.o_orderkey <= 10000 AND lineitem.l_orderkey <= 10000 AND (orders.o_orderkey >= lineitem.l_orderkey)",
        'partsupp',
        'fail-loud: disconnected/non-tree comparator endpoint in strict class-engine route',
    ),
)

CASES: Tuple[Case, ...] = (
    Case('C1', 'ps'),
    Case('C2', 'ps'),
    Case('C0', 'ps'),
    Case('F1', 'ps', expect_error=True),
)

CUSTOM_QUERIES: Dict[str, str] = {
    'ps': (
        'SELECT '
        'COUNT(*)::bigint AS c, '
        'COALESCE(SUM(ps_partkey)::bigint,0) AS s_part, '
        'COALESCE(SUM(ps_suppkey)::bigint,0) AS s_supp, '
        'COALESCE(SUM(ps_availqty)::bigint,0) AS s_avail '
        'FROM partsupp '
        'WHERE ps_partkey <= 5000'
    ),
}


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


def setup_rls_with_index(db: str, enabled_policy_lines: List[str], k: int, timeout_ms: int) -> None:
    h.clear_rls_indexes_and_policies(db)
    h.apply_rls_policies_for_k(db, enabled_policy_lines)
    h.create_rls_indexes_for_k(db, k, enabled_policy_lines, timeout_ms)


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
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:400]
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


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description='Class-engine witness-witness chain comparator correctness verifier')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--statement-timeout', default='30min')
    ap.add_argument('--out-csv', default=str(LOG_CSV))
    ap.add_argument('--out-md', default=str(LOG_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = qmap()
    queries.update(CUSTOM_QUERIES)
    write_policy_file()

    cols = [
        'db', 'policy_code', 'policy_target', 'query_id', 'enabled_policy_id', 'status',
        'ours_rows', 'ours_hash', 'gt_rows', 'gt_hash', 'error_msg',
        'proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters',
        'pf2_cmp_total', 'pf2_cmp_supported', 'pf2_cmp_key_arity_max',
        'pf2_cmp_summary_build_ms', 'pf2_cmp_summary_keys_total',
        'pf2_cmp_checks_total', 'pf2_cmp_rejects_total',
        'pf2_cmp_witness_witness_total', 'pf2_cmp_witness_witness_supported',
        'pf2_cmp_filter_rows_checked', 'pf2_cmp_filter_rows_reject',
        'pf2_cmp_chain_total', 'pf2_cmp_chain_supported', 'pf2_cmp_chain_build_ms',
        'pf2_cmp_chain_bridge_rows_scanned', 'pf2_cmp_chain_compose_steps',
        'pf2_cmp_chain_filter_rows_checked', 'pf2_cmp_chain_filter_rows_reject',
        'class_terms_ok', 'class_terms_reject',
        'class_route_single_hub', 'class_route_two_hop', 'class_route_tree', 'class_route_cycle_rect', 'class_route_reject',
    ]
    rows: List[Dict[str, str]] = []

    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qsql = queries[c.query_id]
        enabled = Path('/tmp') / f'class_ww_chain_correctness_{c.policy_code}_{c.query_id}.txt'
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

            if c.expect_error:
                ppq_kv, prof_err = run_profile_probe(db, c.query_id, qsql, enabled, timeout_ms, idx)
                msg = prof_err
                if 'unsupported term shape' in msg or 'unsupported' in msg:
                    row['status'] = 'PASS'
                else:
                    row['status'] = 'FAIL'
                    row['error_msg'] = msg or 'expected fail-loud but query succeeded'
                for k in cols:
                    if k in ppq_kv:
                        row[k] = str(ppq_kv[k])
                rows.append(row)
                print(f'[class_ww_chain_correctness] case={c.policy_code} q{c.query_id} status={row["status"]}')
                continue

            setup_rls_with_index(db, [p.line], idx, timeout_ms)
            ours_rows, ours_hash, ours_err = run_count_hash(db, 'ours', c.query_id, qsql, enabled, timeout_ms)
            gt_rows, gt_hash, gt_err = run_count_hash(db, 'rls_with_index', c.query_id, qsql, enabled, timeout_ms)
            ppq_kv, prof_err = run_profile_probe(db, c.query_id, qsql, enabled, timeout_ms, idx)

            if ours_rows is None or gt_rows is None:
                row['status'] = 'ERROR'
                row['error_msg'] = '; '.join(x for x in [ours_err, gt_err, prof_err] if x)
            else:
                row['ours_rows'] = str(ours_rows)
                row['ours_hash'] = str(ours_hash)
                row['gt_rows'] = str(gt_rows)
                row['gt_hash'] = str(gt_hash)
                ok = (ours_rows == gt_rows and str(ours_hash) == str(gt_hash))
                row['status'] = 'PASS' if ok else 'FAIL'
                if not ok:
                    row['error_msg'] = 'rows/hash mismatch'
                elif prof_err:
                    row['error_msg'] = prof_err

            for k in cols:
                if k in ppq_kv:
                    row[k] = str(ppq_kv[k])

            for invk in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                v = str(row.get(invk, '0'))
                if v not in ('', '0', '0.000'):
                    row['status'] = 'FAIL'
                    row['error_msg'] = (row.get('error_msg') + '; ' if row.get('error_msg') else '') + f'invariant {invk}={v}'

            if row['status'] == 'PASS':
                if str(row.get('class_route_tree', '0')) in ('', '0'):
                    row['status'] = 'FAIL'
                    row['error_msg'] = (row.get('error_msg') + '; ' if row.get('error_msg') else '') + 'missing class_route_tree'
                if row.get('policy_code') in ('C1', 'C2') and str(row.get('pf2_cmp_chain_total', '0')) in ('', '0'):
                    row['status'] = 'FAIL'
                    row['error_msg'] = (row.get('error_msg') + '; ' if row.get('error_msg') else '') + 'missing pf2_cmp_chain_total'

        except Exception as exc:  # noqa: BLE001
            row['status'] = 'ERROR'
            row['error_msg'] = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:400]
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
        print(f'[class_ww_chain_correctness] case={c.policy_code} q{c.query_id} status={row["status"]}')

    # Prove chain comparator affects target result (C1 ps vs C0 ps).
    c0 = next((r for r in rows if r.get('policy_code') == 'C0' and r.get('query_id') == 'ps' and r.get('status') == 'PASS'), None)
    c1 = next((r for r in rows if r.get('policy_code') == 'C1' and r.get('query_id') == 'ps' and r.get('status') == 'PASS'), None)
    if c0 is not None and c1 is not None:
        same = (c0.get('ours_rows') == c1.get('ours_rows') and c0.get('ours_hash') == c1.get('ours_hash'))
        row = {k: '' for k in cols}
        row.update({
            'db': db,
            'policy_code': 'CHAIN_EFFECT',
            'policy_target': 'partsupp',
            'query_id': 'ps',
            'enabled_policy_id': '-',
            'status': 'PASS' if not same else 'FAIL',
            'error_msg': '' if not same else 'comparator case did not change target result vs baseline',
            'ours_rows': c1.get('ours_rows', ''),
            'ours_hash': c1.get('ours_hash', ''),
            'gt_rows': c0.get('ours_rows', ''),
            'gt_hash': c0.get('ours_hash', ''),
        })
        rows.append(row)

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    p = sum(1 for r in rows if r['status'] == 'PASS')
    fcnt = sum(1 for r in rows if r['status'] == 'FAIL')
    ecnt = sum(1 for r in rows if r['status'] == 'ERROR')
    lines = [
        '# Class Engine Witness-Witness Chain Comparator Correctness',
        '',
        f'- db: `{db}`',
        '- mode: `strict_mode=on`',
        f'- cases: {len(rows)}',
        f'- pass/fail/error: {p}/{fcnt}/{ecnt}',
        '',
        '## Cases',
    ]
    for r in rows:
        lines.append(
            f"- {r['policy_code']} target={r.get('policy_target','')} q{r.get('query_id','')}: "
            f"status={r['status']} ours=({r.get('ours_rows','')},{r.get('ours_hash','')}) "
            f"gt=({r.get('gt_rows','')},{r.get('gt_hash','')}) "
            f"chain(total/supported/steps/build_ms/check/reject)="
            f"{r.get('pf2_cmp_chain_total','')}/{r.get('pf2_cmp_chain_supported','')}/"
            f"{r.get('pf2_cmp_chain_compose_steps','')}/{r.get('pf2_cmp_chain_build_ms','')}/"
            f"{r.get('pf2_cmp_chain_filter_rows_checked','')}/{r.get('pf2_cmp_chain_filter_rows_reject','')} "
            f"proj_sig/mask/rid={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"err={r.get('error_msg','')}"
        )
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'[done] csv={out_csv} md={out_md}')


if __name__ == '__main__':
    main()
