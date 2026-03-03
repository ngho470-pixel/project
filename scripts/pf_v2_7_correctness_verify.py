#!/usr/bin/env python3
from __future__ import annotations
import csv, os, sys
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

LOG_CSV = REPO_ROOT / 'logs' / 'pf_v2_7_correctness.csv'
LOG_MD = REPO_ROOT / 'logs' / 'pf_v2_7_correctness.md'
POLICY_FILE = REPO_ROOT / 'logs' / 'pf_v2_7_policy.txt'


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
    Policy('P29', "1. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem', 'policy29 shape'),
    Policy('P29F', "3. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND partsupp.ps_supplycost > 500 AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem', 'policy29 + witness local predicate'),
    Policy('P29T', "5. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND lineitem.l_discount <= 0.05 AND (lineitem.l_quantity <= partsupp.ps_availqty)", 'lineitem', 'policy29 + target local predicate'),
    Policy('P29G', "7. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity >= partsupp.ps_availqty)", 'lineitem', 'policy29 shape >= comparator variant'),
)

CASES: Tuple[Case, ...] = (
    Case('P29', '1'),
    Case('P29', '6'),
    Case('P29', '9'),
    Case('P29F', '6'),
    Case('P29F', '9'),
    Case('P29T', '1'),
    Case('P29T', '6'),
    Case('P29G', '6'),
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
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
    finally:
        if conn is not None:
            conn.close()


def run_profile_probe(db: str, qid: str, qsql: str, enabled_path: Path, timeout_ms: int, profile_k: int):
    try:
        with pf27_env():
            m, _payload, _kv, _cnt, notices = h.run_ours_profile_capture(
                db, qsql, enabled_path, timeout_ms,
                ours_profile_rescan=False, ours_debug_mode='trace',
                query_id=qid, profile_k=profile_k, profile_query=qid,
            )
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        return m, ppq_kv, ''
    except Exception as exc:  # noqa: BLE001
        return None, {}, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PF-V2.7 correctness verifier (cyclic rectangle subset)')
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
        'db','policy_code','policy_target','policy_notes','query_id','enabled_policy_id','status','reason',
        'ours_rows','ours_hash','gt_rows','gt_hash',
        'policy_total_ms','project_ms','pf2_cmp_total','pf2_cmp_supported','pf2_cmp_key_arity_max',
        'pf2_cmp_summary_build_ms','pf2_cmp_key2_entries','pf2_cmp_key2_build_ms','pf2_cmp_key2_lookups',
        'pf2_cmp_checks_total','pf2_cmp_rejects_total',
        'proj_sig_count','proj_mask_or_ops','proj_rid_iters'
    ]
    rows: List[Dict[str, str]] = []
    for idx, c in enumerate(CASES, start=1):
        p = pol(c.policy_code)
        qid, qsql = c.query_id, queries[c.query_id]
        enabled = Path('/tmp') / f'pf_v2_7_enabled_{p.code}_q{qid}.txt'
        enabled.parent.mkdir(parents=True, exist_ok=True)
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)
        pid = h.parse_policy_entry_with_id(p.line)[0] or 0

        row = {k: '' for k in cols}
        row.update({'db': db, 'policy_code': p.code, 'policy_target': p.target, 'policy_notes': p.notes,
                    'query_id': qid, 'enabled_policy_id': str(pid), 'status': 'PASS', 'reason': ''})
        try:
            h.clear_artifacts(db); h.clear_rls_indexes_and_policies(db)
            with pf27_env():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
                oc, oh, oerr = run_count_hash(db, 'ours', qid, qsql, enabled, timeout_ms)
            m, ppq, perr = run_profile_probe(db, qid, qsql, enabled, timeout_ms, idx)
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
                # PF invariant: no signature projection counters on PF path
                for k in ('proj_sig_count', 'proj_mask_or_ops', 'proj_rid_iters'):
                    if str(ppq.get(k, '0')) not in ('0', '0.000', ''):
                        row['status'] = 'FAIL'
                        row['reason'] = f'PF invariant broken: {k}={ppq.get(k)}'
                        break

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
                'policy_total_ms','project_ms','pf2_cmp_total','pf2_cmp_supported','pf2_cmp_key_arity_max',
                'pf2_cmp_summary_build_ms','pf2_cmp_key2_entries','pf2_cmp_key2_build_ms','pf2_cmp_key2_lookups',
                'pf2_cmp_checks_total','pf2_cmp_rejects_total','proj_sig_count','proj_mask_or_ops','proj_rid_iters'
            ]:
                row[k] = ppq.get(k, row.get(k, ''))
        except Exception as exc:  # noqa: BLE001
            row['status'] = 'ERROR'
            row['reason'] = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
            try: h.clear_artifacts(db)
            except Exception: pass
            try: h.clear_rls_indexes_and_policies(db)
            except Exception: pass

        rows.append(row)
        print(f"[pf2.7_correctness] {p.code} q{qid} status={row['status']}")

    out_csv = Path(args.out_csv); out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(rows)

    pass_n = sum(1 for r in rows if r['status'] == 'PASS')
    fail_n = sum(1 for r in rows if r['status'] == 'FAIL')
    err_n = sum(1 for r in rows if r['status'] == 'ERROR')
    lines = [
        '# PF-V2.7 Correctness', '',
        f'- db: `{db}`',
        '- mode: `strict_mode=on`',
        f'- cases: {len(rows)}',
        f'- result: PASS={pass_n} FAIL={fail_n} ERROR={err_n}',
        '', '## Cases'
    ]
    for r in rows:
        lines.append(
            f"- {r['policy_code']} target={r['policy_target']} q{r['query_id']}: {r['status']} "
            f"ours={r['ours_rows']}/{r['ours_hash']} gt={r['gt_rows']}/{r['gt_hash']} "
            f"cmp={r['pf2_cmp_total']}/{r['pf2_cmp_supported']} key_arity_max={r['pf2_cmp_key_arity_max']} "
            f"key2(entries/build/lookups)={r['pf2_cmp_key2_entries']}/{r['pf2_cmp_key2_build_ms']}/{r['pf2_cmp_key2_lookups']} "
            f"proj_sig/mask/rid={r['proj_sig_count']}/{r['proj_mask_or_ops']}/{r['proj_rid_iters']} reason={r['reason']}"
        )
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'[done] csv={out_csv} md={out_md}')


if __name__ == '__main__':
    main()
