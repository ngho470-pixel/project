#!/usr/bin/env python3
from __future__ import annotations
import os, sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / 'custom_filter' / 'custom_filter.so')
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / 'artifact_builder' / 'artifact_builder.so')
OUT_MD = REPO_ROOT / 'logs' / 'pf_v2_6_shape_fail.md'

@dataclass(frozen=True)
class Case:
    code: str
    desc: str
    policy_line: str
    query_id: str

CASES = (
    Case('F_XNE', 'cross-table != comparator unsupported in PF-V2.6',
         "1. orders: orders.o_custkey = customer.c_custkey AND (orders.o_totalprice != customer.c_acctbal)", '3'),
    Case('F_K3', 'cross-table comparator separator key arity > 2 (customer-orders-lineitem-supplier chain)',
         "3. supplier: supplier.s_suppkey = lineitem.l_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND (customer.c_acctbal <= supplier.s_acctbal)", '5'),
    Case('F_CYCLE', 'cyclic factor graph with cross-table comparator (policy29 shape)',
         "5. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND (lineitem.l_quantity <= partsupp.ps_availqty)", '6'),
)

@contextmanager
def env_force():
    old_pgoptions = os.environ.get('PGOPTIONS')
    old_cf_strict = os.environ.get('CF_POLICY_STRICT_MODE')
    os.environ['PGOPTIONS'] = ' '.join([
        '-c custom_filter.strict_mode=on',
    ])
    os.environ['CF_POLICY_STRICT_MODE'] = '1'
    try: yield
    finally:
        if old_pgoptions is None: os.environ.pop('PGOPTIONS', None)
        else: os.environ['PGOPTIONS'] = old_pgoptions
        if old_cf_strict is None: os.environ.pop('CF_POLICY_STRICT_MODE', None)
        else: os.environ['CF_POLICY_STRICT_MODE'] = old_cf_strict

def qmap() -> Dict[str,str]:
    return {qid:q for qid,q in h.load_queries(REPO_ROOT / 'queries.txt')}

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PF-V2.6 unsupported-shape fail-loud checks')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--statement-timeout', default='10min')
    ap.add_argument('--out-md', default=str(OUT_MD))
    args = ap.parse_args()
    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = qmap()
    lines: List[str] = [
        '# PF-V2.6 Shape Fail-Loud','', f'- db: `{db}`',
        '- mode: `strict_mode=on`','', '## Cases'
    ]
    all_ok = True
    for idx, c in enumerate(CASES, start=1):
        enabled = Path('/tmp') / f'pf_v2_6_shape_fail_{c.code}.txt'
        enabled.parent.mkdir(parents=True, exist_ok=True)
        h.write_enabled_policy_file([c.policy_line], enabled)
        os.chmod(enabled, 0o644)
        qsql = queries[c.query_id]
        status, err = 'PASS', ''
        try:
            h.clear_artifacts(db); h.clear_rls_indexes_and_policies(db)
            with env_force():
                h.setup_ours_for_k(db, idx, enabled, timeout_ms)
                m, _payload, _kv, _cnt, _notices = h.run_ours_profile_capture(
                    db, qsql, enabled, timeout_ms,
                    ours_profile_rescan=False, ours_debug_mode='trace',
                    query_id=c.query_id, profile_k=idx, profile_query=c.query_id,
                )
            msg = (m.error_msg or '') if m.status == 'error' else ''
            if m.status == 'error' and 'PF-V2 path unsupported term shape' in msg:
                status, err = 'PASS', msg
            else:
                status, err = 'FAIL', (msg or 'query unexpectedly succeeded under force mode')
        except Exception as exc:  # noqa: BLE001
            err = (getattr(exc,'pgerror',None) or str(exc)).replace('\n',' ').strip()[:300]
            status = 'PASS' if 'PF-V2 path unsupported term shape' in err else 'FAIL'
        finally:
            try: h.clear_artifacts(db)
            except Exception: pass
            try: h.clear_rls_indexes_and_policies(db)
            except Exception: pass
        all_ok &= (status == 'PASS')
        lines.append(f"- {c.code}: {status} :: {c.desc} :: error=`{err}`")
        print(f"[pf2.6_shape_fail] {c.code} status={status}")
    lines += ['', f"- overall: {'PASS' if all_ok else 'FAIL'}"]
    out_md = Path(args.out_md); out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(f'[done] md={out_md}')

if __name__ == '__main__':
    main()
