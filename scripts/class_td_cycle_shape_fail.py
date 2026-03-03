#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / 'custom_filter' / 'custom_filter.so')
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / 'artifact_builder' / 'artifact_builder.so')

OUT_MD = REPO_ROOT / 'logs' / 'class_td_cycle_shape_fail.md'

POLICY = "1. lineitem: lineitem.l_suppkey = supplier.s_suppkey AND lineitem.l_orderkey = orders.o_orderkey AND orders.o_custkey = customer.c_custkey AND customer.c_nationkey = supplier.s_nationkey AND lineitem.l_quantity > 10 AND supplier.s_suppkey <= 1000 AND customer.c_custkey <= 50000 AND orders.o_orderkey <= 200000"


@contextmanager
def strict_env(width_limit: int):
    old_pgoptions = os.environ.get('PGOPTIONS')
    old_cf_strict = os.environ.get('CF_POLICY_STRICT_MODE')
    os.environ['PGOPTIONS'] = f'-c custom_filter.strict_mode=on -c custom_filter.class_td_width_limit={int(width_limit)}'
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

def run_count_hash(db: str, baseline: str, qid: str, qsql: str, enabled_path: Path, timeout_ms: int, width_limit: int):
    conn = None
    try:
        conn = h.connect(db, h.role_for_baseline(baseline))
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, timeout_ms)
            cur.execute(f'SET custom_filter.class_td_width_limit = {int(width_limit)};')
            if baseline in ('rls', 'rls_with_index'):
                cur.execute('SET row_security = on;')
            cnt, hh = h.result_count_and_hash_in_session(cur, qid, qsql)
            return int(cnt), str(hh or ''), ''
    except Exception as exc:  # noqa: BLE001
        return None, None, (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()[:320]
    finally:
        if conn is not None:
            conn.close()


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description='Class-engine TD-cycle width fail-loud check')
    ap.add_argument('--db', default='tpch1')
    ap.add_argument('--query-id', default='6')
    ap.add_argument('--statement-timeout', default='20min')
    ap.add_argument('--out-md', default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    qid = str(args.query_id)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    queries = {x: y for x, y in h.load_queries(REPO_ROOT / 'queries.txt')}
    qsql = queries[qid]

    enabled = Path('/tmp') / 'class_td_cycle_shape_fail_enabled.txt'
    h.write_enabled_policy_file([POLICY], enabled)
    os.chmod(enabled, 0o644)

    status = 'PASS'
    reason = ''
    expected_substr = 'td_width='

    try:
        run_hygiene(db)
        h.clear_artifacts(db)
        h.clear_rls_indexes_and_policies(db)
        with strict_env(width_limit=1):
            h.setup_ours_for_k(db, 1, enabled, timeout_ms)
            cnt, hh, err = run_count_hash(db, 'ours', qid, qsql, enabled, timeout_ms, 1)
        if cnt is None and expected_substr in (err or '') and 'unsupported term shape' in (err or ''):
            status = 'PASS'
            reason = (err or '')[:360]
        else:
            status = 'FAIL'
            reason = f'unexpected success cnt={cnt} hash={hh} err={err}'
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, 'pgerror', None) or str(exc)).replace('\n', ' ').strip()
        if expected_substr in msg and 'unsupported term shape' in msg:
            status = 'PASS'
            reason = msg[:360]
        else:
            status = 'FAIL'
            reason = msg[:360]
    finally:
        try:
            h.clear_artifacts(db)
        except Exception:
            pass
        try:
            h.clear_rls_indexes_and_policies(db)
        except Exception:
            pass

    lines = [
        '# Class Engine TD-Cycle Shape Fail',
        '',
        f"- db: `{db}`",
        f"- query_id: `{qid}`",
        '- mode: `strict_mode=on`, `custom_filter.class_td_width_limit=1`',
        f"- status: **{status}**",
        f"- reason: `{reason}`",
        '',
        'Expectation: a cyclic TD route with computed width > 1 must fail-loud in strict mode.',
    ]
    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'[class_td_cycle_shape_fail] status={status}')


if __name__ == '__main__':
    main()
