#!/usr/bin/env python3
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import psycopg2
from psycopg2 import sql

ROOT = Path('/home/ng_lab/z3')
DB = 'tpch0_1'
CUSTOM_FILTER_SO = '/home/ng_lab/z3/custom_filter/custom_filter.so'
ARTIFACT_BUILDER_SO = '/home/ng_lab/z3/artifact_builder/artifact_builder.so'

ROLE_CONFIG = {
    'postgres': {'user': 'postgres', 'password': '12345'},
    'rls_user': {'user': 'rls_user', 'password': 'secret'},
}

TABLES = ['lineitem','orders','customer','nation','region','part','supplier','partsupp']

KEYWORDS = {'and','or','in','like','not','is','null','between','exists'}


def connect(role: str):
    cfg = ROLE_CONFIG[role]
    conn = psycopg2.connect(
        host='localhost', port=5432, dbname=DB,
        user=cfg['user'], password=cfg['password']
    )
    conn.autocommit = True
    return conn


def tokenize(expr: str):
    tokens = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch.isalpha() or ch == '_':
            j = i+1
            while j < len(expr) and (expr[j].isalnum() or expr[j] in '_.'):
                j += 1
            tokens.append(('ident', expr[i:j]))
            i = j
            continue
        if ch.isdigit() or (ch=='-' and i+1 < len(expr) and expr[i+1].isdigit()):
            j = i+1
            while j < len(expr) and (expr[j].isdigit() or expr[j]=='.'):
                j += 1
            tokens.append(('number', expr[i:j]))
            i = j
            continue
        if ch == "'":
            j = i+1
            buf = ''
            while j < len(expr):
                if expr[j] == "'" and j+1 < len(expr) and expr[j+1] == "'":
                    buf += "'"
                    j += 2
                    continue
                if expr[j] == "'":
                    j += 1
                    break
                buf += expr[j]
                j += 1
            tokens.append(('string', buf))
            i = j
            continue
        if ch in '(),':
            tokens.append((ch, ch))
            i += 1
            continue
        if ch in '=<>!':
            # handle <> and <= >= !=
            if i + 1 < len(expr) and expr[i:i+2] in ('<>','<=','>=','!='):
                tokens.append(('op', expr[i:i+2]))
                i += 2
                continue
            j = i+1
            if j < len(expr) and expr[j] == '=':
                j += 1
            tokens.append(('op', expr[i:j]))
            i = j
            continue
        tokens.append((ch, ch))
        i += 1
    return tokens


def rewrite_policy_expr(target: str, expr: str):
    tokens = tokenize(expr)
    other_tables = []
    out_parts = []
    for typ, text in tokens:
        if typ == 'ident':
            low = text.lower()
            if low in KEYWORDS:
                out_parts.append(low)
                continue
            if '.' in text:
                tbl, col = text.split('.',1)
                tbl_low = tbl.lower()
                col_low = col.lower()
                if tbl_low == target.lower():
                    out_parts.append(f"{col_low}")
                else:
                    out_parts.append(f"{tbl_low}.{col_low}")
                    if tbl_low not in other_tables:
                        other_tables.append(tbl_low)
            else:
                out_parts.append(f"{low}")
        elif typ == 'string':
            out_parts.append("'" + text.replace("'","''") + "'")
        elif typ == 'number':
            out_parts.append(text)
        elif typ == 'op':
            out_parts.append(text)
        else:
            out_parts.append(text)
    expr_sql = ' '.join(out_parts)
    if other_tables:
        from_clause = ', '.join(other_tables)
        expr_sql = f"EXISTS (SELECT 1 FROM {from_clause} WHERE {expr_sql})"
    return expr_sql


def build_rls_policies(conn, policy_lines: List[str]):
    by_target: Dict[str,List[str]] = {}
    for line in policy_lines:
        if ':' not in line:
            continue
        target, expr = line.split(':',1)
        target = target.strip().lower()
        expr = expr.strip()
        expr_sql = rewrite_policy_expr(target, expr)
        by_target.setdefault(target, []).append(f"({expr_sql})")
    with conn.cursor() as cur:
        cur.execute("SET LOCAL search_path TO public, pg_catalog")
        for t in TABLES:
            cur.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("DROP POLICY IF EXISTS cf_all ON {};").format(sql.Identifier(t)))
        for t, exprs in by_target.items():
            if not exprs:
                continue
            combined = ' AND '.join(exprs)
            cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("CREATE POLICY cf_all ON {} FOR SELECT TO rls_user USING ({});").format(
                sql.Identifier(t), sql.SQL(combined)))


def run_ours(policy_path: Path, query_sql: str, log_path: Path) -> Tuple[Optional[int], Optional[str]]:
    conn = connect('postgres')
    try:
        conn.notices.clear()
        with conn.cursor() as cur:
            cur.execute("SET client_min_messages = notice")
            cur.execute("SET max_parallel_workers_per_gather = 0")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute("SET custom_filter.enabled = on")
            cur.execute("SET custom_filter.contract_mode = off")
            cur.execute("SET custom_filter.debug_mode = 'contract'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute(query_sql)
            row = cur.fetchone()
        # collect notices
        notices = list(conn.notices)
        log_path.write_text(''.join(notices))
        return (row[0] if row else None, None)
    except Exception as e:
        msg = getattr(e, 'pgerror', None) or str(e)
        msg = msg.strip().replace('\n',' ')[:200]
        # still write notices
        try:
            log_path.write_text(''.join(conn.notices) + f"\nERROR: {msg}\n")
        except Exception:
            pass
        return None, msg
    finally:
        conn.close()


def run_rls(policy_lines: List[str], query_sql: str, log_path: Path) -> Tuple[Optional[int], Optional[str]]:
    conn = connect('postgres')
    try:
        build_rls_policies(conn, policy_lines)
    finally:
        conn.close()
    conn = connect('rls_user')
    try:
        conn.notices.clear()
        with conn.cursor() as cur:
            cur.execute("SET client_min_messages = notice")
            cur.execute("SET max_parallel_workers_per_gather = 0")
            cur.execute(query_sql)
            row = cur.fetchone()
        log_path.write_text(''.join(conn.notices))
        return (row[0] if row else None, None)
    except Exception as e:
        msg = getattr(e, 'pgerror', None) or str(e)
        msg = msg.strip().replace('\n',' ')[:200]
        try:
            log_path.write_text(''.join(conn.notices) + f"\nERROR: {msg}\n")
        except Exception:
            pass
        return None, msg
    finally:
        conn.close()


def build_artifacts(policy_path: Path):
    conn = connect('postgres')
    try:
        with conn.cursor() as cur:
            cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}'")
            cur.execute("TRUNCATE public.files")
            cur.execute(sql.SQL("SELECT build_base(%s)"), [str(policy_path)])
    finally:
        conn.close()


def main():
    tests = []
    # Test 1
    tests.append({
        'id': 'T1',
        'targets': 'orders',
        'policies': [
            "orders : orders.o_custkey = customer.c_custkey AND (customer.c_mktsegment = 'AUTOMOBILE' OR customer.c_mktsegment = 'HOUSEHOLD')",
            "orders : orders.o_orderstatus <> 'F'",
        ],
        'query': "SELECT COUNT(*) FROM orders;",
        'expect_error': False,
        'use_sql_ground_truth': False,
    })
    # Test 2
    tests.append({
        'id': 'T2',
        'targets': 'orders,lineitem',
        'policies': [
            "orders : orders.o_custkey = customer.c_custkey AND (customer.c_mktsegment = 'AUTOMOBILE' OR customer.c_mktsegment = 'HOUSEHOLD')",
            "lineitem : lineitem.l_shipmode IN ('MAIL','SHIP')",
        ],
        'query': "SELECT COUNT(*) FROM lineitem l JOIN orders o ON l.l_orderkey = o.o_orderkey;",
        'expect_error': False,
        'use_sql_ground_truth': False,
    })
    # Test 3
    tests.append({
        'id': 'T3',
        'targets': 'customer',
        'policies': [
            "customer : (customer.c_acctbal > 0) AND ((customer.c_mktsegment = 'FURNITURE') OR (customer.c_mktsegment = 'HOUSEHOLD'))",
        ],
        'query': "SELECT COUNT(*) FROM orders o JOIN customer c ON o.o_custkey = c.c_custkey;",
        'expect_error': False,
        'use_sql_ground_truth': False,
    })
    # Test 4
    tests.append({
        'id': 'T4',
        'targets': 'orders',
        'policies': [
            "orders : orders.o_custkey = customer.c_custkey AND customer.c_nationkey = nation.n_nationkey AND nation.n_regionkey = region.r_regionkey AND lineitem.l_orderkey = orders.o_orderkey AND ((region.r_name IN ('EUROPE','ASIA') AND orders.o_orderstatus IN ('O','F')) OR (lineitem.l_shipmode IN ('MAIL','SHIP') AND orders.o_orderpriority IN ('1-URGENT','2-HIGH')))"
        ],
        'query': "SELECT COUNT(*) FROM orders;",
        'expect_error': False,
        'use_sql_ground_truth': True,
        'ground_truth_sql': """
SELECT COUNT(*)
FROM orders o
JOIN customer c ON o.o_custkey=c.c_custkey
JOIN nation n ON c.c_nationkey=n.n_nationkey
JOIN region r ON n.n_regionkey=r.r_regionkey
WHERE (
   (r.r_name IN ('EUROPE','ASIA') AND o.o_orderstatus IN ('O','F'))
   OR
   (
     o.o_orderpriority IN ('1-URGENT','2-HIGH')
     AND EXISTS (
        SELECT 1 FROM lineitem l
        WHERE l.l_orderkey = o.o_orderkey
          AND l.l_shipmode IN ('MAIL','SHIP')
     )
   )
);
""",
    })
    # Test 5
    tests.append({
        'id': 'T5',
        'targets': 'customer',
        'policies': [
            "customer : (customer.c_phone LIKE '2%') AND (customer.c_acctbal >= 500)",
        ],
        'query': "SELECT COUNT(*) FROM customer;",
        'expect_error': False,
        'use_sql_ground_truth': False,
    })
    # Test 6
    tests.append({
        'id': 'T6',
        'targets': 'customer',
        'policies': [
            "customer : (customer.c_phone LIKE '%-%')",
        ],
        'query': "SELECT COUNT(*) FROM customer;",
        'expect_error': True,
        'use_sql_ground_truth': False,
    })

    results = []

    for test in tests:
        policy_path = Path(f"/tmp/policy_{test['id']}.txt")
        policy_path.write_text("\n".join(test['policies']) + "\n")
        build_artifacts(policy_path)

        ours_log = ROOT / f"stage5d_{test['id']}_ours.log"
        rls_log = ROOT / f"stage5d_{test['id']}_rls.log"
        gt_log = ROOT / f"stage5d_{test['id']}_sql.log"

        ours_count, ours_err = run_ours(policy_path, test['query'], ours_log)

        rls_count = None
        rls_err = None
        if test.get('use_sql_ground_truth'):
            # use ground truth SQL
            conn = connect('postgres')
            try:
                with conn.cursor() as cur:
                    cur.execute(test['ground_truth_sql'])
                    row = cur.fetchone()
                    rls_count = row[0] if row else None
                gt_log.write_text(f"GT_COUNT={rls_count}\n")
            finally:
                conn.close()
        else:
            rls_count, rls_err = run_rls(test['policies'], test['query'], rls_log)

        status = 'FAIL'
        if test['expect_error']:
            status = 'PASS' if ours_err else 'FAIL'
        else:
            if ours_err or rls_err:
                status = 'FAIL'
            elif ours_count == rls_count:
                status = 'PASS'
        results.append({
            'test_id': test['id'],
            'query': test['query'].strip(),
            'targets': test['targets'],
            'ours_count': ours_count if ours_err is None else f"ERROR({ours_err})",
            'rls_count': rls_count if rls_err is None else f"ERROR({rls_err})",
            'status': status,
        })

    # print table
    print("test_id\tquery\ttargets\tours_count\trls_count\tstatus")
    for r in results:
        print(f"{r['test_id']}\t{r['query']}\t{r['targets']}\t{r['ours_count']}\t{r['rls_count']}\t{r['status']}")


if __name__ == '__main__':
    main()
