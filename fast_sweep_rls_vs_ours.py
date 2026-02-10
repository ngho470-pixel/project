#!/usr/bin/env python3
import csv
import os
import re
import time
import threading
from pathlib import Path
from statistics import median
from typing import Dict, List, Tuple

import psycopg2
from psycopg2 import sql

ROOT = Path('/home/ng_lab/z3')
DB = 'tpch0_1'
POLICY_PATH = ROOT / 'policy.txt'
QUERIES_PATH = ROOT / 'queries_fast.txt'
CSV_PATH = ROOT / 'fast_sweep_rls_vs_ours_timeout30m.csv'
CUSTOM_FILTER_SO = '/home/ng_lab/z3/custom_filter/custom_filter.so'
ARTIFACT_BUILDER_SO = '/home/ng_lab/z3/artifact_builder/artifact_builder.so'

Ks = [5, 10, 15, 20]
HOT_RUNS = 5
STATEMENT_TIMEOUT = "30min"

ROLE_CONFIG = {
    'postgres': {'user': 'postgres', 'password': '12345'},
    'rls_user': {'user': 'rls_user', 'password': 'secret'},
}

BASE_COLUMNS = [
    'baseline','K','query_id','trial_type','trial_idx','elapsed_ms',
    'mem_peak_mb','mem_delta_mb','status','error_type','error_msg'
]

BASELINE_ORDER = ['nopolicy','ours','rls_with_index','rls_no_index']

KEYWORDS = {'and','or','in','like','not','is','null','between','exists'}


def connect(role: str):
    cfg = ROLE_CONFIG[role]
    last_err = None
    for _ in range(30):
        try:
            conn = psycopg2.connect(
                host='localhost', port=5432, dbname=DB,
                user=cfg['user'], password=cfg['password']
            )
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as e:
            last_err = e
            msg = str(e).lower()
            if 'recovery mode' in msg or 'starting up' in msg:
                time.sleep(2)
                continue
            raise
    raise last_err


def read_mem_kb(pid: int) -> Tuple[int,int]:
    rss = 0
    hwm = 0
    try:
        with open(f'/proc/{pid}/status','r') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    rss = int(line.split()[1])
                elif line.startswith('VmHWM:'):
                    hwm = int(line.split()[1])
    except FileNotFoundError:
        return (rss,hwm)
    return (rss,hwm)


def classify_error(exc: Exception, msg: str) -> Tuple[str,str]:
    low = (msg or '').lower()
    if 'statement timeout' in low or isinstance(exc, psycopg2.errors.QueryCanceled):
        return 'timeout', msg
    if 'indexonlyscan' in low or 'index only scan' in low or 'unsupported scan' in low:
        return 'unsupported_scan_shape', msg
    if 'unsupported boolean structure' in low or 'unsupported policy' in low or 'unsupported ast' in low:
        return 'unsupported_policy_shape', msg
    if 'artifact' in low and ('missing' in low or 'not found' in low):
        return 'missing_artifact', msg
    if 'policy engine' in low or 'engine error' in low or 'assert' in low:
        return 'engine_error', msg
    if isinstance(exc, psycopg2.Error):
        return 'db_error', msg
    return 'db_error', msg


def run_with_mem(cur, sql_text: str) -> Tuple[float,str,str,str,float,float]:
    cur.execute('SELECT pg_backend_pid()')
    pid = cur.fetchone()[0]
    stop = threading.Event()
    peak_rss = 0
    peak_hwm = 0
    start_hwm = 0
    _, start_hwm = read_mem_kb(pid)

    def monitor():
        nonlocal peak_rss, peak_hwm
        while not stop.is_set():
            rss,hwm = read_mem_kb(pid)
            if rss > peak_rss:
                peak_rss = rss
            if hwm > peak_hwm:
                peak_hwm = hwm
            time.sleep(0.02)

    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    t0 = time.perf_counter()
    status = 'ok'
    err_type = ''
    err_msg = ''
    try:
        cur.execute(sql_text)
        # fetch to ensure completion
        cur.fetchall()
    except Exception as e:
        status = 'error'
        msg = getattr(e, 'pgerror', None) or str(e)
        msg = msg.strip().replace('\n', ' ')[:120]
        err_type, err_msg = classify_error(e, msg)
    finally:
        stop.set()
        t.join(timeout=1)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    peak_kb = peak_hwm if peak_hwm else peak_rss
    peak_mb = (peak_kb / 1024.0) if peak_kb else 0.0
    mem_delta = 0.0
    if peak_hwm and start_hwm and peak_hwm >= start_hwm:
        mem_delta = (peak_hwm - start_hwm) / 1024.0
    return elapsed_ms, status, err_type, err_msg, peak_mb, mem_delta


def load_policy_lines(path: Path) -> List[str]:
    lines = []
    for raw in path.read_text().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        raw = re.sub(r'^\s*\d+\.\s*', '', raw)
        lines.append(raw)
    return lines


def load_queries(path: Path) -> List[Tuple[str,str]]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if ':' not in line:
            continue
        qid, sql_text = line.split(':',1)
        sql_text = sql_text.strip()
        if not sql_text.endswith(';'):
            sql_text += ';'
        out.append((qid.strip(), sql_text))
    return out


def tokenize(expr: str) -> List[Tuple[str,str]]:
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
            j = i+1
            if j < len(expr) and expr[j] == '=':
                j += 1
            tokens.append(('op', expr[i:j]))
            i = j
            continue
        # default
        tokens.append((ch, ch))
        i += 1
    return tokens


def rewrite_policy_expr(target: str, expr: str) -> Tuple[str,List[str]]:
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
    return expr_sql, other_tables


def build_rls_policies(conn, policy_lines: List[str]):
    # group by target
    by_target: Dict[str,List[str]] = {}
    for line in policy_lines:
        if ':' not in line:
            continue
        target, expr = line.split(':',1)
        target = target.strip().lower()
        expr = expr.strip()
        expr_sql, _ = rewrite_policy_expr(target, expr)
        by_target.setdefault(target, []).append(f"({expr_sql})")

    tables = ['lineitem','orders','customer','nation','region','part','supplier','partsupp']
    with conn.cursor() as cur:
        cur.execute("SET LOCAL search_path TO public, pg_catalog")
        # disable all first
        for t in tables:
            cur.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("DROP POLICY IF EXISTS cf_all ON {};").format(sql.Identifier(t)))
        for t, exprs in by_target.items():
            if not exprs:
                continue
            combined = ' AND '.join(exprs)
            cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("CREATE POLICY cf_all ON {} FOR SELECT TO rls_user USING ({});").format(
                sql.Identifier(t), sql.SQL(combined)))


def apply_session_settings(cur, baseline: str):
    cur.execute("SET max_parallel_workers_per_gather = 0;")
    cur.execute(f"SET statement_timeout = '{STATEMENT_TIMEOUT}';")
    if baseline == 'ours':
        cur.execute("SET enable_indexonlyscan = off;")
    elif baseline == 'rls_no_index':
        cur.execute("SET enable_indexonlyscan = off;")
        cur.execute("SET enable_indexscan = off;")
        cur.execute("SET enable_bitmapscan = off;")
        cur.execute("SET enable_seqscan = on;")


def run_baseline_query(baseline: str, k: int, qid: str, sql_text: str, policy_path: str, trial_type: str, trial_idx: int, rows: List[Dict[str,str]]):
    role = 'postgres' if baseline in ('ours','nopolicy') else 'rls_user'
    conn = connect(role)
    try:
        with conn.cursor() as cur:
            apply_session_settings(cur, baseline)
            if baseline == 'ours':
                cur.execute(f"LOAD '{CUSTOM_FILTER_SO}';")
                cur.execute("SET custom_filter.enabled = on;")
                cur.execute("SET custom_filter.contract_mode = off;")
                cur.execute("SET custom_filter.debug_mode = 'off';")
                cur.execute("SET enable_tidscan = off;")
                cur.execute(sql.SQL("SET custom_filter.policy_path = %s;") , [policy_path])
            else:
                cur.execute("SET custom_filter.enabled = off;")
            elapsed_ms, status, err_type, err_msg, peak_mb, delta_mb = run_with_mem(cur, sql_text)
    finally:
        conn.close()
    rows.append({
        'baseline': baseline,
        'K': str(k),
        'query_id': qid,
        'trial_type': trial_type,
        'trial_idx': str(trial_idx),
        'elapsed_ms': f"{elapsed_ms:.3f}",
        'mem_peak_mb': f"{peak_mb:.3f}",
        'mem_delta_mb': f"{delta_mb:.3f}",
        'status': status,
        'error_type': err_type,
        'error_msg': err_msg,
    })


def main():
    policy_lines = load_policy_lines(POLICY_PATH)
    queries = load_queries(QUERIES_PATH)

    rows: List[Dict[str,str]] = []
    # initialize CSV with header
    with CSV_PATH.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=BASE_COLUMNS)
        writer.writeheader()

    for k in Ks:
        if len(policy_lines) < k:
            raise SystemExit(f"policy.txt has only {len(policy_lines)} lines, cannot take K={k}")
        tmp_policy = Path(f"/tmp/policy_k{k}.txt")
        tmp_policy.write_text("\n".join(policy_lines[:k]) + "\n")

        # build artifacts once per K
        conn = connect('postgres')
        try:
            with conn.cursor() as cur:
                cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}';")
                cur.execute("TRUNCATE public.files;")
                cur.execute(sql.SQL("SELECT build_base(%s);") , [str(tmp_policy)])
        finally:
            conn.close()

        # build RLS policies once per K
        conn = connect('postgres')
        try:
            build_rls_policies(conn, policy_lines[:k])
        finally:
            conn.close()

        for baseline in BASELINE_ORDER:
            for qid, sql_text in queries:
                # cold run
                run_baseline_query(baseline, k, qid, sql_text, str(tmp_policy), 'cold', 0, rows)
                with CSV_PATH.open('a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=BASE_COLUMNS)
                    writer.writerow(rows[-1])
                # hot runs
                for i in range(HOT_RUNS):
                    run_baseline_query(baseline, k, qid, sql_text, str(tmp_policy), 'hot', i+1, rows)
                    with CSV_PATH.open('a', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=BASE_COLUMNS)
                        writer.writerow(rows[-1])

    print(f"Wrote CSV to {CSV_PATH}")


if __name__ == '__main__':
    main()
