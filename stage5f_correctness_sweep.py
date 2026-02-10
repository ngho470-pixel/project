#!/usr/bin/env python3
import csv
import re
from pathlib import Path
from typing import List, Tuple, Dict, Set, Optional

import psycopg2
from psycopg2 import sql

ROOT = Path('/home/ng_lab/z3')
DB = 'tpch0_1'
POLICY_PATH = ROOT / 'policy_supported.txt'
QUERIES_PATH = ROOT / 'queries_fast.txt'
CSV_PATH = ROOT / 'stage5f_correctness_sweep_supported.csv'
CUSTOM_FILTER_SO = '/home/ng_lab/z3/custom_filter/custom_filter.so'
ARTIFACT_BUILDER_SO = '/home/ng_lab/z3/artifact_builder/artifact_builder.so'

Ks = [5, 10, 15, 20]

ROLE_CONFIG = {
    'postgres': {'user': 'postgres', 'password': '12345'},
    'rls_user': {'user': 'rls_user', 'password': 'secret'},
}

TABLES = ['lineitem','orders','customer','nation','region','part','supplier','partsupp']
KEYWORDS = {'and','or','in','like','not','is','null','between','exists'}
CLAUSE_KEYWORDS = {'where','join','on','group','order','limit','left','right','inner','outer','full','cross','union','having'}


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
                import time
                time.sleep(2)
                continue
            raise
    raise last_err


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


def rewrite_policy_expr(target: str, expr: str, target_alias: Optional[str]) -> str:
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
                    if target_alias:
                        out_parts.append(f"{target_alias}.{col_low}")
                    else:
                        out_parts.append(f"{col_low}")
                else:
                    out_parts.append(f"{tbl_low}.{col_low}")
                    if tbl_low not in other_tables:
                        other_tables.append(tbl_low)
            else:
                if target_alias:
                    out_parts.append(f"{target_alias}.{low}")
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


def build_artifacts(policy_path: Path):
    conn = connect('postgres')
    try:
        with conn.cursor() as cur:
            cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}'")
            cur.execute("TRUNCATE public.files")
            cur.execute(sql.SQL("SELECT build_base(%s)"), [str(policy_path)])
    finally:
        conn.close()


def classify_error(msg: str) -> str:
    low = (msg or '').lower()
    if 'unsupported like pattern' in low:
        return 'unsupported_policy_shape'
    if 'unsupported' in low and 'policy' in low:
        return 'unsupported_policy_shape'
    if 'indexonly' in low or 'ctid' in low or 'scan' in low:
        return 'scan_type'
    if 'missing' in low and 'artifact' in low:
        return 'missing_artifact'
    if 'ast mismatch' in low:
        return 'ast_mismatch'
    if 'engine' in low:
        return 'engine_error'
    return 'db_error'


def run_ours(policy_path: Path, sql_text: str) -> Tuple[int, str]:
    conn = connect('postgres')
    try:
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather = 0")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute("SET custom_filter.enabled = on")
            cur.execute("SET custom_filter.contract_mode = off")
            cur.execute("SET custom_filter.debug_mode = 'off'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute(sql_text)
            row = cur.fetchone()
            return (row[0] if row else 0, '')
    except Exception as e:
        msg = getattr(e, 'pgerror', None) or str(e)
        return (0, msg.strip().replace('\n',' ')[:200])
    finally:
        conn.close()


def run_sql_ground_truth(query_sql: str) -> Tuple[int, str]:
    conn = connect('postgres')
    try:
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather = 0")
            cur.execute(query_sql)
            row = cur.fetchone()
            return (row[0] if row else 0, '')
    except Exception as e:
        msg = getattr(e, 'pgerror', None) or str(e)
        return (0, msg.strip().replace('\n',' ')[:200])
    finally:
        conn.close()


def parse_aliases(sql_text: str) -> Dict[str,str]:
    aliases: Dict[str,str] = {}
    for m in re.finditer(r"\bfrom\s+([a-z_][a-z0-9_]*)(?:\s+([a-z_][a-z0-9_]*))?", sql_text, re.IGNORECASE):
        tbl = m.group(1).lower()
        cand = (m.group(2) or tbl).lower()
        alias = cand if cand not in CLAUSE_KEYWORDS else tbl
        aliases[tbl] = alias
    for m in re.finditer(r"\bjoin\s+([a-z_][a-z0-9_]*)(?:\s+([a-z_][a-z0-9_]*))?", sql_text, re.IGNORECASE):
        tbl = m.group(1).lower()
        cand = (m.group(2) or tbl).lower()
        alias = cand if cand not in CLAUSE_KEYWORDS else tbl
        aliases[tbl] = alias
    return aliases


def build_target_filter_expr(target: str, policies: List[str], alias_map: Dict[str,str]) -> Optional[str]:
    exprs = []
    for line in policies:
        if ':' not in line:
            continue
        tgt, expr = line.split(':',1)
        tgt = tgt.strip().lower()
        if tgt != target:
            continue
        expr_sql = rewrite_policy_expr(target, expr.strip(), alias_map.get(target))
        exprs.append(f"({expr_sql})")
    if not exprs:
        return None
    return ' AND '.join(exprs)


def apply_filters_to_query(sql_text: str, filters: List[str]) -> str:
    filt = ' AND '.join(filters)
    if not filt:
        return sql_text
    text = sql_text.strip().rstrip(';')
    if re.search(r"\bwhere\b", text, re.IGNORECASE):
        return text + " AND (" + filt + ");"
    return text + " WHERE " + filt + ";"


def scan_tables(sql_text: str) -> Set[str]:
    tables = set()
    for m in re.finditer(r"\bfrom\s+([a-z_][a-z0-9_]*)|\bjoin\s+([a-z_][a-z0-9_]*)", sql_text, re.IGNORECASE):
        tbl = m.group(1) or m.group(2)
        if tbl:
            tables.add(tbl.lower())
    return tables


def main():
    policy_lines = load_policy_lines(POLICY_PATH)
    queries = load_queries(QUERIES_PATH)
    rows = []
    error_summary: Dict[str,int] = {}

    with CSV_PATH.open('w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['K','query_id','targets','ground_truth_source','ours_count','gt_count','status','error_type'])

    for k in Ks:
        if len(policy_lines) < k:
            raise SystemExit(f"policy.txt has only {len(policy_lines)} lines, cannot take K={k}")
        tmp_policy = Path(f"/tmp/policy_k{k}.txt")
        tmp_policy.write_text("\n".join(policy_lines[:k]) + "\n")
        build_artifacts(tmp_policy)
        targets_set = {line.split(':',1)[0].strip().lower() for line in policy_lines[:k] if ':' in line}

        for qid, sql_text in queries:
            scanned = scan_tables(sql_text)
            targets = sorted(list(targets_set.intersection(scanned)))
            targets_str = ','.join(targets) if targets else ''

            ours_count, ours_err = run_ours(tmp_policy, sql_text)
            alias_map = parse_aliases(sql_text)
            filters: List[str] = []
            for tgt in targets:
                expr = build_target_filter_expr(tgt, policy_lines[:k], alias_map)
                if expr:
                    filters.append(expr)
            gt_sql = apply_filters_to_query(sql_text, filters)
            gt_source = 'rewritten_sql'
            gt_count, gt_err = run_sql_ground_truth(gt_sql)

            status = 'PASS'
            err_type = ''
            if ours_err:
                status = 'ERROR'
                err_type = classify_error(ours_err)
                error_summary[err_type] = error_summary.get(err_type, 0) + 1
            elif gt_err:
                status = 'ERROR'
                err_type = classify_error(gt_err)
                error_summary[err_type] = error_summary.get(err_type, 0) + 1
            elif ours_count != gt_count:
                status = 'FAIL'
            rows.append([k, qid, targets_str, gt_source, ours_count if not ours_err else '', gt_count if not gt_err else '', status, err_type])
            with CSV_PATH.open('a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(rows[-1])

    # print summary table
    print("K\tquery_id\ttargets\tground_truth_source\tours_count\tgt_count\tstatus\terror_type")
    for r in rows:
        print("\t".join(str(x) for x in r))

    if error_summary:
        print("\nError summary:")
        for k, v in sorted(error_summary.items()):
            print(f"{k}: {v}")


if __name__ == '__main__':
    main()
