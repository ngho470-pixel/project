#!/usr/bin/env python3
import csv
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psycopg2
from psycopg2 import sql

ROOT = Path("/home/ng_lab/z3")
DB = "tpch0_1"
POLICY_SUPPORTED = ROOT / "policy_supported.txt"
QUERIES_SCALE = ROOT / "queries_scale.txt"
CSV_OUT = ROOT / "policy_scale_correctness.csv"
MD_OUT = ROOT / "policy_scale_correctness.md"
LOG_DIR = ROOT / "logs"
CUSTOM_FILTER_SO = "/home/ng_lab/z3/custom_filter/custom_filter.so"
ARTIFACT_BUILDER_SO = "/home/ng_lab/z3/artifact_builder/artifact_builder.so"

Ks = [5, 10, 15, 20]

ROLE_CONFIG = {
    "postgres": {"user": "postgres", "password": "12345"},
    "rls_user": {"user": "rls_user", "password": "secret"},
}

TABLES = ["lineitem", "orders", "customer", "nation", "region", "part", "supplier", "partsupp"]
KEYWORDS = {"and", "or", "in", "like", "not", "is", "null", "between", "exists"}
CLAUSE_KEYWORDS = {"where", "join", "on", "group", "order", "limit", "left", "right", "inner", "outer", "full", "cross", "union", "having"}


@dataclass
class RowResult:
    K: int
    query_id: str
    status: str
    error_type: str
    ours_count: Optional[int]
    gt_count: Optional[int]
    gt_source: str
    targets: str
    closure: str
    scanned: str
    wrapped: str
    policy_file: str


def connect(role: str):
    cfg = ROLE_CONFIG[role]
    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        dbname=DB,
        user=cfg["user"],
        password=cfg["password"],
    )
    conn.autocommit = True
    return conn


def load_policy_lines(path: Path) -> List[str]:
    lines: List[str] = []
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if not s:
            continue
        s = re.sub(r"^\s*\d+\.\s*", "", s)
        lines.append(s)
    return lines


def load_queries(path: Path) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for raw in path.read_text().splitlines():
        s = raw.strip()
        if not s or ":" not in s:
            continue
        qid, q = s.split(":", 1)
        q = q.strip()
        if not q.endswith(";"):
            q += ";"
        out.append((qid.strip(), q))
    return out


def tokenize(expr: str):
    tokens = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < len(expr) and (expr[j].isalnum() or expr[j] in "_."):
                j += 1
            tokens.append(("ident", expr[i:j]))
            i = j
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < len(expr) and expr[i + 1].isdigit()):
            j = i + 1
            while j < len(expr) and (expr[j].isdigit() or expr[j] == "."):
                j += 1
            tokens.append(("number", expr[i:j]))
            i = j
            continue
        if ch == "'":
            j = i + 1
            buf = ""
            while j < len(expr):
                if expr[j] == "'" and j + 1 < len(expr) and expr[j + 1] == "'":
                    buf += "'"
                    j += 2
                    continue
                if expr[j] == "'":
                    j += 1
                    break
                buf += expr[j]
                j += 1
            tokens.append(("string", buf))
            i = j
            continue
        if ch in "(),":
            tokens.append((ch, ch))
            i += 1
            continue
        if ch in "=<>!":
            if i + 1 < len(expr) and expr[i:i + 2] in ("<>", "<=", ">=", "!="):
                tokens.append(("op", expr[i:i + 2]))
                i += 2
                continue
            j = i + 1
            if j < len(expr) and expr[j] == "=":
                j += 1
            tokens.append(("op", expr[i:j]))
            i = j
            continue
        tokens.append((ch, ch))
        i += 1
    return tokens


def rewrite_policy_expr(target: str, expr: str, target_alias: Optional[str]) -> str:
    tokens = tokenize(expr)
    other_tables: List[str] = []
    out_parts: List[str] = []
    for typ, text in tokens:
        if typ == "ident":
            low = text.lower()
            if low in KEYWORDS:
                out_parts.append(low)
                continue
            if "." in text:
                tbl, col = text.split(".", 1)
                tbl_low = tbl.lower()
                col_low = col.lower()
                if tbl_low == target.lower():
                    if target_alias:
                        out_parts.append(f"{target_alias}.{col_low}")
                    else:
                        out_parts.append(col_low)
                else:
                    out_parts.append(f"{tbl_low}.{col_low}")
                    if tbl_low not in other_tables:
                        other_tables.append(tbl_low)
            else:
                if target_alias:
                    out_parts.append(f"{target_alias}.{low}")
                else:
                    out_parts.append(low)
        elif typ == "string":
            out_parts.append("'" + text.replace("'", "''") + "'")
        else:
            out_parts.append(text)
    expr_sql = " ".join(out_parts)
    if other_tables:
        from_clause = ", ".join(other_tables)
        expr_sql = f"EXISTS (SELECT 1 FROM {from_clause} WHERE {expr_sql})"
    return expr_sql


def build_rls_policies(conn, policy_lines: List[str]):
    by_target: Dict[str, List[str]] = {}
    for line in policy_lines:
        if ":" not in line:
            continue
        target, expr = line.split(":", 1)
        target = target.strip().lower()
        expr_sql = rewrite_policy_expr(target, expr.strip(), None)
        by_target.setdefault(target, []).append(f"({expr_sql})")

    with conn.cursor() as cur:
        cur.execute("SET LOCAL search_path TO public, pg_catalog")
        for t in TABLES:
            cur.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("DROP POLICY IF EXISTS cf_all ON {};").format(sql.Identifier(t)))
        for t, exprs in by_target.items():
            if not exprs:
                continue
            combined = " AND ".join(exprs)
            cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
            cur.execute(sql.SQL("CREATE POLICY cf_all ON {} FOR SELECT TO rls_user USING ({});").format(sql.Identifier(t), sql.SQL(combined)))


def classify_error(msg: str) -> str:
    low = (msg or "").lower()
    if "server closed the connection unexpectedly" in low or "terminating connection due to administrator command" in low:
        return "backend_crash"
    if "unsupported like pattern" in low or "unsupported boolean structure" in low:
        return "unsupported_policy_shape"
    if "indexonlyscan" in low or ("ctid" in low and "missing" in low):
        return "unsupported_scan_shape"
    if "missing artifact" in low:
        return "missing_artifact"
    if "ast mismatch" in low:
        return "ast_mismatch"
    if "statement timeout" in low or "canceling statement due to statement timeout" in low:
        return "timeout"
    if not low:
        return ""
    return "engine_error"


def parse_contract_metadata(notices: str) -> Dict[str, str]:
    def extract_array(tag: str) -> str:
        m = re.search(rf"{re.escape(tag)}\s*=\s*(\[[^\n]*\])", notices)
        return m.group(1) if m else ""

    wrapped = sorted(set(re.findall(r"custom_filter: wrap rel=([a-zA-Z0-9_]+)", notices)))
    return {
        "targets": extract_array("custom_filter: policy_targets"),
        "closure": extract_array("custom_filter: closure_tables"),
        "scanned": extract_array("custom_filter: scanned_tables"),
        "needed_files": extract_array("custom_filter: needed_files"),
        "wrapped": "[" + ", ".join(wrapped) + "]" if wrapped else "",
    }


def write_log(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def run_gt_rls(query: str, policy_lines: List[str], gt_log: Path) -> Tuple[Optional[int], str]:
    conn = connect("postgres")
    try:
        build_rls_policies(conn, policy_lines)
    finally:
        conn.close()

    conn = connect("rls_user")
    try:
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute(query)
            row = cur.fetchone()
            count = row[0] if row else None
            write_log(gt_log, f"QUERY:\n{query}\nGT_SOURCE: rls\nCOUNT: {count}\n")
            return count, ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        write_log(gt_log, f"QUERY:\n{query}\nGT_SOURCE: rls\nERROR: {msg}\n")
        return None, msg
    finally:
        conn.close()


def run_contract_and_explain(query: str, policy_path: Path, contract_log: Path) -> Tuple[Dict[str, str], str]:
    conn = connect("postgres")
    try:
        notices_out = []
        explain_off = []
        explain_on = []
        err = ""
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute("SET client_min_messages=notice")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute("SET custom_filter.contract_mode=on")
            cur.execute("SET custom_filter.debug_mode='contract'")

            cur.execute("SET custom_filter.enabled=off")
            cur.execute("EXPLAIN (COSTS OFF) " + query.rstrip(";") + ";")
            explain_off = [r[0] for r in cur.fetchall()]
            notices_out.extend(conn.notices)
            conn.notices.clear()

            cur.execute("SET custom_filter.enabled=on")
            cur.execute("EXPLAIN (COSTS OFF) " + query.rstrip(";") + ";")
            explain_on = [r[0] for r in cur.fetchall()]
            notices_out.extend(conn.notices)
            conn.notices.clear()

            cur.execute(query)
            _ = cur.fetchone()
            notices_out.extend(conn.notices)
            conn.notices.clear()

        notices_text = "".join(notices_out)
        meta = parse_contract_metadata(notices_text)
        log_txt = []
        log_txt.append("QUERY:")
        log_txt.append(query)
        log_txt.append("")
        log_txt.append("EXPLAIN OFF:")
        log_txt.extend(explain_off)
        log_txt.append("")
        log_txt.append("EXPLAIN ON:")
        log_txt.extend(explain_on)
        log_txt.append("")
        log_txt.append("--- CONTRACT NOTICES ---")
        log_txt.append(notices_text.rstrip())
        write_log(contract_log, "\n".join(log_txt) + "\n")
        return meta, err
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        write_log(contract_log, f"QUERY:\n{query}\nERROR: {msg}\nNOTICES:\n{''.join(conn.notices)}\n")
        return {"targets": "", "closure": "", "scanned": "", "needed_files": "", "wrapped": ""}, msg
    finally:
        conn.close()


def run_ours(query: str, policy_path: Path, ours_log: Path) -> Tuple[Optional[int], str]:
    conn = connect("postgres")
    try:
        notices = ""
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute("SET client_min_messages=notice")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute("SET custom_filter.enabled=on")
            cur.execute("SET custom_filter.contract_mode=off")
            cur.execute("SET custom_filter.debug_mode='off'")
            cur.execute(query)
            row = cur.fetchone()
            count = row[0] if row else None
            notices = "".join(conn.notices)
            write_log(ours_log, f"QUERY:\n{query}\nCOUNT: {count}\n--- NOTICES ---\n{notices}\n")
            return count, ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        write_log(ours_log, f"QUERY:\n{query}\nERROR: {msg}\n--- NOTICES ---\n{''.join(conn.notices)}\n")
        return None, msg
    finally:
        conn.close()


def rebuild_artifacts(policy_path: Path):
    conn = connect("postgres")
    try:
        with conn.cursor() as cur:
            cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}'")
            cur.execute("TRUNCATE public.files")
            cur.execute(sql.SQL("SELECT build_base(%s)"), [str(policy_path)])
    finally:
        conn.close()


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    policy_lines = load_policy_lines(POLICY_SUPPORTED)
    queries = load_queries(QUERIES_SCALE)

    rows: List[RowResult] = []
    stop = False
    stop_reason = ""
    stop_case = None

    for K in Ks:
        if stop:
            break
        k_lines = policy_lines[:K]
        tmp_policy = ROOT / f"tmp_policy_k{K}.txt"
        tmp_policy.write_text("\n".join(k_lines) + "\n")
        rebuild_artifacts(tmp_policy)

        for qid, query in queries:
            if stop:
                break

            if qid == "7":
                # Optional long chain query.
                row = RowResult(K, qid, "SKIP", "", None, None, "rls", "", "", "", "", str(tmp_policy))
                rows.append(row)
                continue

            ours_log = LOG_DIR / f"K{K}_Q{qid}_ours.log"
            gt_log = LOG_DIR / f"K{K}_Q{qid}_gt.log"
            contract_log = LOG_DIR / f"K{K}_Q{qid}_contract.log"

            gt_count, gt_err = run_gt_rls(query, k_lines, gt_log)
            meta, contract_err = run_contract_and_explain(query, tmp_policy, contract_log)
            ours_count, ours_err = run_ours(query, tmp_policy, ours_log)

            status = "PASS"
            err_msg = ours_err or gt_err or contract_err
            err_type = classify_error(err_msg)

            if gt_err or contract_err or ours_err:
                status = "ERROR"
            elif ours_count != gt_count:
                status = "FAIL"

            row = RowResult(
                K=K,
                query_id=qid,
                status=status,
                error_type=err_type,
                ours_count=ours_count,
                gt_count=gt_count,
                gt_source="rls",
                targets=meta.get("targets", ""),
                closure=meta.get("closure", ""),
                scanned=meta.get("scanned", ""),
                wrapped=meta.get("wrapped", ""),
                policy_file=str(tmp_policy),
            )
            rows.append(row)

            if status == "FAIL":
                stop = True
                stop_reason = "mismatch"
                stop_case = row
                break
            if status == "ERROR" and err_type == "backend_crash":
                stop = True
                stop_reason = "backend_crash"
                stop_case = row
                break
            if status == "ERROR":
                stop = True
                stop_reason = "error"
                stop_case = row
                break

    with CSV_OUT.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "K", "query_id", "status", "error_type",
            "ours_count", "gt_count", "gt_source",
            "targets", "closure", "scanned", "wrapped", "policy_file"
        ])
        for r in rows:
            w.writerow([
                r.K, r.query_id, r.status, r.error_type,
                "" if r.ours_count is None else r.ours_count,
                "" if r.gt_count is None else r.gt_count,
                r.gt_source, r.targets, r.closure, r.scanned, r.wrapped, r.policy_file
            ])

    md = []
    md.append("# policy_scale_correctness")
    md.append("")
    md.append("| K | query_id | status | error_type | ours_count | gt_count | gt_source | targets | closure | scanned | wrapped |")
    md.append("|---:|---:|---|---|---:|---:|---|---|---|---|---|")
    for r in rows:
        ours_s = "" if r.ours_count is None else str(r.ours_count)
        gt_s = "" if r.gt_count is None else str(r.gt_count)
        md.append(f"| {r.K} | {r.query_id} | {r.status} | {r.error_type} | {ours_s} | {gt_s} | {r.gt_source} | {r.targets} | {r.closure} | {r.scanned} | {r.wrapped} |")

    if stop_case is not None:
        qmap = {qid: q for qid, q in queries}
        md.append("")
        md.append("## minimal_repro")
        md.append(f"- stop_reason: `{stop_reason}`")
        md.append(f"- K: `{stop_case.K}`")
        md.append(f"- query_id: `{stop_case.query_id}`")
        md.append(f"- policy_file: `{stop_case.policy_file}`")
        md.append(f"- query: `{qmap.get(stop_case.query_id, '')}`")
        md.append(f"- ours_log: `{LOG_DIR / f'K{stop_case.K}_Q{stop_case.query_id}_ours.log'}`")
        md.append(f"- gt_log: `{LOG_DIR / f'K{stop_case.K}_Q{stop_case.query_id}_gt.log'}`")
        md.append(f"- contract_log: `{LOG_DIR / f'K{stop_case.K}_Q{stop_case.query_id}_contract.log'}`")

    MD_OUT.write_text("\n".join(md) + "\n")

    print(f"csv={CSV_OUT}")
    print(f"md={MD_OUT}")
    print(f"rows={len(rows)} stop={stop} reason={stop_reason}")


if __name__ == "__main__":
    main()
