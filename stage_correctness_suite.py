#!/usr/bin/env python3
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psycopg2
from psycopg2 import sql

ROOT = Path("/home/ng_lab/z3")
DB = "tpch0_1"
CUSTOM_FILTER_SO = "/home/ng_lab/z3/custom_filter/custom_filter.so"
ARTIFACT_BUILDER_SO = "/home/ng_lab/z3/artifact_builder/artifact_builder.so"
LOG_DIR = ROOT / "correctness_suite_logs"
POLICY_DIR = ROOT / "correctness_suite_policies"
REPORT_MD = ROOT / "correctness_suite_report.md"

ROLE_CONFIG = {
    "postgres": {"user": "postgres", "password": "12345"},
    "rls_user": {"user": "rls_user", "password": "secret"},
}

TABLES = ["lineitem", "orders", "customer", "nation", "region", "part", "supplier", "partsupp"]
KEYWORDS = {"and", "or", "in", "like", "not", "is", "null", "between", "exists"}
CLAUSE_KEYWORDS = {"where", "join", "on", "group", "order", "limit", "left", "right", "inner", "outer", "full", "cross", "union", "having"}


@dataclass
class TestCase:
    test_id: str
    group_name: str
    query: str
    policies: List[str]
    gt_source: str  # rls, sql, none
    gt_sql: Optional[str] = None
    expect_error: bool = False
    expected_error_type: Optional[str] = None


@dataclass
class TestResult:
    test_id: str
    group_name: str
    status: str
    error_type: str
    ours_count: Optional[int]
    gt_source: str
    gt_count: Optional[int]
    ours_error: Optional[str]
    gt_error: Optional[str]
    policy_path: Path
    log_path: Path


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


def classify_error(msg: str) -> str:
    low = (msg or "").lower()
    if "server closed the connection unexpectedly" in low or "terminating connection due to administrator command" in low:
        return "backend_crash"
    if "unsupported like pattern" in low:
        return "unsupported_policy_shape"
    if "unsupported boolean structure" in low or ("unsupported" in low and "policy" in low):
        return "unsupported_policy_shape"
    if "indexonlyscan" in low or ("ctid" in low and "missing" in low):
        return "unsupported_scan_shape"
    if "missing artifact" in low:
        return "missing_artifact"
    if "ast mismatch" in low:
        return "ast_mismatch"
    if "statement timeout" in low or "canceling statement due to statement timeout" in low:
        return "timeout"
    if "segmentation fault" in low:
        return "backend_crash"
    return "engine_error"


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


def rewrite_policy_expr(target: str, expr: str, target_alias: Optional[str] = None) -> str:
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
        expr_sql = rewrite_policy_expr(target, expr.strip())
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


def build_artifacts(policy_path: Path):
    conn = connect("postgres")
    try:
        with conn.cursor() as cur:
            cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}'")
            cur.execute("TRUNCATE public.files")
            cur.execute(sql.SQL("SELECT build_base(%s)"), [str(policy_path)])
    finally:
        conn.close()


def run_explain(query: str, policy_path: Path, cf_enabled: bool) -> Tuple[List[str], str, str]:
    conn = connect("postgres")
    try:
        conn.notices.clear()
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute("SET client_min_messages=notice")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute("SET custom_filter.contract_mode=off")
            cur.execute("SET custom_filter.debug_mode='contract'")
            cur.execute(f"SET custom_filter.enabled={'on' if cf_enabled else 'off'}")
            cur.execute("EXPLAIN (COSTS OFF) " + query.rstrip(";") + ";")
            plan = [r[0] for r in cur.fetchall()]
        return plan, "".join(conn.notices), ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        return [], "".join(conn.notices), msg
    finally:
        conn.close()


def run_ours(query: str, policy_path: Path) -> Tuple[Optional[int], str, str]:
    conn = connect("postgres")
    try:
        conn.notices.clear()
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute("SET client_min_messages=notice")
            cur.execute(f"LOAD '{CUSTOM_FILTER_SO}'")
            cur.execute("SET custom_filter.enabled=on")
            cur.execute("SET custom_filter.contract_mode=off")
            cur.execute("SET custom_filter.debug_mode='contract'")
            cur.execute(sql.SQL("SET custom_filter.policy_path = %s"), [str(policy_path)])
            cur.execute(query)
            row = cur.fetchone()
            return (row[0] if row else None), "".join(conn.notices), ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        return None, "".join(conn.notices), msg
    finally:
        conn.close()


def run_gt_rls(query: str, policy_lines: List[str]) -> Tuple[Optional[int], str]:
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
            return (row[0] if row else None), ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        return None, msg
    finally:
        conn.close()


def run_gt_sql(gt_sql: str) -> Tuple[Optional[int], str]:
    conn = connect("postgres")
    try:
        with conn.cursor() as cur:
            cur.execute("SET max_parallel_workers_per_gather=0")
            cur.execute(gt_sql)
            row = cur.fetchone()
            return (row[0] if row else None), ""
    except Exception as e:
        msg = (getattr(e, "pgerror", None) or str(e)).strip().replace("\n", " ")
        return None, msg
    finally:
        conn.close()


def write_raw_log(path: Path, tc: TestCase, plan_off: List[str], plan_off_notices: str, plan_off_err: str,
                  plan_on: List[str], plan_on_notices: str, plan_on_err: str,
                  ours_count: Optional[int], ours_notices: str, ours_err: str,
                  gt_count: Optional[int], gt_err: str):
    lines: List[str] = []
    lines.append(f"TEST: {tc.test_id} ({tc.group_name})")
    lines.append("QUERY:")
    lines.append(tc.query.strip())
    lines.append("")
    lines.append("ENABLED POLICIES:")
    for p in tc.policies:
        lines.append(p)
    lines.append("")
    lines.append("EXPLAIN OFF (custom_filter.enabled=off):")
    if plan_off_err:
        lines.append(f"ERROR: {plan_off_err}")
    else:
        lines.extend(plan_off)
    if plan_off_notices:
        lines.append("--- OFF notices ---")
        lines.append(plan_off_notices.rstrip())
    lines.append("")
    lines.append("EXPLAIN ON (custom_filter.enabled=on):")
    if plan_on_err:
        lines.append(f"ERROR: {plan_on_err}")
    else:
        lines.extend(plan_on)
    if plan_on_notices:
        lines.append("--- ON notices ---")
        lines.append(plan_on_notices.rstrip())
    lines.append("")
    lines.append("OURS EXECUTION:")
    if ours_err:
        lines.append(f"ERROR: {ours_err}")
    else:
        lines.append(f"COUNT: {ours_count}")
    if ours_notices:
        lines.append("--- Ours notices ---")
        lines.append(ours_notices.rstrip())
    lines.append("")
    lines.append(f"GROUND TRUTH SOURCE: {tc.gt_source}")
    if gt_err:
        lines.append(f"GT ERROR: {gt_err}")
    else:
        lines.append(f"GT COUNT: {gt_count}")
    path.write_text("\n".join(lines) + "\n")


def build_tests() -> List[TestCase]:
    return [
        TestCase(
            test_id="A",
            group_name="single-table const AND/OR",
            query="SELECT COUNT(*) FROM customer;",
            policies=[
                "customer : (customer.c_acctbal > 0) AND ((customer.c_mktsegment = 'FURNITURE') OR (customer.c_mktsegment = 'HOUSEHOLD')) AND (customer.c_nationkey < 10)",
                "customer : (customer.c_acctbal < 9000) AND ((customer.c_mktsegment = 'MACHINERY') OR (customer.c_mktsegment = 'HOUSEHOLD'))",
            ],
            gt_source="rls",
        ),
        TestCase(
            test_id="B",
            group_name="join policy single target with closure",
            query="SELECT COUNT(*) FROM orders o JOIN customer c ON o.o_custkey=c.c_custkey;",
            policies=[
                "orders : orders.o_custkey = customer.c_custkey AND (customer.c_mktsegment = 'AUTOMOBILE' OR customer.c_mktsegment = 'HOUSEHOLD')",
            ],
            gt_source="rls",
        ),
        TestCase(
            test_id="C",
            group_name="multi-target query two targets",
            query="SELECT COUNT(*) FROM lineitem l JOIN orders o ON l.l_orderkey=o.o_orderkey;",
            policies=[
                "orders : orders.o_custkey = customer.c_custkey AND (customer.c_mktsegment = 'AUTOMOBILE' OR customer.c_mktsegment = 'HOUSEHOLD')",
                "lineitem : lineitem.l_shipmode IN ('MAIL','SHIP')",
            ],
            gt_source="rls",
        ),
        TestCase(
            test_id="D",
            group_name="multi-join-class chain AND-only",
            query="SELECT COUNT(*) FROM orders;",
            policies=[
                "orders : orders.o_custkey = customer.c_custkey AND customer.c_nationkey = nation.n_nationkey AND nation.n_regionkey = region.r_regionkey AND region.r_name IN ('EUROPE','ASIA')",
            ],
            gt_source="sql",
            gt_sql="""
SELECT COUNT(*)
FROM orders o
WHERE EXISTS (
  SELECT 1
  FROM customer c
  JOIN nation n ON c.c_nationkey=n.n_nationkey
  JOIN region r ON n.n_regionkey=r.r_regionkey
  WHERE c.c_custkey=o.o_custkey
    AND r.r_name IN ('EUROPE','ASIA')
);
""",
        ),
        TestCase(
            test_id="E",
            group_name="OR across tables",
            query="SELECT COUNT(*) FROM orders;",
            policies=[
                "orders : orders.o_custkey = customer.c_custkey AND customer.c_nationkey = nation.n_nationkey AND nation.n_regionkey = region.r_regionkey AND lineitem.l_orderkey = orders.o_orderkey AND ((region.r_name IN ('EUROPE','ASIA') AND orders.o_orderstatus IN ('O','F')) OR (lineitem.l_shipmode IN ('MAIL','SHIP') AND orders.o_orderpriority IN ('1-URGENT','2-HIGH')))",
            ],
            gt_source="sql",
            gt_sql="""
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
        ),
        TestCase(
            test_id="F",
            group_name="fail-closed unsupported operator",
            query="SELECT COUNT(*) FROM customer;",
            policies=[
                "customer : customer.c_phone LIKE '%-%'",
            ],
            gt_source="none",
            expect_error=True,
            expected_error_type="unsupported_policy_shape",
        ),
    ]


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    tests = build_tests()
    results: List[TestResult] = []
    crash_detected = False

    for tc in tests:
        policy_path = POLICY_DIR / f"policy_{tc.test_id}.txt"
        policy_path.write_text("\n".join(tc.policies) + "\n")
        log_path = LOG_DIR / f"test_{tc.test_id}.log"

        ours_count: Optional[int] = None
        gt_count: Optional[int] = None
        ours_err = ""
        gt_err = ""

        try:
            build_artifacts(policy_path)
        except Exception as e:
            ours_err = f"artifact_builder_error: {(getattr(e, 'pgerror', None) or str(e)).strip().replace(chr(10), ' ')}"
            plan_off, plan_off_notices, plan_off_err = [], "", ""
            plan_on, plan_on_notices, plan_on_err = [], "", ""
            write_raw_log(log_path, tc, plan_off, plan_off_notices, plan_off_err, plan_on, plan_on_notices, plan_on_err, ours_count, "", ours_err, gt_count, gt_err)
            results.append(TestResult(tc.test_id, tc.group_name, "ERROR", "missing_artifact", None, tc.gt_source, None, ours_err, None, policy_path, log_path))
            continue

        plan_off, plan_off_notices, plan_off_err = run_explain(tc.query, policy_path, cf_enabled=False)
        plan_on, plan_on_notices, plan_on_err = run_explain(tc.query, policy_path, cf_enabled=True)

        ours_count, ours_notices, ours_err = run_ours(tc.query, policy_path)

        if tc.gt_source == "rls":
            gt_count, gt_err = run_gt_rls(tc.query, tc.policies)
        elif tc.gt_source == "sql":
            gt_count, gt_err = run_gt_sql(tc.gt_sql or "")
        else:
            gt_count, gt_err = None, ""

        write_raw_log(log_path, tc, plan_off, plan_off_notices, plan_off_err, plan_on, plan_on_notices, plan_on_err, ours_count, ours_notices, ours_err, gt_count, gt_err)

        ours_err_type = classify_error(ours_err) if ours_err else ""
        if ours_err_type == "backend_crash":
            crash_detected = True

        status = "FAIL"
        if tc.expect_error:
            if ours_err:
                if tc.expected_error_type and ours_err_type == tc.expected_error_type:
                    status = "PASS"
                elif not tc.expected_error_type:
                    status = "PASS"
                else:
                    status = "ERROR"
            else:
                status = "FAIL"
        else:
            if ours_err:
                status = "ERROR"
            elif gt_err:
                status = "ERROR"
            elif ours_count == gt_count:
                status = "PASS"
            else:
                status = "FAIL"

        results.append(
            TestResult(
                test_id=tc.test_id,
                group_name=tc.group_name,
                status=status,
                error_type=(ours_err_type if ours_err else ("gt_error" if gt_err else "")),
                ours_count=ours_count,
                gt_source=tc.gt_source,
                gt_count=gt_count,
                ours_error=(ours_err if ours_err else None),
                gt_error=(gt_err if gt_err else None),
                policy_path=policy_path,
                log_path=log_path,
            )
        )

        if crash_detected:
            break

    lines: List[str] = []
    lines.append("# correctness_suite_report")
    lines.append("")
    lines.append("| test_id | group | status | error_type | ours_count | gt_source | gt_count | log |")
    lines.append("|---|---|---|---|---:|---|---:|---|")
    for r in results:
        ours_s = "" if r.ours_count is None else str(r.ours_count)
        gt_s = "" if r.gt_count is None else str(r.gt_count)
        lines.append(f"| {r.test_id} | {r.group_name} | {r.status} | {r.error_type} | {ours_s} | {r.gt_source} | {gt_s} | `{r.log_path}` |")

    failing = [r for r in results if r.status != "PASS"]
    if failing:
        lines.append("")
        lines.append("## failing_cases")
        for r in failing:
            lines.append("")
            lines.append(f"### test_{r.test_id}")
            lines.append(f"- policy_file: `{r.policy_path}`")
            lines.append(f"- raw_log: `{r.log_path}`")
            if r.ours_error:
                lines.append(f"- ours_error: `{r.ours_error}`")
            if r.gt_error:
                lines.append(f"- gt_error: `{r.gt_error}`")
            excerpt = []
            try:
                raw = r.log_path.read_text().splitlines()
                for ln in raw:
                    if ("policy_targets" in ln or "closure_tables" in ln or "scanned_tables" in ln or
                        "needed_files" in ln or "wrap rel=" in ln or ln.startswith("ERROR:")):
                        excerpt.append(ln)
                excerpt = excerpt[:40]
            except Exception:
                excerpt = []
            if excerpt:
                lines.append("- log_excerpt:")
                lines.append("```text")
                lines.extend(excerpt)
                lines.append("```")

    if crash_detected:
        lines.append("")
        lines.append("## crash_notice")
        lines.append("A backend crash signature was detected (`backend_crash`). Stopped suite execution immediately.")

    REPORT_MD.write_text("\n".join(lines) + "\n")

    print(f"report: {REPORT_MD}")
    for r in results:
        print(f"{r.test_id}\t{r.status}\t{r.error_type}\tours={r.ours_count}\tgt={r.gt_count}\tlog={r.log_path}")

    return 1 if crash_detected else 0


if __name__ == "__main__":
    sys.exit(main())
