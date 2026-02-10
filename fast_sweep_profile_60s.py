#!/usr/bin/env python3
import argparse
import csv
import random
import re
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import psycopg2
from psycopg2 import sql

# Use the script directory as repo root so the harness is portable across machines.
ROOT = Path(__file__).resolve().parent
DEFAULT_DB = "tpch0_1"
DEFAULT_POLICY = ROOT / "policy.txt"
DEFAULT_QUERIES = ROOT / "queries.txt"
DEFAULT_POLICIES_ENABLED = ROOT / "policies_enabled.txt"
DEFAULT_TIMES_CSV = ROOT / "logs" / "policy_scaling_times.csv"
DEFAULT_PROFILE_CSV = ROOT / "logs" / "policy_scaling_profile.csv"
DEFAULT_CORRECTNESS_CSV = ROOT / "logs" / "policy_scaling_correctness.csv"
DEFAULT_SUMMARY_CSV = ROOT / "logs" / "policy_scaling_summary.csv"
DEFAULT_PLOTS_DIR = ROOT / "logs" / "policy_scaling_plots"

CUSTOM_FILTER_SO = str(ROOT / "custom_filter" / "custom_filter.so")
ARTIFACT_BUILDER_SO = str(ROOT / "artifact_builder" / "artifact_builder.so")

DEFAULT_KS = [1, 5, 10, 11]
DEFAULT_POLICY_POOL = "1-5,10-15"
CROSS_TABLE_QUERY_IDS = {"3", "5", "7", "8", "10", "12", "13", "18", "22"}

ROLE_CONFIG = {
    "postgres": {"user": "postgres", "password": "12345"},
    "rls_user": {"user": "rls_user", "password": "secret"},
}

TABLES = ["lineitem", "orders", "customer", "nation", "region", "part", "supplier", "partsupp"]
KEYWORDS = {
    "and",
    "or",
    "not",
    "in",
    "like",
    "is",
    "null",
    "between",
    "exists",
    "select",
    "from",
    "where",
    "as",
    "on",
    "join",
    "left",
    "right",
    "inner",
    "outer",
    "case",
    "when",
    "then",
    "else",
    "end",
    "extract",
    "interval",
    "date",
    "substring",
    "for",
    "avg",
    "sum",
    "count",
    "min",
    "max",
    "having",
    "group",
    "order",
    "by",
    "desc",
    "asc",
    "distinct",
    "true",
    "false",
}

KNOWN_OLD_INDEXES = [
    "idx_orders_o_custkey",
    "idx_customer_c_custkey",
    "idx_lineitem_l_orderkey",
    "idx_customer_c_custkey_mktsegment",
]

TIMES_COLUMNS = [
    "row_type",
    "db",
    "K",
    "policy_ids",
    "baseline",
    "query_id",
    "setup_ms",
    "disk_overhead_bytes",
    "cold_ms",
    "cold_peak_rss_kb",
    "hot1_ms",
    "hot1_peak_rss_kb",
    "hot2_ms",
    "hot2_peak_rss_kb",
    "hot3_ms",
    "hot3_peak_rss_kb",
    "hot4_ms",
    "hot4_peak_rss_kb",
    "hot5_ms",
    "hot5_peak_rss_kb",
    "hot_avg_ms",
    "hot_avg_peak_rss_kb",
    "status",
    "error_type",
    "error_msg",
]

CORRECTNESS_COLUMNS = ["db", "K", "query_id", "correctness", "ours_count", "rls_count", "reason"]

SUMMARY_COLUMNS = [
    "db",
    "db_scale",
    "K",
    "policy_ids",
    "median_hot_ours_ms",
    "median_hot_rls_ms",
    "speedup_ratio",
    "cross_median_hot_ours_ms",
    "cross_median_hot_rls_ms",
    "cross_speedup_ratio",
    "median_hot_peak_rss_ours_kb",
    "median_hot_peak_rss_rls_kb",
    "disk_ours_bytes",
    "disk_rls_bytes",
]

PROFILE_COLUMNS = [
    "db",
    "K",
    "policy_ids",
    "baseline",
    "query_id",
    "status",
    "error_type",
    "error_msg",
    "eval_ms",
    "artifact_load_ms",
    "policy_total_ms",
    "ctid_map_ms",
    "filter_ms",
    "bytes_artifacts_loaded",
    "bytes_allow",
    "bytes_ctid",
    "bytes_blk_index",
    "rows_seen",
    "rows_passed",
    "ctid_misses",
    "peak_rss_kb_end",
    "policy_profile_lines",
    "has_new_layer_fields",
    "profile_line",
]


class HarnessError(Exception):
    pass


@dataclass(frozen=True)
class IndexSpec:
    table: str
    column: str
    pattern_ops: bool


@dataclass
class RunMetrics:
    elapsed_ms: float
    peak_rss_kb: int
    status: str
    error_type: str
    error_msg: str


def make_error_metrics(error_type: str, error_msg: str, elapsed_ms: float = 0.0) -> RunMetrics:
    return RunMetrics(
        elapsed_ms=float(elapsed_ms),
        peak_rss_kb=0,
        status="error",
        error_type=error_type or "error",
        error_msg=(error_msg or "")[:240],
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stage S2.5 policy-scaling stress harness")
    p.add_argument("--run", action="store_true", help="Run experiment")
    p.add_argument("--smoke-check", action="store_true", help="Run smoke check (K=11 pool-full, q3/q13, hot=2)")
    p.add_argument("--smoke-only", action="store_true", help="Run smoke check only, then exit")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--dbs", nargs="*", default=None, help="Optional list of DBs to run back-to-back")
    p.add_argument("--ks", nargs="*", type=int, default=DEFAULT_KS)
    p.add_argument("--policy-pool", default=DEFAULT_POLICY_POOL, help="Policy ID pool, e.g. 1-5,10-15")
    p.add_argument("--hot-runs", type=int, default=5)
    p.add_argument("--statement-timeout", default="0", help="statement_timeout (e.g. 0, 300000, 30min, 1800s)")
    p.add_argument("--custom-filter-so", default=CUSTOM_FILTER_SO, help="Path to custom_filter.so (backend must be able to read)")
    p.add_argument(
        "--artifact-builder-so", default=ARTIFACT_BUILDER_SO, help="Path to artifact_builder.so (backend must be able to read)"
    )
    p.add_argument("--queries", default=str(DEFAULT_QUERIES))
    p.add_argument("--policy", default=str(DEFAULT_POLICY))
    p.add_argument("--policies-enabled", default=str(DEFAULT_POLICIES_ENABLED))
    p.add_argument("--times-csv", default=str(DEFAULT_TIMES_CSV))
    p.add_argument("--profile-csv", default=str(DEFAULT_PROFILE_CSV))
    p.add_argument("--correctness-csv", default=str(DEFAULT_CORRECTNESS_CSV))
    p.add_argument("--summary-csv", default=str(DEFAULT_SUMMARY_CSV))
    p.add_argument("--plots-dir", default=str(DEFAULT_PLOTS_DIR))
    p.add_argument("--seed", type=int, default=20260209)
    p.add_argument("--query-ids", nargs="*", default=None)
    p.add_argument("--skip-query-ids", nargs="*", default=None)
    p.add_argument("--correctness-sample", type=int, default=3, help="Queries sampled per K for COUNT correctness (0=all)")
    return p.parse_args()


def connect(db: str, role: str):
    cfg = ROLE_CONFIG[role]
    last_exc: Optional[Exception] = None
    for attempt in range(30):
        try:
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                dbname=db,
                user=cfg["user"],
                password=cfg["password"],
                connect_timeout=5,
            )
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as exc:
            msg = (getattr(exc, "pgerror", None) or str(exc)).lower()
            last_exc = exc
            retryable = (
                "recovery mode" in msg
                or "starting up" in msg
                or "connection refused" in msg
                or "terminating connection" in msg
            )
            if retryable and attempt < 29:
                time.sleep(2.0)
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise HarnessError(f"failed to connect to db={db} role={role}")


def apply_timing_session_settings(cur, statement_timeout_ms: int) -> None:
    cur.execute("SET max_parallel_workers_per_gather = 0;")
    cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])


def classify_error(exc: Exception, msg: str) -> Tuple[str, str]:
    low = (msg or "").lower()
    if "statement timeout" in low:
        return "timeout", msg
    if "unsupported" in low:
        return "unsupported", msg
    if isinstance(exc, psycopg2.Error):
        return "db_error", msg
    return "error", msg


def read_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        return 0
    return 0


def execute_with_rss(cur, sql_text: str) -> RunMetrics:
    t0 = time.perf_counter()
    try:
        cur.execute("SELECT pg_backend_pid()")
        pid = int(cur.fetchone()[0])
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        etype, emsg = classify_error(exc, msg)
        return make_error_metrics(etype, emsg, elapsed_ms=(time.perf_counter() - t0) * 1000.0)

    stop_evt = threading.Event()
    peak_rss_kb = 0

    def sampler() -> None:
        nonlocal peak_rss_kb
        while not stop_evt.is_set():
            rss = read_rss_kb(pid)
            if rss > peak_rss_kb:
                peak_rss_kb = rss
            time.sleep(0.03)

    t = threading.Thread(target=sampler, daemon=True)
    t.start()

    status = "ok"
    error_type = ""
    error_msg = ""
    try:
        cur.execute(sql_text)
        if cur.description is not None:
            cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        status = "error"
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        error_type, error_msg = classify_error(exc, msg)
    finally:
        stop_evt.set()
        t.join(timeout=1)

    return RunMetrics(
        elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        peak_rss_kb=int(peak_rss_kb),
        status=status,
        error_type=error_type,
        error_msg=error_msg,
    )


def execute_with_rss_and_notices(cur, sql_text: str) -> Tuple[RunMetrics, List[str]]:
    conn = cur.connection
    del conn.notices[:]
    metrics = execute_with_rss(cur, sql_text)
    notices = [n.replace("\n", " ").strip() for n in conn.notices]
    del conn.notices[:]
    return metrics, notices


def normalize_query_for_postgres(q: str) -> str:
    out = q
    out = re.sub(
        r"interval\s*'([0-9]+)'\s+day\s*\(\s*[0-9]+\s*\)",
        r"interval '\\1 day'",
        out,
        flags=re.IGNORECASE,
    )
    return out


def load_queries(path: Path) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s:
            continue
        m = re.match(r"^\s*(\d+)\s*[:.]\s*(.*)$", s)
        if m:
            qid = m.group(1)
            sql_text = m.group(2).strip()
        else:
            qid = str(len(rows) + 1)
            sql_text = s
        sql_text = normalize_query_for_postgres(sql_text)
        if not sql_text.endswith(";"):
            sql_text += ";"
        rows.append((qid, sql_text))
    if not rows:
        raise HarnessError(f"No queries found in {path}")
    return rows


def load_policy_lines(path: Path) -> List[str]:
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.rstrip("\n")
        if not s.strip():
            continue
        if s.strip().startswith("#"):
            continue
        out.append(s)
    if len(out) < 20:
        raise HarnessError(f"Expected at least 20 policies in {path}, found {len(out)}")
    return out


def parse_policy_entry(policy_line: str) -> Tuple[str, str]:
    line = re.sub(r"^\s*\d+\s*[:.]\s*", "", policy_line.strip())
    if ":" not in line:
        raise HarnessError(f"Policy line missing ':' separator: {policy_line}")
    target, expr = line.split(":", 1)
    target = target.strip().lower()
    expr = expr.strip()
    if not target or not expr:
        raise HarnessError(f"Malformed policy line: {policy_line}")
    return target, expr


def parse_policy_pool(pool_spec: str, max_policy_id: int) -> List[int]:
    ids: List[int] = []
    seen = set()
    parts = [p.strip() for p in pool_spec.split(",") if p.strip()]
    if not parts:
        raise HarnessError("policy pool cannot be empty")
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                start = int(a.strip())
                end = int(b.strip())
            except ValueError as exc:
                raise HarnessError(f"invalid pool range token: {part}") from exc
            step = 1 if end >= start else -1
            rng = range(start, end + step, step)
            for pid in rng:
                if pid < 1 or pid > max_policy_id:
                    raise HarnessError(f"policy id {pid} out of range 1..{max_policy_id}")
                if pid not in seen:
                    ids.append(pid)
                    seen.add(pid)
        else:
            try:
                pid = int(part)
            except ValueError as exc:
                raise HarnessError(f"invalid pool token: {part}") from exc
            if pid < 1 or pid > max_policy_id:
                raise HarnessError(f"policy id {pid} out of range 1..{max_policy_id}")
            if pid not in seen:
                ids.append(pid)
                seen.add(pid)
    return ids


def parse_timeout_ms(raw: str) -> int:
    s = str(raw).strip().lower()
    if not s:
        raise HarnessError("statement-timeout cannot be empty")
    m = re.match(r"^(\d+)\s*([a-z]+)?$", s)
    if not m:
        raise HarnessError(f"invalid statement-timeout: {raw}")
    n = int(m.group(1))
    unit = (m.group(2) or "ms").lower()
    if unit in ("ms", "msec", "millisecond", "milliseconds"):
        return n
    if unit in ("s", "sec", "secs", "second", "seconds"):
        return n * 1000
    if unit in ("m", "min", "mins", "minute", "minutes"):
        return n * 60 * 1000
    if unit in ("h", "hr", "hrs", "hour", "hours"):
        return n * 60 * 60 * 1000
    raise HarnessError(f"unsupported statement-timeout unit: {unit}")


def db_scale_from_name(db: str) -> str:
    d = db.strip().lower()
    if d == "tpch":
        return "1"
    if d.startswith("tpch"):
        tail = d[4:]
        if tail.startswith("_"):
            tail = tail[1:]
        if tail:
            tail = tail.replace("_", ".")
            try:
                v = float(tail)
                if v.is_integer():
                    return str(int(v))
                return str(v)
            except Exception:
                pass
    return ""


def select_enabled_policies(policy_lines: Sequence[str], pool_ids: Sequence[int], k: int) -> Tuple[List[int], List[str]]:
    if k < 1:
        raise HarnessError("K must be >= 1")
    if k > len(pool_ids):
        raise HarnessError(f"K={k} exceeds policy pool size={len(pool_ids)}")
    enabled_ids = list(pool_ids[:k])
    enabled_set = set(enabled_ids)
    enabled_lines: List[str] = []
    for pid, line in enumerate(policy_lines, start=1):
        if pid in enabled_set:
            enabled_lines.append(line)
    if len(enabled_lines) != len(enabled_ids):
        raise HarnessError(
            f"enabled policy resolution mismatch: requested {enabled_ids}, got {len(enabled_lines)} lines"
        )
    return enabled_ids, enabled_lines


def write_enabled_policy_file(enabled_policy_lines: Sequence[str], enabled_path: Path) -> None:
    enabled_path.write_text("\n".join(enabled_policy_lines) + "\n", encoding="utf-8")


def _strip_string_literals(expr: str) -> str:
    return re.sub(r"'(?:''|[^'])*'", " ", expr)


def infer_index_specs(enabled_policy_lines: Sequence[str]) -> List[IndexSpec]:
    specs: Dict[Tuple[str, str], IndexSpec] = {}
    like_prefix_cols: Dict[Tuple[str, str], bool] = {}

    for line in enabled_policy_lines:
        target, expr = parse_policy_entry(line)
        expr_work = expr

        for tbl, col in re.findall(r"\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b", expr_work, flags=re.IGNORECASE):
            key = (tbl.lower(), col.lower())
            specs[key] = IndexSpec(table=key[0], column=key[1], pattern_ops=False)

        for tbl, col, pat in re.findall(
            r"\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\s+like\s+'([^']*)'",
            expr_work,
            flags=re.IGNORECASE,
        ):
            key = (tbl.lower(), col.lower())
            if pat.strip().endswith("%") and not pat.strip().startswith("%"):
                like_prefix_cols[key] = True

        for col, pat in re.findall(
            r"(?<!\.)\b([a-z_][a-z0-9_]*)\s+like\s+'([^']*)'",
            expr_work,
            flags=re.IGNORECASE,
        ):
            c = col.lower()
            if c in KEYWORDS:
                continue
            key = (target, c)
            specs[key] = IndexSpec(table=target, column=c, pattern_ops=False)
            if pat.strip().endswith("%") and not pat.strip().startswith("%"):
                like_prefix_cols[key] = True

        stripped = _strip_string_literals(expr_work)
        stripped = re.sub(r"\b[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\b", " ", stripped, flags=re.IGNORECASE)
        for tok in re.findall(r"\b[a-z_][a-z0-9_]*\b", stripped, flags=re.IGNORECASE):
            t = tok.lower()
            if t in KEYWORDS or t == target or t.isdigit():
                continue
            specs[(target, t)] = IndexSpec(table=target, column=t, pattern_ops=False)

    for key in like_prefix_cols:
        if key in specs:
            s = specs[key]
            specs[key] = IndexSpec(table=s.table, column=s.column, pattern_ops=True)

    out = sorted(specs.values(), key=lambda x: (x.table, x.column, 0 if x.pattern_ops else 1))
    return out


def rewrite_policy_expr_for_rls(target: str, expr: str) -> str:
    tokens: List[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "'":
            j = i + 1
            while j < len(expr):
                if expr[j] == "'" and j + 1 < len(expr) and expr[j + 1] == "'":
                    j += 2
                    continue
                if expr[j] == "'":
                    j += 1
                    break
                j += 1
            tokens.append(expr[i:j])
            i = j
            continue
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < len(expr) and (expr[j].isalnum() or expr[j] in "_."):
                j += 1
            tok = expr[i:j]
            low = tok.lower()
            if "." in tok or low in KEYWORDS:
                tokens.append(tok)
            else:
                tokens.append(f"{target}.{low}")
            i = j
            continue
        tokens.append(ch)
        i += 1

    expr2 = "".join(tokens)
    refs = sorted(set(re.findall(r"\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b", expr2, flags=re.IGNORECASE)))
    other_tables = sorted({t.lower() for t, _ in refs if t.lower() != target})
    if other_tables:
        return f"EXISTS (SELECT 1 FROM {', '.join(other_tables)} WHERE {expr2})"
    return expr2


def apply_rls_policies_for_k(db: str, enabled_policy_lines: Sequence[str]) -> None:
    by_target: Dict[str, List[str]] = {}
    for line in enabled_policy_lines:
        target, expr = parse_policy_entry(line)
        pred = rewrite_policy_expr_for_rls(target, expr)
        by_target.setdefault(target, []).append(f"({pred})")

    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            cur.execute("GRANT USAGE, CREATE ON SCHEMA public TO rls_user;")
            cur.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO rls_user;")
            cur.execute("SET LOCAL search_path TO public, pg_catalog")
            for t in TABLES:
                cur.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
                cur.execute(sql.SQL("DROP POLICY IF EXISTS cf_all ON {};").format(sql.Identifier(t)))
            for tgt in sorted(by_target.keys()):
                combined = " AND ".join(by_target[tgt])
                cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY;").format(sql.Identifier(tgt)))
                cur.execute(
                    sql.SQL("CREATE POLICY cf_all ON {} FOR SELECT TO rls_user USING ({});").format(
                        sql.Identifier(tgt), sql.SQL(combined)
                    )
                )
    finally:
        conn.close()


def drop_harness_indexes(cur) -> None:
    cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname LIKE 'cf_rls_k%';")
    names = [r[0] for r in cur.fetchall()]
    for n in names:
        cur.execute(sql.SQL("DROP INDEX IF EXISTS public.{};").format(sql.Identifier(n)))
    for n in KNOWN_OLD_INDEXES:
        cur.execute(sql.SQL("DROP INDEX IF EXISTS public.{};").format(sql.Identifier(n)))


def create_rls_indexes_for_k(
    db: str,
    k: int,
    enabled_policy_lines: Sequence[str],
    statement_timeout_ms: int,
) -> Tuple[float, int, List[str]]:
    specs = infer_index_specs(enabled_policy_lines)
    spec_log = [f"{s.table}.{s.column}{':text_pattern_ops' if s.pattern_ops else ''}" for s in specs]
    print(f"[index_infer] K={k} specs={spec_log}")

    created: List[str] = []
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            apply_timing_session_settings(cur, statement_timeout_ms)
            drop_harness_indexes(cur)
            t0 = time.perf_counter()
            for i, spec in enumerate(specs, start=1):
                idx_name = f"cf_rls_k{k}_{spec.table}_{spec.column}_{i}"
                try:
                    if spec.pattern_ops:
                        cur.execute(
                            sql.SQL("CREATE INDEX {} ON {} ({} text_pattern_ops);").format(
                                sql.Identifier(idx_name),
                                sql.Identifier(spec.table),
                                sql.Identifier(spec.column),
                            )
                        )
                    else:
                        cur.execute(
                            sql.SQL("CREATE INDEX {} ON {} ({});").format(
                                sql.Identifier(idx_name),
                                sql.Identifier(spec.table),
                                sql.Identifier(spec.column),
                            )
                        )
                except psycopg2.Error:
                    if spec.pattern_ops:
                        cur.execute(
                            sql.SQL("CREATE INDEX {} ON {} ({});").format(
                                sql.Identifier(idx_name),
                                sql.Identifier(spec.table),
                                sql.Identifier(spec.column),
                            )
                        )
                    else:
                        raise
                created.append(idx_name)
            index_build_ms = (time.perf_counter() - t0) * 1000.0

            disk_bytes = 0
            for n in created:
                cur.execute("SELECT COALESCE(pg_total_relation_size(to_regclass(%s)), 0);", [f"public.{n}"])
                disk_bytes += int(cur.fetchone()[0] or 0)
    finally:
        conn.close()

    print(f"[setup_rls] K={k} setup_ms={index_build_ms:.3f} disk={disk_bytes} indexes={created}")
    return index_build_ms, disk_bytes, created


def ensure_build_base_function(cur) -> None:
    cur.execute(f"LOAD '{ARTIFACT_BUILDER_SO}';")
    cur.execute(
        "SELECT p.oid, pg_get_function_result(p.oid) "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='public' AND p.proname='build_base' "
        "AND pg_get_function_identity_arguments(p.oid)='text';"
    )
    row = cur.fetchone()
    if row is None:
        cur.execute(
            f"CREATE FUNCTION public.build_base(text) RETURNS void "
            f"AS '{ARTIFACT_BUILDER_SO}', 'build_base' LANGUAGE C STRICT;"
        )
        return

    ret = str(row[1]).lower().strip()
    if ret != "void":
        cur.execute("DROP FUNCTION public.build_base(text);")
        cur.execute(
            f"CREATE FUNCTION public.build_base(text) RETURNS void "
            f"AS '{ARTIFACT_BUILDER_SO}', 'build_base' LANGUAGE C STRICT;"
        )


def setup_ours_for_k(db: str, k: int, enabled_path: Path, statement_timeout_ms: int) -> Tuple[float, int]:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            apply_timing_session_settings(cur, statement_timeout_ms)
            cur.execute("CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);")
            ensure_build_base_function(cur)
            cur.execute("TRUNCATE public.files;")
            t0 = time.perf_counter()
            cur.execute("SELECT public.build_base(%s);", [str(enabled_path)])
            setup_ms = (time.perf_counter() - t0) * 1000.0
            # Artifact payload bytes for current build (table is truncated right before build).
            cur.execute("SELECT COALESCE(SUM(octet_length(file)), 0) FROM public.files;")
            disk_bytes = int(cur.fetchone()[0] or 0)
    finally:
        conn.close()
    print(f"[setup_ours] K={k} setup_ms={setup_ms:.3f} disk={disk_bytes}")
    return setup_ms, disk_bytes


def set_session_for_baseline(
    cur,
    baseline: str,
    enabled_path: Path,
    statement_timeout_ms: int,
    ours_debug_mode: str = "off",
) -> None:
    apply_timing_session_settings(cur, statement_timeout_ms)
    if baseline == "ours":
        cur.execute(f"LOAD '{CUSTOM_FILTER_SO}';")
        cur.execute("SET custom_filter.enabled = on;")
        cur.execute("SET custom_filter.contract_mode = off;")
        cur.execute("SET custom_filter.debug_mode = %s;", [ours_debug_mode])
        cur.execute("SET enable_tidscan = off;")
        cur.execute("SET enable_indexonlyscan = off;")
        cur.execute(sql.SQL("SET custom_filter.policy_path = %s;"), [str(enabled_path)])
    elif baseline == "rls_with_index":
        cur.execute("SET custom_filter.enabled = off;")
        cur.execute("SET enable_indexonlyscan = off;")
    else:
        raise HarnessError(f"Unknown baseline: {baseline}")


def run_query_series(
    db: str,
    baseline: str,
    query_sql: str,
    hot_runs: int,
    enabled_path: Path,
    statement_timeout_ms: int,
) -> Tuple[RunMetrics, List[RunMetrics]]:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = None
    try:
        conn = connect(db, role)
        with conn.cursor() as cur:
            set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            cold = execute_with_rss(cur, query_sql)
            hots: List[RunMetrics] = []
            for _ in range(hot_runs):
                try:
                    hots.append(execute_with_rss(cur, query_sql))
                except Exception as exc:  # noqa: BLE001
                    msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
                    etype, emsg = classify_error(exc, msg)
                    hots.append(make_error_metrics(etype, emsg))
            return cold, hots
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        etype, emsg = classify_error(exc, msg)
        cold = make_error_metrics(etype, emsg)
        hots = [make_error_metrics(etype, emsg) for _ in range(hot_runs)]
        return cold, hots
    finally:
        if conn is not None:
            conn.close()


def extract_policy_profile(notices: Sequence[str]) -> Tuple[str, Dict[str, str], int]:
    parseable = ""
    parseable_kv: Dict[str, str] = {}
    best_score = None
    fallback = ""
    count = 0
    for line in notices:
        if "policy_profile:" not in line:
            continue
        count += 1
        payload = line.split("policy_profile:", 1)[1].strip()
        kv_one: Dict[str, str] = {}
        for key, val in re.findall(r"([A-Za-z0-9_]+)=([^\s]+)", payload):
            kv_one[key] = val.rstrip(",")
        if "bytes_artifacts_loaded" in kv_one:
            try:
                score = (
                    int(kv_one.get("n_policy_targets", "0")),
                    int(kv_one.get("rows_seen", "0")),
                    int(float(kv_one.get("policy_total_ms", "0")) * 1000.0),
                    int(kv_one.get("bytes_artifacts_loaded", "0")),
                )
            except Exception:
                score = (0, 0, 0, 0)
            if best_score is None or score > best_score:
                best_score = score
                parseable = payload
                parseable_kv = kv_one
        elif not fallback:
            fallback = payload
    if parseable:
        return parseable, parseable_kv, count
    payload = fallback
    kv: Dict[str, str] = {}
    if payload:
        for key, val in re.findall(r"([A-Za-z0-9_]+)=([^\s]+)", payload):
            kv[key] = val.rstrip(",")
    return payload, kv, count


def run_ours_profile_capture(
    db: str,
    query_sql: str,
    enabled_path: Path,
    statement_timeout_ms: int,
) -> Tuple[RunMetrics, str, Dict[str, str], int]:
    conn = None
    try:
        conn = connect(db, "postgres")
        with conn.cursor() as cur:
            set_session_for_baseline(cur, "ours", enabled_path, statement_timeout_ms, ours_debug_mode="trace")
            cur.execute("SET client_min_messages = notice;")
            metrics, notices = execute_with_rss_and_notices(cur, query_sql)
            payload, kv, cnt = extract_policy_profile(notices)
            return metrics, payload, kv, cnt
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        etype, emsg = classify_error(exc, msg)
        return make_error_metrics(etype, emsg), "", {}, 0
    finally:
        if conn is not None:
            conn.close()


def build_time_row(
    db: str,
    k: int,
    policy_ids: str,
    baseline: str,
    query_id: str,
    cold: RunMetrics,
    hots: List[RunMetrics],
    expected_hot: int,
) -> Dict[str, str]:
    row = {
        "row_type": "query",
        "db": db,
        "K": str(k),
        "policy_ids": policy_ids,
        "baseline": baseline,
        "query_id": query_id,
        "setup_ms": "",
        "disk_overhead_bytes": "",
        "cold_ms": f"{cold.elapsed_ms:.3f}",
        "cold_peak_rss_kb": str(cold.peak_rss_kb),
        "hot1_ms": "",
        "hot1_peak_rss_kb": "",
        "hot2_ms": "",
        "hot2_peak_rss_kb": "",
        "hot3_ms": "",
        "hot3_peak_rss_kb": "",
        "hot4_ms": "",
        "hot4_peak_rss_kb": "",
        "hot5_ms": "",
        "hot5_peak_rss_kb": "",
        "hot_avg_ms": "0.000",
        "hot_avg_peak_rss_kb": "0",
        "status": "ok",
        "error_type": "",
        "error_msg": "",
    }

    if cold.status != "ok":
        row["status"] = "error"
        row["error_type"] = cold.error_type or "db_error"
        row["error_msg"] = cold.error_msg
        return row

    hot_vals: List[float] = []
    hot_rss: List[int] = []

    for i in range(min(5, len(hots))):
        h = hots[i]
        if h.status == "ok":
            row[f"hot{i+1}_ms"] = f"{h.elapsed_ms:.3f}"
            row[f"hot{i+1}_peak_rss_kb"] = str(h.peak_rss_kb)
            hot_vals.append(h.elapsed_ms)
            hot_rss.append(h.peak_rss_kb)
        else:
            row["status"] = "error"
            row["error_type"] = h.error_type or "db_error"
            row["error_msg"] = h.error_msg

    # Required guardrail
    if row["status"] == "ok" and len(hot_vals) != expected_hot:
        row["status"] = "error"
        row["error_type"] = "timing_bug"
        row["error_msg"] = "cold succeeded but one or more hot timings are missing"

    if row["status"] == "ok" and hot_vals:
        row["hot_avg_ms"] = f"{sum(hot_vals)/len(hot_vals):.3f}"
        row["hot_avg_peak_rss_kb"] = str(int(sum(hot_rss) / len(hot_rss)))

    return row


def build_profile_row(
    db: str,
    k: int,
    policy_ids: str,
    query_id: str,
    run_metrics: RunMetrics,
    profile_payload: str,
    profile_kv: Dict[str, str],
    profile_line_count: int,
) -> Dict[str, str]:
    required_layer_fields = [
        "child_exec_ms",
        "ctid_extract_ms",
        "ctid_to_rid_ms",
        "allow_check_ms",
        "projection_ms",
    ]
    row = {
        "db": db,
        "K": str(k),
        "policy_ids": policy_ids,
        "baseline": "ours",
        "query_id": query_id,
        "status": run_metrics.status,
        "error_type": run_metrics.error_type if run_metrics.status != "ok" else "",
        "error_msg": run_metrics.error_msg if run_metrics.status != "ok" else "",
        "eval_ms": "0",
        "artifact_load_ms": "0",
        "policy_total_ms": "0",
        "ctid_map_ms": "0",
        "filter_ms": "0",
        "bytes_artifacts_loaded": "0",
        "bytes_allow": "0",
        "bytes_ctid": "0",
        "bytes_blk_index": "0",
        "rows_seen": "0",
        "rows_passed": "0",
        "ctid_misses": "0",
        "peak_rss_kb_end": "0",
        "policy_profile_lines": str(profile_line_count),
        "has_new_layer_fields": "0",
        "profile_line": profile_payload,
    }
    key_map = {
        "eval_ms": "eval_ms",
        "artifact_load_ms": "artifact_load_ms",
        "policy_total_ms": "policy_total_ms",
        "ctid_map_ms": "ctid_map_ms",
        "filter_ms": "filter_ms",
        "bytes_artifacts_loaded": "bytes_artifacts_loaded",
        "bytes_allow": "bytes_allow",
        "bytes_ctid": "bytes_ctid",
        "bytes_blk_index": "bytes_blk_index",
        "rows_seen": "rows_seen",
        "rows_passed": "rows_passed",
        "ctid_misses": "ctid_misses",
        "peak_rss_kb_end": "peak_rss_kb_end",
    }
    for out_key, in_key in key_map.items():
        if in_key in profile_kv:
            row[out_key] = profile_kv[in_key]
    row["has_new_layer_fields"] = "1" if all(k in profile_kv for k in required_layer_fields) else "0"
    if run_metrics.status == "ok" and not profile_payload:
        row["status"] = "error"
        row["error_type"] = "missing_profile"
        row["error_msg"] = "no parseable policy_profile line found"
    # Some queries (e.g., with nested subqueries) can emit multiple policy_profile lines; keep count for auditing.
    if row["status"] == "ok" and row["has_new_layer_fields"] != "1":
        row["status"] = "error"
        row["error_type"] = "missing_layer_fields"
        row["error_msg"] = "missing one or more layer timing fields"
    if row["status"] == "ok":
        try:
            if int(row["ctid_misses"]) != 0:
                row["status"] = "error"
                row["error_type"] = "ctid_miss"
                row["error_msg"] = f"ctid_misses={row['ctid_misses']}"
        except Exception:
            pass
    return row


def is_single_select(query_sql: str) -> bool:
    s = query_sql.strip()
    if s.endswith(";"):
        s = s[:-1].strip()
    if ";" in s:
        return False
    return s.lower().startswith("select")


def count_wrapper(query_sql: str) -> Optional[str]:
    if not is_single_select(query_sql):
        return None
    s = query_sql.strip()
    if s.endswith(";"):
        s = s[:-1].strip()
    return f"SELECT COUNT(*) FROM ({s}) AS __q;"


def count_fallback_sql(query_id: str) -> Optional[str]:
    # TPC-H q15 is multi-statement (create view; select; drop view) in queries.txt,
    # so we can't COUNT-wrap it directly. Use an equivalent single-statement count.
    if str(query_id) == "15":
        return (
            "WITH revenue0 AS ("
            "  SELECT l_suppkey AS supplier_no, SUM(l_extendedprice * (1 - l_discount)) AS total_revenue "
            "  FROM lineitem "
            "  WHERE l_shipdate >= DATE '1996-10-01' "
            "    AND l_shipdate < DATE '1996-10-01' + INTERVAL '3' month "
            "  GROUP BY l_suppkey"
            "), maxrev AS ("
            "  SELECT MAX(total_revenue) AS max_total_revenue FROM revenue0"
            ") "
            "SELECT COUNT(*) "
            "FROM supplier, revenue0, maxrev "
            "WHERE s_suppkey = supplier_no "
            "  AND total_revenue = max_total_revenue;"
        )
    # TPC-H q6 returns a single aggregate row; COUNT-wrapping it gets planner-simplified
    # into a constant and bypasses scans (and thus enforcement). Use a meaningful
    # row-count on the underlying base relation instead.
    if str(query_id) == "6":
        return (
            "SELECT COUNT(*) "
            "FROM lineitem "
            "WHERE l_shipdate >= DATE '1994-01-01' "
            "  AND l_shipdate < DATE '1994-01-01' + INTERVAL '1' year "
            "  AND l_discount BETWEEN 0.04 - 0.01 AND 0.04 + 0.01 "
            "  AND l_quantity < 24;"
        )
    return None


def count_query_sql(db: str, baseline: str, sql_text: str, enabled_path: Path, statement_timeout_ms: int) -> int:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = connect(db, role)
    try:
        with conn.cursor() as cur:
            set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            cur.execute(sql_text)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def count_query(db: str, baseline: str, query_sql: str, enabled_path: Path, statement_timeout_ms: int) -> int:
    wrapped = count_wrapper(query_sql)
    if wrapped is None:
        raise HarnessError("cannot count-wrap multi-statement query")
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = connect(db, role)
    try:
        with conn.cursor() as cur:
            set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            cur.execute(wrapped)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def compare_counts(db: str, k: int, qid: str, qsql: str, enabled_path: Path, statement_timeout_ms: int) -> Dict[str, str]:
    fb = count_fallback_sql(qid)
    try:
        if fb is not None:
            oc = count_query_sql(db, "ours", fb, enabled_path, statement_timeout_ms)
        else:
            oc = count_query(db, "ours", qsql, enabled_path, statement_timeout_ms)
    except Exception as exc:  # noqa: BLE001
        return {
            "db": db,
            "K": str(k),
            "query_id": qid,
            "correctness": "skip",
            "ours_count": "",
            "rls_count": "",
            "reason": f"ours_count_failed: {str(exc).replace(chr(10), ' ')[:160]}",
        }

    try:
        if fb is not None:
            rc = count_query_sql(db, "rls_with_index", fb, enabled_path, statement_timeout_ms)
        else:
            rc = count_query(db, "rls_with_index", qsql, enabled_path, statement_timeout_ms)
    except Exception as exc:  # noqa: BLE001
        return {
            "db": db,
            "K": str(k),
            "query_id": qid,
            "correctness": "skip",
            "ours_count": str(oc),
            "rls_count": "",
            "reason": f"rls_count_failed: {str(exc).replace(chr(10), ' ')[:160]}",
        }

    return {
        "db": db,
        "K": str(k),
        "query_id": qid,
        "correctness": "1" if oc == rc else "0",
        "ours_count": str(oc),
        "rls_count": str(rc),
        "reason": "" if oc == rc else "count_mismatch",
    }


def write_csv_header(path: Path, columns: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(columns))
        w.writeheader()


def append_csv_row(path: Path, columns: Sequence[str], row: Dict[str, str]) -> None:
    with path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(columns))
        w.writerow(row)


def choose_correctness_queries(
    queries: Sequence[Tuple[str, str]],
    sample_count: int,
    rng: random.Random,
) -> List[Tuple[str, str]]:
    if sample_count <= 0 or sample_count >= len(queries):
        return list(queries)
    eligible = [(qid, qsql) for qid, qsql in queries if count_wrapper(qsql) is not None]
    if not eligible:
        return []
    if sample_count >= len(eligible):
        return eligible
    return rng.sample(eligible, sample_count)


def filter_queries_by_args(queries: List[Tuple[str, str]], query_ids, skip_query_ids) -> List[Tuple[str, str]]:
    out = list(queries)
    if query_ids:
        wanted = {str(x).strip() for x in query_ids}
        out = [(qid, q) for qid, q in out if qid in wanted]
    if skip_query_ids:
        skipped = {str(x).strip() for x in skip_query_ids}
        out = [(qid, q) for qid, q in out if qid not in skipped]
    if not out:
        raise HarnessError("query filtering removed all queries")
    return out


def compute_summary(times_csv: Path, summary_csv: Path) -> None:
    with times_csv.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    setup = {
        (r["db"], int(r["K"]), r["baseline"]): int(r["disk_overhead_bytes"] or 0)
        for r in rows
        if r["row_type"] == "setup"
    }
    qrows = [r for r in rows if r["row_type"] == "query" and r["status"] == "ok"]
    keys = sorted({(r["db"], int(r["K"])) for r in rows})

    out_rows: List[Dict[str, str]] = []
    for db, k in keys:
        db_scale = db_scale_from_name(db)
        policy_ids = ""
        for r in rows:
            if r["db"] == db and int(r["K"]) == k and r.get("policy_ids"):
                policy_ids = r["policy_ids"]
                break
        ours_ms = [float(r["hot_avg_ms"]) for r in qrows if r["db"] == db and int(r["K"]) == k and r["baseline"] == "ours"]
        rls_ms = [
            float(r["hot_avg_ms"])
            for r in qrows
            if r["db"] == db and int(r["K"]) == k and r["baseline"] == "rls_with_index"
        ]
        cross_ours_ms = [
            float(r["hot_avg_ms"])
            for r in qrows
            if r["db"] == db and int(r["K"]) == k and r["baseline"] == "ours" and r["query_id"] in CROSS_TABLE_QUERY_IDS
        ]
        cross_rls_ms = [
            float(r["hot_avg_ms"])
            for r in qrows
            if r["db"] == db and int(r["K"]) == k and r["baseline"] == "rls_with_index" and r["query_id"] in CROSS_TABLE_QUERY_IDS
        ]
        ours_rss = [
            int(r["hot_avg_peak_rss_kb"])
            for r in qrows
            if r["db"] == db and int(r["K"]) == k and r["baseline"] == "ours"
        ]
        rls_rss = [
            int(r["hot_avg_peak_rss_kb"])
            for r in qrows
            if r["db"] == db and int(r["K"]) == k and r["baseline"] == "rls_with_index"
        ]

        med_ours_ms = statistics.median(ours_ms) if ours_ms else 0.0
        med_rls_ms = statistics.median(rls_ms) if rls_ms else 0.0
        ratio = (med_ours_ms / med_rls_ms) if med_rls_ms > 0 else 0.0
        cross_med_ours_ms = statistics.median(cross_ours_ms) if cross_ours_ms else 0.0
        cross_med_rls_ms = statistics.median(cross_rls_ms) if cross_rls_ms else 0.0
        cross_ratio = (cross_med_ours_ms / cross_med_rls_ms) if cross_med_rls_ms > 0 else 0.0

        out_rows.append(
            {
                "db": db,
                "db_scale": db_scale,
                "K": str(k),
                "policy_ids": policy_ids,
                "median_hot_ours_ms": f"{med_ours_ms:.3f}",
                "median_hot_rls_ms": f"{med_rls_ms:.3f}",
                "speedup_ratio": f"{ratio:.3f}",
                "cross_median_hot_ours_ms": f"{cross_med_ours_ms:.3f}",
                "cross_median_hot_rls_ms": f"{cross_med_rls_ms:.3f}",
                "cross_speedup_ratio": f"{cross_ratio:.3f}",
                "median_hot_peak_rss_ours_kb": str(int(statistics.median(ours_rss)) if ours_rss else 0),
                "median_hot_peak_rss_rls_kb": str(int(statistics.median(rls_rss)) if rls_rss else 0),
                "disk_ours_bytes": str(setup.get((db, k, "ours"), 0)),
                "disk_rls_bytes": str(setup.get((db, k, "rls_with_index"), 0)),
            }
        )

    def _sort_key(r: Dict[str, str]):
        try:
            scale = float(r["db_scale"]) if r.get("db_scale") else float("inf")
        except Exception:
            scale = float("inf")
        return (scale, r["db"], int(r["K"]))

    out_rows.sort(key=_sort_key)

    write_csv_header(summary_csv, SUMMARY_COLUMNS)
    for r in out_rows:
        append_csv_row(summary_csv, SUMMARY_COLUMNS, r)

    for r in out_rows:
        print(
            f"[summary] db={r['db']} scale={r['db_scale']} K={r['K']} "
            f"median_hot ours={r['median_hot_ours_ms']}ms rls={r['median_hot_rls_ms']}ms "
            f"ratio={r['speedup_ratio']} cross_ratio={r['cross_speedup_ratio']} "
            f"disk ours={r['disk_ours_bytes']} rls={r['disk_rls_bytes']} "
            f"median_rss ours={r['median_hot_peak_rss_ours_kb']}KB rls={r['median_hot_peak_rss_rls_kb']}KB"
        )


def generate_plots(summary_csv: Path, plots_dir: Path, policy_pool_spec: str) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:  # noqa: BLE001
        print(f"[plot] matplotlib unavailable: {exc}")
        return

    plots_dir.mkdir(parents=True, exist_ok=True)

    with summary_csv.open("r", encoding="utf-8", newline="") as f:
        srows = list(csv.DictReader(f))
    if not srows:
        print("[plot] no summary rows")
        return

    def _scale_num(row):
        try:
            return float(row["db_scale"]) if row.get("db_scale") else float("inf")
        except Exception:
            return float("inf")

    ks = sorted({int(r["K"]) for r in srows})
    db_order = sorted({r["db"] for r in srows}, key=lambda d: _scale_num({"db_scale": db_scale_from_name(d)}))
    rows_by = {(r["db"], int(r["K"])): r for r in srows}
    scale_by_db = {}
    for db in db_order:
        scale_txt = db_scale_from_name(db)
        try:
            scale_by_db[db] = float(scale_txt) if scale_txt else float("nan")
        except Exception:
            scale_by_db[db] = float("nan")

    n = len(ks)
    ncols = min(2, n) if n > 1 else 1
    nrows = (n + ncols - 1) // ncols

    def _plot(metric_ours: str, metric_rls: str, ylabel: str, filename: str, title: str) -> None:
        fig, axes = plt.subplots(nrows=nrows, ncols=ncols, figsize=(6 * ncols, 4.5 * nrows), squeeze=False)
        for idx, k in enumerate(ks):
            ax = axes[idx // ncols][idx % ncols]
            xvals: List[float] = []
            ours_vals: List[float] = []
            rls_vals: List[float] = []
            for db in db_order:
                key = (db, k)
                if key not in rows_by:
                    continue
                x = scale_by_db.get(db)
                if x is None or x != x:  # NaN check
                    continue
                row = rows_by[key]
                xvals.append(x)
                ours_vals.append(float(row[metric_ours]))
                rls_vals.append(float(row[metric_rls]))
            if xvals:
                ax.plot(xvals, ours_vals, marker="o", label="ours")
                ax.plot(xvals, rls_vals, marker="o", label="rls_with_index")
            ax.set_yscale("log")
            ax.set_xlabel("db scale")
            ax.set_ylabel(ylabel)
            ax.set_title(f"K={k}")
            if xvals:
                ax.set_xticks(sorted(set(xvals)))
            ax.grid(True, linestyle=":", alpha=0.3)
            ax.legend()
        for j in range(len(ks), nrows * ncols):
            axes[j // ncols][j % ncols].axis("off")
        fig.suptitle(f"{title} (pool={policy_pool_spec})")
        fig.tight_layout()
        fig.savefig(plots_dir / filename)
        plt.close(fig)

    _plot("median_hot_ours_ms", "median_hot_rls_ms", "median hot_avg_ms (ms, log scale)", "runtime_vs_dbscale.png", "Runtime vs DB Scale")
    _plot("disk_ours_bytes", "disk_rls_bytes", "disk_overhead_bytes (bytes, log scale)", "disk_vs_dbscale.png", "Disk vs DB Scale")
    _plot(
        "median_hot_peak_rss_ours_kb",
        "median_hot_peak_rss_rls_kb",
        "median peak rss (KB, log scale)",
        "memory_vs_dbscale.png",
        "Memory vs DB Scale",
    )


def run_smoke_check(
    db: str,
    policy_lines: List[str],
    policy_pool: Sequence[int],
    queries: List[Tuple[str, str]],
    enabled_path: Path,
    statement_timeout_ms: int,
) -> None:
    k = len(policy_pool)
    enabled_ids, enabled = select_enabled_policies(policy_lines, policy_pool, k)
    policy_ids = ",".join(str(x) for x in enabled_ids)
    print(f"[smoke] Running K={k} (pool-full), queries {{3,13}}, hot-runs=2")
    print(f"[smoke] enabled_ids={enabled_ids}")
    write_enabled_policy_file(enabled, enabled_path)
    setup_ours_for_k(db, k, enabled_path, statement_timeout_ms)
    apply_rls_policies_for_k(db, enabled)
    create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)

    qmap = {qid: q for qid, q in queries}
    for qid in ["3", "13"]:
        if qid not in qmap:
            raise HarnessError(f"smoke query id {qid} missing from query file")
        q = qmap[qid]
        cold_o, hot_o = run_query_series(db, "ours", q, 2, enabled_path, statement_timeout_ms)
        cold_r, hot_r = run_query_series(db, "rls_with_index", q, 2, enabled_path, statement_timeout_ms)
        if cold_o.status != "ok" or cold_r.status != "ok":
            raise HarnessError(f"smoke failed: cold run error for q={qid}")
        if len(hot_o) != 2 or len(hot_r) != 2:
            raise HarnessError(f"smoke failed: expected 2 hot runs for q={qid}")
        ours_hot = [h.elapsed_ms for h in hot_o if h.status == "ok"]
        rls_hot = [h.elapsed_ms for h in hot_r if h.status == "ok"]
        if len(ours_hot) != 2 or len(rls_hot) != 2:
            raise HarnessError(f"smoke failed: hot run status error for q={qid}")
        if any(v <= 0 for v in ours_hot + rls_hot):
            raise HarnessError(f"smoke failed: non-positive hot timing for q={qid}")
        print(
            f"[smoke] K={k} q={qid} hot_ours={[round(x,3) for x in ours_hot]} "
            f"hot_rls={[round(x,3) for x in rls_hot]}"
        )

        ours_count = count_query(db, "ours", q, enabled_path, statement_timeout_ms)
        rls_count = count_query(db, "rls_with_index", q, enabled_path, statement_timeout_ms)
        print(f"[smoke] K={k} q={qid} policy_ids={policy_ids} ours_count={ours_count} rls_count={rls_count}")
        if ours_count != rls_count:
            raise HarnessError(f"smoke failed: count mismatch for q={qid} ours={ours_count} rls={rls_count}")

    prof_metrics, prof_payload, prof_kv, prof_cnt = run_ours_profile_capture(
        db, qmap["3"], enabled_path, statement_timeout_ms
    )
    has_profile = bool(prof_payload) and "bytes_artifacts_loaded=" in prof_payload
    misses = int(prof_kv.get("ctid_misses", "-1"))
    print(
        f"[smoke] profile_found={has_profile} policy_profile_lines={prof_cnt} "
        f"ctid_misses={misses} status={prof_metrics.status}"
    )
    if prof_metrics.status != "ok":
        raise HarnessError(f"smoke failed: profile run status={prof_metrics.status} err={prof_metrics.error_msg}")
    if not has_profile:
        raise HarnessError("smoke failed: parseable policy_profile line not found")
    if misses != 0:
        raise HarnessError(f"smoke failed: expected ctid_misses=0, got {misses}")


def run_experiment(args: argparse.Namespace) -> None:
    dbs = [str(d).strip() for d in (args.dbs or [args.db]) if str(d).strip()]
    if not dbs:
        raise HarnessError("no databases provided")
    hot_runs = args.hot_runs
    if hot_runs != 5:
        raise HarnessError("For stress matrix run, --hot-runs must be 5")
    statement_timeout_ms = parse_timeout_ms(args.statement_timeout)

    policy_lines = load_policy_lines(Path(args.policy))
    policy_pool = parse_policy_pool(args.policy_pool, len(policy_lines))
    queries = load_queries(Path(args.queries))
    queries = filter_queries_by_args(queries, args.query_ids, args.skip_query_ids)

    enabled_path = Path(args.policies_enabled)
    times_csv = Path(args.times_csv)
    profile_csv = Path(args.profile_csv)
    correctness_csv = Path(args.correctness_csv)
    summary_csv = Path(args.summary_csv)
    plots_dir = Path(args.plots_dir)

    write_csv_header(times_csv, TIMES_COLUMNS)
    write_csv_header(profile_csv, PROFILE_COLUMNS)
    write_csv_header(correctness_csv, CORRECTNESS_COLUMNS)

    rng = random.Random(args.seed)

    for db in dbs:
        print(f"[db] start db={db}")
        for k in args.ks:
            enabled_ids, enabled = select_enabled_policies(policy_lines, policy_pool, k)
            policy_ids = ",".join(str(x) for x in enabled_ids)
            print(f"[policy_set] db={db} K={k} enabled_ids={enabled_ids}")
            write_enabled_policy_file(enabled, enabled_path)

            # setup ours
            ours_setup_ms, ours_disk = setup_ours_for_k(db, k, enabled_path, statement_timeout_ms)
            append_csv_row(
                times_csv,
                TIMES_COLUMNS,
                {
                    "row_type": "setup",
                    "db": db,
                    "K": str(k),
                    "policy_ids": policy_ids,
                    "baseline": "ours",
                    "query_id": "__setup__",
                    "setup_ms": f"{ours_setup_ms:.3f}",
                    "disk_overhead_bytes": str(ours_disk),
                    "cold_ms": "",
                    "cold_peak_rss_kb": "",
                    "hot1_ms": "",
                    "hot1_peak_rss_kb": "",
                    "hot2_ms": "",
                    "hot2_peak_rss_kb": "",
                    "hot3_ms": "",
                    "hot3_peak_rss_kb": "",
                    "hot4_ms": "",
                    "hot4_peak_rss_kb": "",
                    "hot5_ms": "",
                    "hot5_peak_rss_kb": "",
                    "hot_avg_ms": "",
                    "hot_avg_peak_rss_kb": "",
                    "status": "ok",
                    "error_type": "",
                    "error_msg": "",
                },
            )

            # setup rls + index
            apply_rls_policies_for_k(db, enabled)
            rls_setup_ms, rls_disk, _ = create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)
            append_csv_row(
                times_csv,
                TIMES_COLUMNS,
                {
                    "row_type": "setup",
                    "db": db,
                    "K": str(k),
                    "policy_ids": policy_ids,
                    "baseline": "rls_with_index",
                    "query_id": "__setup__",
                    "setup_ms": f"{rls_setup_ms:.3f}",
                    "disk_overhead_bytes": str(rls_disk),
                    "cold_ms": "",
                    "cold_peak_rss_kb": "",
                    "hot1_ms": "",
                    "hot1_peak_rss_kb": "",
                    "hot2_ms": "",
                    "hot2_peak_rss_kb": "",
                    "hot3_ms": "",
                    "hot3_peak_rss_kb": "",
                    "hot4_ms": "",
                    "hot4_peak_rss_kb": "",
                    "hot5_ms": "",
                    "hot5_peak_rss_kb": "",
                    "hot_avg_ms": "",
                    "hot_avg_peak_rss_kb": "",
                    "status": "ok",
                    "error_type": "",
                    "error_msg": "",
                },
            )

            correctness_queries = choose_correctness_queries(queries, args.correctness_sample, rng)
            print(f"[correctness_sample] db={db} K={k} queries={[qid for qid, _ in correctness_queries]}")

            # timing + correctness per query
            for qid, qsql in queries:
                for baseline in ["ours", "rls_with_index"]:
                    print(f"[progress] db={db} K={k} baseline={baseline} query={qid}")
                    cold, hots = run_query_series(db, baseline, qsql, hot_runs, enabled_path, statement_timeout_ms)
                    row = build_time_row(db, k, policy_ids, baseline, qid, cold, hots, expected_hot=hot_runs)
                    append_csv_row(times_csv, TIMES_COLUMNS, row)
                    if baseline == "ours":
                        prof_metrics, prof_payload, prof_kv, prof_cnt = run_ours_profile_capture(
                            db, qsql, enabled_path, statement_timeout_ms
                        )
                        prow = build_profile_row(
                            db, k, policy_ids, qid, prof_metrics, prof_payload, prof_kv, prof_cnt
                        )
                        append_csv_row(profile_csv, PROFILE_COLUMNS, prow)

            # correctness for sampled queries
            for qid, qsql in correctness_queries:
                cr = compare_counts(db, k, qid, qsql, enabled_path, statement_timeout_ms)
                append_csv_row(correctness_csv, CORRECTNESS_COLUMNS, cr)

        print(f"[db] done db={db}")

    compute_summary(times_csv, summary_csv)
    generate_plots(summary_csv, plots_dir, args.policy_pool)

    print(f"[done] times_csv={times_csv}")
    print(f"[done] profile_csv={profile_csv}")
    print(f"[done] correctness_csv={correctness_csv}")
    print(f"[done] summary_csv={summary_csv}")
    print(f"[done] plots_dir={plots_dir}")


def main() -> None:
    args = parse_args()
    if not args.run:
        raise HarnessError("Use --run")
    if args.smoke_only and not args.smoke_check:
        raise HarnessError("--smoke-only requires --smoke-check")

    # Allow overriding .so locations (useful when the DB backend can't traverse the harness user's $HOME).
    global CUSTOM_FILTER_SO, ARTIFACT_BUILDER_SO
    CUSTOM_FILTER_SO = str(args.custom_filter_so)
    ARTIFACT_BUILDER_SO = str(args.artifact_builder_so)

    policy_lines = load_policy_lines(Path(args.policy))
    policy_pool = parse_policy_pool(args.policy_pool, len(policy_lines))
    queries = load_queries(Path(args.queries))
    queries = filter_queries_by_args(queries, args.query_ids, args.skip_query_ids)
    timeout_ms = parse_timeout_ms(args.statement_timeout)

    if args.smoke_check:
        run_smoke_check(
            args.db,
            policy_lines,
            policy_pool,
            queries,
            Path(args.policies_enabled),
            timeout_ms,
        )
        if args.smoke_only:
            return

    run_experiment(args)


if __name__ == "__main__":
    try:
        main()
    except HarnessError as exc:
        raise SystemExit(f"Error: {exc}")
