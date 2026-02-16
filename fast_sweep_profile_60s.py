#!/usr/bin/env python3
import argparse
import csv
import json
import os
import random
import re
import statistics
import threading
import time
from dataclasses import dataclass
from datetime import datetime
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
DEFAULT_MATRIX_KS = [1, 5, 10, 15, 20]
DEFAULT_MATRIX_DBS = ["tpch0_1", "tpch1", "tpch10"]
CROSS_TABLE_QUERY_IDS = {"3", "5", "7", "8", "10", "12", "13", "18", "22"}

DEFAULT_LAYER_PROBE_KS = [5, 15]
DEFAULT_LAYER_PROBE_QUERY_IDS = ["1", "3", "6", "13", "22"]

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

DASH_RUNS_COLUMNS = [
    "run_id",
    "ts",
    "db",
    "K",
    "policy_ids",
    "baseline",
    "query_id",
    "warmup_runs",
    "timed_runs",
    "planning_ms",
    "execution_ms",
    "total_ms",
    "peak_rss_mb",
    "status",
    "error_type",
    "error_msg",
    "result_count",
    "result_hash",
    "ours_count",
    "ours_hash",
    "rls_count",
    "rls_hash",
    "correctness",
]

DASH_BUILD_COLUMNS = [
    "run_id",
    "ts",
    "db",
    "K",
    "policy_ids",
    "ours_artifact_build_ms_total",
    "ours_artifact_bytes_db",
    "ours_artifact_bytes_disk",
    "rls_index_build_ms_total",
    "rls_index_bytes",
]

LAYER_PROBE_COLUMNS = [
    "run_id",
    "ts",
    "db",
    "K",
    "query_id",
    "policy_total_ms",
    "artifact_load_ms",
    "artifact_parse_ms",
    "atoms_ms",
    "presence_ms",
    "project_ms",
    "ctid_map_ms",
    "filter_ms",
    "child_exec_ms",
    "ctid_extract_ms",
    "ctid_to_rid_ms",
    "allow_check_ms",
    "projection_ms",
    "rss_mb",
    "rows_filtered",
    "rows_returned",
    "pe_total_ms",
    "pe_load_ms",
    "pe_local_ms",
    "pe_prop_ms",
    "pe_decode_ms",
    "local_stamp_ms",
    "local_bin_ms",
    "local_eval_ms",
    "local_fill_ms",
    "prop_ms_bundle",
    "status",
    "error_type",
    "error_msg",
    "policy_profile_lines",
    "policy_profile_query_lines",
    "policy_profile_bundle_lines",
]


class HarnessError(Exception):
    pass


class NoticeBuffer:
    def __init__(self, maxlen: int = 5000) -> None:
        self.maxlen = maxlen
        self._items: List[str] = []

    def append(self, item: str) -> None:
        self._items.append(item)
        overflow = len(self._items) - self.maxlen
        if overflow > 0:
            del self._items[:overflow]

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, idx):
        return self._items[idx]

    def __delitem__(self, idx) -> None:
        del self._items[idx]


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


@dataclass
class ExplainMetrics:
    planning_ms: float
    execution_ms: float
    total_ms: float
    wall_ms: float
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
    p.add_argument(
        "--matrix-tpch-scale",
        "--matrix_tpch_scale",
        dest="matrix_tpch_scale",
        action="store_true",
        help="Run the 4-metric dashboard matrix (dbs=tpch0_1,tpch1,tpch10; K=1,5,10,15,20; pool=1-20; skip q20)",
    )
    p.add_argument(
        "--layer-probe",
        "--layer_probe",
        dest="layer_probe",
        action="store_true",
        help="Run OURS-only per-layer timing probe (dbs=tpch0_1,tpch1,tpch10; K=5,15; queries=1,3,6,13,22)",
    )
    p.add_argument("--smoke-check", action="store_true", help="Run smoke check (K=11 pool-full, q3/q13, hot=2)")
    p.add_argument("--smoke-only", action="store_true", help="Run smoke check only, then exit")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--dbs", nargs="*", default=None, help="Optional list of DBs to run back-to-back")
    p.add_argument("--ks", nargs="*", type=int, default=DEFAULT_KS)
    p.add_argument("--policy-pool", default=DEFAULT_POLICY_POOL, help="Policy ID pool, e.g. 1-5,10-15")
    p.add_argument("--hot-runs", type=int, default=5)
    p.add_argument("--warmup-runs", type=int, default=1, help="Warm-up runs (not recorded) per query in matrix mode")
    p.add_argument("--timed-runs", type=int, default=3, help="Timed runs per query in matrix mode (median recorded)")
    p.add_argument("--run-dir", default="", help="Output run directory (default: logs/matrix_<ts>)")
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
    p.add_argument(
        "--profile-debug-mode",
        default="trace",
        choices=["off", "contract", "trace"],
        help="custom_filter.debug_mode used for the OURS profile-capture run (default: trace)",
    )
    p.add_argument(
        "--ours-profile-rescan",
        action="store_true",
        help="Enable custom_filter.profile_rescan=on for the OURS profile-capture run",
    )
    p.add_argument(
        "--dump-ours-notices",
        action="store_true",
        help="Write full NOTICE lines from the OURS profile-capture run into the profile CSV directory",
    )
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
            try:
                conn.notices = NoticeBuffer(maxlen=5000)
            except Exception:
                pass
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


def apply_no_parallel_settings(cur) -> None:
    # Hard-disable all query/maintenance parallelism for determinism and to
    # match the "no parallelism anywhere" experiment rule.
    stmts = [
        "SET max_parallel_workers_per_gather = 0;",
        "SET max_parallel_maintenance_workers = 0;",
        "SET parallel_leader_participation = off;",
        "SET force_parallel_mode = off;",
        "SET enable_parallel_append = off;",
        "SET enable_parallel_hash = off;",
        "SET max_parallel_workers = 0;",
    ]

    # Some clusters may run older Postgres versions (no parallel query) or
    # restrict certain GUCs. In those cases we best-effort set what exists.
    for stmt in stmts:
        try:
            cur.execute(stmt)
        except Exception:  # noqa: BLE001
            try:
                cur.connection.rollback()
            except Exception:
                pass


def apply_timing_session_settings(cur, statement_timeout_ms: int) -> None:
    apply_no_parallel_settings(cur)
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


def execute_with_rss_fetchall(cur, sql_text: str) -> Tuple[RunMetrics, List[Tuple]]:
    t0 = time.perf_counter()
    try:
        cur.execute("SELECT pg_backend_pid()")
        pid = int(cur.fetchone()[0])
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        etype, emsg = classify_error(exc, msg)
        return make_error_metrics(etype, emsg, elapsed_ms=(time.perf_counter() - t0) * 1000.0), []

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
    rows: List[Tuple] = []
    try:
        cur.execute(sql_text)
        if cur.description is not None:
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        status = "error"
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        error_type, error_msg = classify_error(exc, msg)
    finally:
        stop_evt.set()
        t.join(timeout=1)

    return (
        RunMetrics(
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            peak_rss_kb=int(peak_rss_kb),
            status=status,
            error_type=error_type,
            error_msg=error_msg,
        ),
        rows,
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


def parse_policy_entry_with_id(policy_line: str) -> Tuple[Optional[int], str, str]:
    s = policy_line.strip()
    pid: Optional[int] = None

    # Accept "12. table : ...", "12 table : ...", "12: table : ...".
    m = re.match(r"^\s*(\d+)\s*(?:[.:]\s*|\s+)(.*)$", s)
    if m:
        pid = int(m.group(1))
        s = m.group(2).strip()

    target, expr = parse_policy_entry(s)
    return pid, target, expr


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


def enabled_policy_path_for_k(base_path: Path, db: str, k: int) -> Path:
    suffix = base_path.suffix if base_path.suffix else ".txt"
    stem = base_path.stem if base_path.suffix else base_path.name
    safe_db = re.sub(r"[^A-Za-z0-9_]+", "_", db)
    return base_path.with_name(f"{stem}_{safe_db}_k{k}{suffix}")


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


def maybe_dump_rls_state(cur, tag: str) -> None:
    if os.getenv("CF_DUMP_RLS", "0") != "1":
        return

    print(f"[CF_RLS_DUMP] tag={tag}")
    cur.execute("SELECT current_user, session_user;")
    current_user, session_user = cur.fetchone()
    print(f"[CF_RLS_DUMP] current_user={current_user} session_user={session_user}")

    cur.execute("SHOW row_security;")
    print(f"[CF_RLS_DUMP] row_security={cur.fetchone()[0]}")

    cur.execute("SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user;")
    for rolname, rolsuper, rolbypassrls in cur.fetchall():
        print(f"[CF_RLS_DUMP] role rolname={rolname} rolsuper={rolsuper} rolbypassrls={rolbypassrls}")

    cur.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity "
        "FROM pg_class "
        "WHERE relname IN ('orders','customer','lineitem') "
        "ORDER BY relname;"
    )
    for relname, relrowsecurity, relforcerowsecurity in cur.fetchall():
        print(
            f"[CF_RLS_DUMP] rel relname={relname} relrowsecurity={relrowsecurity} "
            f"relforcerowsecurity={relforcerowsecurity}"
        )

    cur.execute(
        "SELECT tablename, policyname, permissive, roles, qual "
        "FROM pg_policies "
        "WHERE schemaname='public' AND policyname LIKE 'cf_%' "
        "ORDER BY tablename, policyname;"
    )
    rows = cur.fetchall()
    if not rows:
        print("[CF_RLS_DUMP] policies none")
    for tablename, policyname, permissive, roles, qual in rows:
        print(
            f"[CF_RLS_DUMP] policy tablename={tablename} policyname={policyname} "
            f"permissive={permissive} roles={roles} qual={qual}"
        )


def maybe_dump_policy_ast_notices(conn, tag: str) -> None:
    if os.getenv("CF_DUMP_POLICY_AST", "0") != "1":
        return
    lines = [n.replace("\n", " ").strip() for n in conn.notices if "CF_POLICY_AST" in n]
    if lines:
        print(f"[CF_POLICY_AST_DUMP] tag={tag} lines={len(lines)}")
        for line in lines:
            print(line)
    del conn.notices[:]


def apply_rls_policies_for_k(db: str, enabled_policy_lines: Sequence[str]) -> None:
    by_target: Dict[str, List[Tuple[str, bool, str]]] = {}
    for i, line in enumerate(enabled_policy_lines, start=1):
        pid, target, expr = parse_policy_entry_with_id(line)
        pred = rewrite_policy_expr_for_rls(target, expr)

        # Mirror Postgres: permissive policies are ORed, restrictive are ANDed with the permissive OR.
        # If only restrictive policies exist for a table, Postgres returns no rows.
        permissive = True if pid is None else (pid % 2 == 1)
        name = f"cf_p{pid}" if pid is not None else f"cf_pX{i}"

        by_target.setdefault(target, []).append((name, permissive, f"({pred})"))

    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            apply_no_parallel_settings(cur)
            cur.execute("GRANT USAGE, CREATE ON SCHEMA public TO rls_user;")
            cur.execute("GRANT SELECT ON ALL TABLES IN SCHEMA public TO rls_user;")
            drop_harness_policies_and_disable_rls(cur)
            for tgt in sorted(by_target.keys()):
                cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY;").format(sql.Identifier(tgt)))
                for name, permissive, pred in by_target[tgt]:
                    mode = sql.SQL("PERMISSIVE" if permissive else "RESTRICTIVE")
                    cur.execute(
                        sql.SQL("CREATE POLICY {} ON {} AS {} FOR SELECT TO rls_user USING ({});").format(
                            sql.Identifier(name),
                            sql.Identifier(tgt),
                            mode,
                            sql.SQL(pred),
                        )
                    )
            maybe_dump_rls_state(cur, f"post_create db={db}")
    finally:
        conn.close()


def drop_harness_indexes(cur) -> None:
    cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname LIKE 'cf_rls_k%';")
    names = [r[0] for r in cur.fetchall()]
    for n in names:
        cur.execute(sql.SQL("DROP INDEX IF EXISTS public.{};").format(sql.Identifier(n)))
    for n in KNOWN_OLD_INDEXES:
        cur.execute(sql.SQL("DROP INDEX IF EXISTS public.{};").format(sql.Identifier(n)))


def drop_harness_policies_and_disable_rls(cur) -> None:
    cur.execute("SET LOCAL search_path TO public, pg_catalog")
    for t in TABLES:
        cur.execute(sql.SQL("ALTER TABLE {} DISABLE ROW LEVEL SECURITY;").format(sql.Identifier(t)))
        cur.execute(
            "SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename=%s AND policyname LIKE 'cf_%%';",
            [t],
        )
        for (pname,) in cur.fetchall():
            cur.execute(
                sql.SQL("DROP POLICY IF EXISTS {} ON {};").format(sql.Identifier(pname), sql.Identifier(t))
            )


def clear_artifacts(db: str) -> None:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);")
            cur.execute("TRUNCATE public.files;")
    finally:
        conn.close()


def clear_rls_indexes_and_policies(db: str) -> None:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            drop_harness_indexes(cur)
            drop_harness_policies_and_disable_rls(cur)
    finally:
        conn.close()


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
        "SELECT p.oid, pg_get_function_result(p.oid), p.probin, p.prosrc "
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
    probin = str(row[2] or "")
    prosrc = str(row[3] or "")
    if ret != "void" or probin != ARTIFACT_BUILDER_SO or prosrc != "build_base":
        cur.execute("DROP FUNCTION IF EXISTS public.build_base(text);")
        cur.execute(
            f"CREATE FUNCTION public.build_base(text) RETURNS void "
            f"AS '{ARTIFACT_BUILDER_SO}', 'build_base' LANGUAGE C STRICT;"
        )


def setup_ours_for_k(db: str, k: int, enabled_path: Path, statement_timeout_ms: int) -> Tuple[float, int]:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            apply_timing_session_settings(cur, statement_timeout_ms)
            dump_ast = os.getenv("CF_DUMP_POLICY_AST", "0") == "1"
            if dump_ast:
                cur.execute(f"LOAD '{CUSTOM_FILTER_SO}';")
                cur.execute("SET custom_filter.debug_mode = trace;")
                cur.execute("SET client_min_messages = notice;")
            cur.execute("CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);")
            ensure_build_base_function(cur)
            cur.execute("TRUNCATE public.files;")
            t0 = time.perf_counter()
            cur.execute("SELECT public.build_base(%s);", [str(enabled_path)])
            if dump_ast:
                maybe_dump_policy_ast_notices(conn, f"setup_ours db={db} k={k}")
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
        effective_debug_mode = ours_debug_mode
        if os.getenv("CF_DUMP_POLICY_AST", "0") == "1" and effective_debug_mode == "off":
            # Backend processes usually don't inherit this harness env var, so
            # use debug_mode as a backend-visible signal to emit AST dumps.
            effective_debug_mode = "trace"
        cur.execute("SET custom_filter.debug_mode = %s;", [effective_debug_mode])
        if os.getenv("CF_DUMP_POLICY_AST", "0") == "1":
            cur.execute("SET client_min_messages = notice;")
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
    query_id: str = "",
) -> Tuple[RunMetrics, List[RunMetrics]]:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = None
    try:
        conn = connect(db, role)
        with conn.cursor() as cur:
            set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            if baseline == "rls_with_index":
                maybe_dump_rls_state(cur, f"pre_query db={db} baseline={baseline} q={query_id or 'unknown'}")
            cold = execute_with_rss(cur, query_sql)
            if baseline == "ours":
                maybe_dump_policy_ast_notices(conn, f"db={db} baseline={baseline} q={query_id or 'unknown'} phase=cold")
            hots: List[RunMetrics] = []
            for run_idx in range(1, hot_runs + 1):
                try:
                    hots.append(execute_with_rss(cur, query_sql))
                except Exception as exc:  # noqa: BLE001
                    msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
                    etype, emsg = classify_error(exc, msg)
                    hots.append(make_error_metrics(etype, emsg))
                if baseline == "ours":
                    maybe_dump_policy_ast_notices(
                        conn,
                        f"db={db} baseline={baseline} q={query_id or 'unknown'} phase=hot{run_idx}",
                    )
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


def extract_policy_profile_query(notices: Sequence[str]) -> Tuple[str, Dict[str, str], int]:
    payload = ""
    kv: Dict[str, str] = {}
    count = 0
    for line in notices:
        if "policy_profile_query:" not in line:
            continue
        count += 1
        payload = line.split("policy_profile_query:", 1)[1].strip()
        kv_one: Dict[str, str] = {}
        for key, val in re.findall(r"([A-Za-z0-9_]+)=([^\s]+)", payload):
            kv_one[key] = val.rstrip(",")
        kv = kv_one
    return payload, kv, count


def extract_policy_load_ms_sum(notices: Sequence[str]) -> Tuple[float, int]:
    total = 0.0
    count = 0
    for line in notices:
        if "policy: load_ms=" not in line:
            continue
        m = re.search(r"\bpolicy:\s*load_ms=([0-9]+(?:\.[0-9]+)?)", line)
        if not m:
            continue
        try:
            total += float(m.group(1))
            count += 1
        except Exception:
            continue
    return total, count


def extract_policy_profile_bundle_agg(notices: Sequence[str]) -> Tuple[int, Dict[str, float]]:
    stamp_ms = 0.0
    bin_ms = 0.0
    eval_ms = 0.0
    fill_ms = 0.0
    prop_ms = 0.0
    count = 0
    for line in notices:
        if "policy_profile_bundle:" not in line:
            continue
        count += 1
        for a, b, c, d in re.findall(
            r"ms=([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)",
            line,
        ):
            try:
                stamp_ms += float(a)
                bin_ms += float(b)
                eval_ms += float(c)
                fill_ms += float(d)
            except Exception:
                pass
        m = re.search(r"prop=\{iter=\d+,ms=([0-9]+(?:\.[0-9]+)?)", line)
        if m:
            try:
                prop_ms += float(m.group(1))
            except Exception:
                pass
    return count, {
        "local_stamp_ms": stamp_ms,
        "local_bin_ms": bin_ms,
        "local_eval_ms": eval_ms,
        "local_fill_ms": fill_ms,
        "prop_ms_bundle": prop_ms,
    }


def run_ours_profile_capture(
    db: str,
    query_sql: str,
    enabled_path: Path,
    statement_timeout_ms: int,
    ours_profile_rescan: bool = False,
    ours_debug_mode: str = "trace",
    query_id: str = "",
    profile_k: Optional[int] = None,
    profile_query: str = "",
) -> Tuple[RunMetrics, str, Dict[str, str], int, List[str]]:
    conn = None
    try:
        conn = connect(db, "postgres")
        with conn.cursor() as cur:
            set_session_for_baseline(cur, "ours", enabled_path, statement_timeout_ms, ours_debug_mode=ours_debug_mode)
            if ours_profile_rescan:
                cur.execute("SET custom_filter.profile_rescan = on;")
            if profile_k is not None:
                cur.execute("SET custom_filter.profile_k = %s;", [int(profile_k)])
            if profile_query:
                cur.execute("SET custom_filter.profile_query = %s;", [str(profile_query)])
            cur.execute("SET client_min_messages = notice;")
            metrics, notices = execute_with_rss_and_notices(cur, query_sql)
            if os.getenv("CF_DUMP_POLICY_AST", "0") == "1":
                ast_lines = [n.replace("\n", " ").strip() for n in notices if "CF_POLICY_AST" in n]
                if ast_lines:
                    print(
                        f"[CF_POLICY_AST_DUMP] tag=profile_capture db={db} q={query_id or 'unknown'} "
                        f"lines={len(ast_lines)}"
                    )
                    for line in ast_lines:
                        print(line)
            payload, kv, cnt = extract_policy_profile(notices)
            return metrics, payload, kv, cnt, notices
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
        etype, emsg = classify_error(exc, msg)
        return make_error_metrics(etype, emsg), "", {}, 0, []
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


def timing_fallback_sql(query_id: str) -> Optional[str]:
    # For matrix runs we need single-statement EXPLAIN-able SQL.
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
            "SELECT s_suppkey, s_name, s_address, s_phone, total_revenue "
            "FROM supplier, revenue0, maxrev "
            "WHERE s_suppkey = supplier_no "
            "  AND total_revenue = max_total_revenue "
            "ORDER BY s_suppkey;"
        )
    return None


def count_query_sql(db: str, baseline: str, sql_text: str, enabled_path: Path, statement_timeout_ms: int) -> int:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = connect(db, role)
    try:
        with conn.cursor() as cur:
            set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            if baseline == "rls_with_index":
                maybe_dump_rls_state(cur, f"pre_count_sql db={db} baseline={baseline}")
            cur.execute(sql_text)
            if baseline == "ours":
                maybe_dump_policy_ast_notices(conn, f"pre_count_sql db={db} baseline={baseline}")
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
            if baseline == "rls_with_index":
                maybe_dump_rls_state(cur, f"pre_count_query db={db} baseline={baseline}")
            cur.execute(wrapped)
            if baseline == "ours":
                maybe_dump_policy_ast_notices(conn, f"pre_count_query db={db} baseline={baseline}")
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


def now_ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_clean_state(cur) -> Dict[str, int]:
    # Return invariants to ensure phased runs don't leak state across K/baselines.
    cur.execute("CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);")
    cur.execute("SELECT COUNT(*), COALESCE(SUM(pg_column_size(file)), 0) FROM public.files;")
    artifact_rows, artifact_bytes_db = cur.fetchone()
    cur.execute("SELECT COALESCE(pg_total_relation_size('public.files'::regclass), 0);")
    artifact_bytes_disk = int(cur.fetchone()[0] or 0)
    cur.execute("SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public' AND indexname LIKE 'cf_rls_k%';")
    idx_cnt = int(cur.fetchone()[0] or 0)
    cur.execute("SELECT COUNT(*) FROM pg_policies WHERE schemaname='public' AND policyname LIKE 'cf_%';")
    pol_cnt = int(cur.fetchone()[0] or 0)
    return {
        "artifact_rows": int(artifact_rows or 0),
        "artifact_bytes_db": int(artifact_bytes_db or 0),
        "artifact_bytes_disk": int(artifact_bytes_disk or 0),
        "harness_index_count": idx_cnt,
        "harness_policy_count": pol_cnt,
    }


def print_clean_state(db: str, tag: str) -> None:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            st = get_clean_state(cur)
            print(
                f"[clean_state] tag={tag} db={db} "
                f"artifacts_rows={st['artifact_rows']} artifacts_bytes_db={st['artifact_bytes_db']} "
                f"artifacts_bytes_disk={st['artifact_bytes_disk']} "
                f"indexes={st['harness_index_count']} policies={st['harness_policy_count']}"
            )
    finally:
        conn.close()


def explain_analyze_json(cur, query_sql: str) -> ExplainMetrics:
    q = query_sql.strip()
    if q.endswith(";"):
        q = q[:-1].rstrip()
    explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {q};"
    run, rows = execute_with_rss_fetchall(cur, explain_sql)
    if run.status != "ok":
        return ExplainMetrics(
            planning_ms=0.0,
            execution_ms=0.0,
            total_ms=0.0,
            wall_ms=float(run.elapsed_ms),
            peak_rss_kb=int(run.peak_rss_kb),
            status=run.status,
            error_type=run.error_type,
            error_msg=run.error_msg,
        )
    if not rows or not rows[0]:
        return ExplainMetrics(
            planning_ms=0.0,
            execution_ms=0.0,
            total_ms=0.0,
            wall_ms=float(run.elapsed_ms),
            peak_rss_kb=int(run.peak_rss_kb),
            status="error",
            error_type="explain_parse",
            error_msg="EXPLAIN returned no rows",
        )
    cell = rows[0][0]
    try:
        doc = cell if isinstance(cell, (list, dict)) else json.loads(str(cell))
        top = doc[0] if isinstance(doc, list) and doc else doc
        planning_ms = float(top.get("Planning Time", 0.0))
        execution_ms = float(top.get("Execution Time", 0.0))
        total_ms = planning_ms + execution_ms
        return ExplainMetrics(
            planning_ms=planning_ms,
            execution_ms=execution_ms,
            total_ms=total_ms,
            wall_ms=float(run.elapsed_ms),
            peak_rss_kb=int(run.peak_rss_kb),
            status="ok",
            error_type="",
            error_msg="",
        )
    except Exception as exc:  # noqa: BLE001
        return ExplainMetrics(
            planning_ms=0.0,
            execution_ms=0.0,
            total_ms=0.0,
            wall_ms=float(run.elapsed_ms),
            peak_rss_kb=int(run.peak_rss_kb),
            status="error",
            error_type="explain_parse",
            error_msg=str(exc).replace("\n", " ")[:240],
        )


def measure_explain_median_in_session(
    cur,
    query_sql: str,
    warmup_runs: int,
    timed_runs: int,
) -> ExplainMetrics:
    if warmup_runs < 0 or timed_runs < 1:
        raise HarnessError("warmup_runs must be >= 0 and timed_runs must be >= 1")

    # Warm-ups are still EXPLAIN ANALYZE executions; discard metrics.
    for _ in range(warmup_runs):
        m = explain_analyze_json(cur, query_sql)
        if m.status != "ok":
            return m

    trials: List[ExplainMetrics] = []
    for _ in range(timed_runs):
        m = explain_analyze_json(cur, query_sql)
        if m.status != "ok":
            return m
        trials.append(m)

    planning = statistics.median([t.planning_ms for t in trials]) if trials else 0.0
    execution = statistics.median([t.execution_ms for t in trials]) if trials else 0.0
    total = statistics.median([t.total_ms for t in trials]) if trials else 0.0
    wall = statistics.median([t.wall_ms for t in trials]) if trials else 0.0
    peak = int(statistics.median([t.peak_rss_kb for t in trials])) if trials else 0
    return ExplainMetrics(
        planning_ms=float(planning),
        execution_ms=float(execution),
        total_ms=float(total),
        wall_ms=float(wall),
        peak_rss_kb=int(peak),
        status="ok",
        error_type="",
        error_msg="",
    )


def result_count_in_session(cur, query_id: str, query_sql: str) -> int:
    fb = count_fallback_sql(query_id)
    if fb is not None:
        cur.execute(fb)
        return int(cur.fetchone()[0])

    wrapped = count_wrapper(query_sql)
    if wrapped is None:
        raise HarnessError(f"cannot count-wrap query_id={query_id} (and no fallback exists)")
    cur.execute(wrapped)
    return int(cur.fetchone()[0])


def count_and_hash_wrapper(query_sql: str) -> Optional[str]:
    # Order-insensitive hash (multiset) over result rows.
    if not is_single_select(query_sql):
        return None
    s = query_sql.strip()
    if s.endswith(";"):
        s = s[:-1].strip()
    return (
        "WITH __q AS ("
        + s
        + "), __h AS (SELECT md5(row_to_json(__q)::text) AS h FROM __q) "
        + "SELECT COUNT(*)::bigint AS count, "
        + "COALESCE(md5(string_agg(h, '' ORDER BY h)), md5('')) AS hash "
        + "FROM __h;"
    )


def result_count_and_hash_in_session(cur, query_id: str, query_sql: str) -> Tuple[int, str]:
    base_sql: Optional[str] = query_sql if is_single_select(query_sql) else timing_fallback_sql(query_id)
    wrapped = count_and_hash_wrapper(base_sql) if base_sql is not None else None
    if wrapped is None:
        # Best-effort fallback: keep counts so runs can proceed, but correctness becomes "skip".
        return result_count_in_session(cur, query_id, query_sql), ""
    cur.execute(wrapped)
    row = cur.fetchone()
    if not row or len(row) < 2:
        raise HarnessError("count+hash wrapper returned no rows")
    return int(row[0]), str(row[1] or "")


def timing_sql_for_query(query_id: str, query_sql: str) -> str:
    fb = timing_fallback_sql(query_id)
    if fb is not None:
        return fb
    if is_single_select(query_sql):
        return query_sql
    raise HarnessError(f"query_id={query_id} is not EXPLAIN-able (multi-statement and no timing fallback)")


def setup_ours_for_k_with_sizes(db: str, k: int, enabled_path: Path, statement_timeout_ms: int) -> Tuple[float, int, int]:
    conn = connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            apply_timing_session_settings(cur, statement_timeout_ms)
            dump_ast = os.getenv("CF_DUMP_POLICY_AST", "0") == "1"
            if dump_ast:
                cur.execute(f"LOAD '{CUSTOM_FILTER_SO}';")
                cur.execute("SET custom_filter.debug_mode = trace;")
                cur.execute("SET client_min_messages = notice;")
            cur.execute("CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);")
            ensure_build_base_function(cur)
            cur.execute("TRUNCATE public.files;")
            t0 = time.perf_counter()
            cur.execute("SELECT public.build_base(%s);", [str(enabled_path)])
            if dump_ast:
                maybe_dump_policy_ast_notices(conn, f"setup_ours db={db} k={k}")
            setup_ms = (time.perf_counter() - t0) * 1000.0
            cur.execute("SELECT COALESCE(SUM(pg_column_size(file)), 0) FROM public.files;")
            bytes_db = int(cur.fetchone()[0] or 0)
            cur.execute("SELECT COALESCE(pg_total_relation_size('public.files'::regclass), 0);")
            bytes_disk = int(cur.fetchone()[0] or 0)
    finally:
        conn.close()
    print(
        f"[setup_ours] K={k} setup_ms={setup_ms:.3f} "
        f"artifact_bytes_db={bytes_db} artifact_bytes_disk={bytes_disk}"
    )
    return setup_ms, bytes_db, bytes_disk


def run_matrix_tpch_scale(args: argparse.Namespace) -> None:
    statement_timeout_ms = parse_timeout_ms(args.statement_timeout)
    warmup_runs = int(args.warmup_runs)
    timed_runs = int(args.timed_runs)
    if warmup_runs < 0:
        raise HarnessError("--warmup-runs must be >= 0")
    if timed_runs < 1:
        raise HarnessError("--timed-runs must be >= 1")

    policy_lines = load_policy_lines(Path(args.policy))
    pool_spec = args.policy_pool
    if pool_spec == DEFAULT_POLICY_POOL:
        pool_spec = "1-20"
    policy_pool = parse_policy_pool(pool_spec, len(policy_lines))

    ks = list(args.ks)
    if ks == DEFAULT_KS:
        ks = list(DEFAULT_MATRIX_KS)
    if not ks:
        raise HarnessError("no K values provided")

    dbs = [str(d).strip() for d in (args.dbs or []) if str(d).strip()]
    if not dbs:
        dbs = list(DEFAULT_MATRIX_DBS)

    queries = load_queries(Path(args.queries))
    # Always skip q20 for this mode (can still further filter via args).
    skip_ids = set(str(x).strip() for x in (args.skip_query_ids or []))
    skip_ids.add("20")
    queries = filter_queries_by_args(queries, args.query_ids, list(skip_ids))

    if str(args.run_dir).strip():
        run_dir = Path(args.run_dir)
        if not run_dir.is_absolute():
            run_dir = ROOT / run_dir
    else:
        run_dir = ROOT / "logs" / f"matrix_{time.strftime('%Y%m%d_%H%M%S')}"
    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = run_dir.name
    runs_csv = run_dir / "runs.csv"
    build_csv = run_dir / "build.csv"
    enabled_base = run_dir / "policies_enabled.txt"

    write_csv_header(runs_csv, DASH_RUNS_COLUMNS)
    write_csv_header(build_csv, DASH_BUILD_COLUMNS)

    print(f"[matrix] run_id={run_id} run_dir={run_dir}")
    print(f"[matrix] dbs={dbs} Ks={ks} pool={pool_spec} warmup_runs={warmup_runs} timed_runs={timed_runs}")
    print(f"[matrix] queries={[qid for qid, _ in queries]}")

    for db in dbs:
        print(f"[db] start db={db}")
        clear_artifacts(db)
        clear_rls_indexes_and_policies(db)
        print_clean_state(db, tag="clean_start")

        for k in ks:
            enabled_ids, enabled = select_enabled_policies(policy_lines, policy_pool, k)
            policy_ids = ",".join(str(x) for x in enabled_ids)
            enabled_path_k = enabled_policy_path_for_k(enabled_base, db, k)
            print(f"[policy_set] db={db} K={k} enabled_ids={enabled_ids}")

            write_enabled_policy_file(enabled, enabled_path_k)
            clear_artifacts(db)
            clear_rls_indexes_and_policies(db)
            print_clean_state(db, tag=f"clean_before_k K={k}")

            # OURS phase.
            ours_setup_ms, ours_bytes_db, ours_bytes_disk = setup_ours_for_k_with_sizes(
                db, k, enabled_path_k, statement_timeout_ms
            )

            ours_metrics: Dict[str, ExplainMetrics] = {}
            ours_counts: Dict[str, Optional[int]] = {}
            ours_hashes: Dict[str, str] = {}
            conn_o = connect(db, "postgres")
            try:
                with conn_o.cursor() as cur:
                    set_session_for_baseline(cur, "ours", enabled_path_k, statement_timeout_ms, ours_debug_mode="off")
                    for qid, qsql in queries:
                        print(f"[progress] db={db} K={k} baseline=ours query={qid}")
                        timing_sql = timing_sql_for_query(qid, qsql)
                        m = measure_explain_median_in_session(cur, timing_sql, warmup_runs, timed_runs)
                        ours_metrics[qid] = m
                        if m.status == "ok":
                            try:
                                cnt, h = result_count_and_hash_in_session(cur, qid, qsql)
                                ours_counts[qid] = cnt
                                ours_hashes[qid] = h
                            except Exception as exc:  # noqa: BLE001
                                ours_counts[qid] = None
                                ours_hashes[qid] = ""
                                ours_metrics[qid] = ExplainMetrics(
                                    planning_ms=m.planning_ms,
                                    execution_ms=m.execution_ms,
                                    total_ms=m.total_ms,
                                    wall_ms=m.wall_ms,
                                    peak_rss_kb=m.peak_rss_kb,
                                    status="error",
                                    error_type="count_error",
                                    error_msg=str(exc).replace("\n", " ")[:240],
                                )
                        else:
                            ours_counts[qid] = None
                            ours_hashes[qid] = ""
            finally:
                conn_o.close()

            clear_artifacts(db)
            print_clean_state(db, tag=f"after_ours_drop K={k}")

            # RLS phase.
            apply_rls_policies_for_k(db, enabled)
            rls_setup_ms, rls_index_bytes, _idxs = create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)

            rls_metrics: Dict[str, ExplainMetrics] = {}
            rls_counts: Dict[str, Optional[int]] = {}
            rls_hashes: Dict[str, str] = {}
            conn_r = connect(db, "rls_user")
            try:
                with conn_r.cursor() as cur:
                    set_session_for_baseline(cur, "rls_with_index", enabled_path_k, statement_timeout_ms)
                    cur.execute("SET row_security = on;")
                    for qid, qsql in queries:
                        print(f"[progress] db={db} K={k} baseline=rls_with_index query={qid}")
                        timing_sql = timing_sql_for_query(qid, qsql)
                        m = measure_explain_median_in_session(cur, timing_sql, warmup_runs, timed_runs)
                        rls_metrics[qid] = m
                        if m.status == "ok":
                            try:
                                cnt, h = result_count_and_hash_in_session(cur, qid, qsql)
                                rls_counts[qid] = cnt
                                rls_hashes[qid] = h
                            except Exception as exc:  # noqa: BLE001
                                rls_counts[qid] = None
                                rls_hashes[qid] = ""
                                rls_metrics[qid] = ExplainMetrics(
                                    planning_ms=m.planning_ms,
                                    execution_ms=m.execution_ms,
                                    total_ms=m.total_ms,
                                    wall_ms=m.wall_ms,
                                    peak_rss_kb=m.peak_rss_kb,
                                    status="error",
                                    error_type="count_error",
                                    error_msg=str(exc).replace("\n", " ")[:240],
                                )
                        else:
                            rls_counts[qid] = None
                            rls_hashes[qid] = ""
            finally:
                conn_r.close()

            clear_rls_indexes_and_policies(db)
            print_clean_state(db, tag=f"after_rls_drop K={k}")

            # Build row (one per db,K).
            b_row = {
                "run_id": run_id,
                "ts": now_ts(),
                "db": db,
                "K": str(k),
                "policy_ids": policy_ids,
                "ours_artifact_build_ms_total": f"{ours_setup_ms:.3f}",
                "ours_artifact_bytes_db": str(ours_bytes_db),
                "ours_artifact_bytes_disk": str(ours_bytes_disk),
                "rls_index_build_ms_total": f"{rls_setup_ms:.3f}",
                "rls_index_bytes": str(rls_index_bytes),
            }
            append_csv_row(build_csv, DASH_BUILD_COLUMNS, b_row)

            # Runs rows (two per db,K,query).
            for qid, _qsql in queries:
                oc = ours_counts.get(qid)
                oh = ours_hashes.get(qid, "")
                rc = rls_counts.get(qid)
                rh = rls_hashes.get(qid, "")
                correctness = ""
                if oc is None or rc is None or not oh or not rh:
                    correctness = "skip"
                else:
                    correctness = "1" if (int(oc) == int(rc) and oh == rh) else "0"

                for baseline, m, cnt in [
                    ("ours", ours_metrics.get(qid), oc),
                    ("rls_with_index", rls_metrics.get(qid), rc),
                ]:
                    if m is None:
                        m = ExplainMetrics(
                            planning_ms=0.0,
                            execution_ms=0.0,
                            total_ms=0.0,
                            wall_ms=0.0,
                            peak_rss_kb=0,
                            status="error",
                            error_type="missing",
                            error_msg="missing metrics",
                        )
                    peak_rss_mb = float(m.peak_rss_kb) / 1024.0
                    result_hash = ""
                    if baseline == "ours":
                        result_hash = oh or ""
                    elif baseline == "rls_with_index":
                        result_hash = rh or ""
                    r_row = {
                        "run_id": run_id,
                        "ts": now_ts(),
                        "db": db,
                        "K": str(k),
                        "policy_ids": policy_ids,
                        "baseline": baseline,
                        "query_id": qid,
                        "warmup_runs": str(warmup_runs),
                        "timed_runs": str(timed_runs),
                        "planning_ms": f"{m.planning_ms:.3f}" if m.status == "ok" else "",
                        "execution_ms": f"{m.execution_ms:.3f}" if m.status == "ok" else "",
                        "total_ms": f"{m.total_ms:.3f}" if m.status == "ok" else "",
                        "peak_rss_mb": f"{peak_rss_mb:.3f}" if m.status == "ok" else "",
                        "status": m.status,
                        "error_type": m.error_type,
                        "error_msg": m.error_msg,
                        "result_count": "" if cnt is None else str(int(cnt)),
                        "result_hash": "" if not result_hash else str(result_hash),
                        "ours_count": "" if oc is None else str(int(oc)),
                        "ours_hash": "" if not oh else str(oh),
                        "rls_count": "" if rc is None else str(int(rc)),
                        "rls_hash": "" if not rh else str(rh),
                        "correctness": correctness,
                    }
                    append_csv_row(runs_csv, DASH_RUNS_COLUMNS, r_row)

        print(f"[db] done db={db}")

    print(f"[done] run_dir={run_dir}")
    print(f"[done] runs_csv={runs_csv}")
    print(f"[done] build_csv={build_csv}")


def write_layer_probe_summary(rows: Sequence[Dict[str, str]], out_path: Path) -> None:
    def fnum(x: str) -> float:
        try:
            return float(x)
        except Exception:
            return 0.0

    def ikey(x: str) -> int:
        try:
            return int(x)
        except Exception:
            return 0

    lines: List[str] = []
    lines.append("# Layer-Probe Summary")
    lines.append("")
    lines.append(f"rows={len(rows)}")
    lines.append("")

    def sort_key(r: Dict[str, str]):
        scale_txt = db_scale_from_name(r.get("db", ""))
        try:
            scale = float(scale_txt) if scale_txt else float("inf")
        except Exception:
            scale = float("inf")
        return (scale, r.get("db", ""), ikey(r.get("K", "0")), ikey(r.get("query_id", "0")))

    for r in sorted(rows, key=sort_key):
        db = r.get("db", "")
        k = r.get("K", "")
        q = r.get("query_id", "")
        status = r.get("status", "")
        lines.append(f"## db={db} K={k} q={q} status={status}")
        if status != "ok":
            et = r.get("error_type", "")
            em = r.get("error_msg", "")
            lines.append(f"error_type={et} error_msg={em}")
            lines.append("")
            continue

        layer_vals = {
            "child_exec_ms": fnum(r.get("child_exec_ms", "")),
            "ctid_map_ms": fnum(r.get("ctid_map_ms", "")),
            "filter_ms": fnum(r.get("filter_ms", "")),
            "policy_total_ms": fnum(r.get("policy_total_ms", "")),
        }
        sorted_layers = sorted(layer_vals.items(), key=lambda kv: kv[1], reverse=True)
        lines.append(
            "policy_layers_ms "
            + " ".join(f"{k}={v:.3f}" for k, v in sorted_layers)
        )

        pe_vals = {
            "pe_load_ms": fnum(r.get("pe_load_ms", "")),
            "pe_local_ms": fnum(r.get("pe_local_ms", "")),
            "pe_prop_ms": fnum(r.get("pe_prop_ms", "")),
            "pe_decode_ms": fnum(r.get("pe_decode_ms", "")),
            "pe_total_ms": fnum(r.get("pe_total_ms", "")),
        }
        sorted_pe = sorted(pe_vals.items(), key=lambda kv: kv[1], reverse=True)
        lines.append(
            "policy_engine_ms "
            + " ".join(f"{k}={v:.3f}" for k, v in sorted_pe)
        )

        local_vals = {
            "local_stamp_ms": fnum(r.get("local_stamp_ms", "")),
            "local_bin_ms": fnum(r.get("local_bin_ms", "")),
            "local_eval_ms": fnum(r.get("local_eval_ms", "")),
            "local_fill_ms": fnum(r.get("local_fill_ms", "")),
        }
        sorted_local = sorted(local_vals.items(), key=lambda kv: kv[1], reverse=True)
        lines.append(
            "local_bundle_ms "
            + " ".join(f"{k}={v:.3f}" for k, v in sorted_local)
        )
        lines.append(
            f"prop_ms_bundle={fnum(r.get('prop_ms_bundle', '')):.3f} rss_mb={fnum(r.get('rss_mb', '')):.3f} "
            f"rows_returned={r.get('rows_returned', '')} rows_filtered={r.get('rows_filtered', '')}"
        )
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_layer_probe(args: argparse.Namespace) -> None:
    statement_timeout_ms = parse_timeout_ms(args.statement_timeout)

    policy_lines = load_policy_lines(Path(args.policy))
    pool_spec = args.policy_pool
    if pool_spec == DEFAULT_POLICY_POOL:
        pool_spec = "1-20"
    policy_pool = parse_policy_pool(pool_spec, len(policy_lines))

    ks = list(args.ks)
    if ks == DEFAULT_KS:
        ks = list(DEFAULT_LAYER_PROBE_KS)
    if not ks:
        raise HarnessError("no K values provided")

    dbs = [str(d).strip() for d in (args.dbs or []) if str(d).strip()]
    if not dbs:
        dbs = [str(args.db).strip()]

    queries = load_queries(Path(args.queries))
    query_ids = args.query_ids if args.query_ids is not None else list(DEFAULT_LAYER_PROBE_QUERY_IDS)
    skip_ids = set(str(x).strip() for x in (args.skip_query_ids or []))
    skip_ids.add("20")
    queries = filter_queries_by_args(queries, query_ids, list(skip_ids))

    if str(args.run_dir).strip():
        run_dir = Path(args.run_dir)
        if not run_dir.is_absolute():
            run_dir = ROOT / run_dir
    else:
        run_dir = ROOT / "logs" / f"layer_probe_{time.strftime('%Y%m%d_%H%M%S')}"
    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = run_dir.name

    layer_csv = run_dir / "layer_probe.csv"
    enabled_base = run_dir / "policies_enabled.txt"
    summary_md = run_dir / "layer_probe_summary.md"

    write_csv_header(layer_csv, LAYER_PROBE_COLUMNS)

    print(f"[layer_probe] run_id={run_id} run_dir={run_dir}")
    print(f"[layer_probe] dbs={dbs} Ks={ks} pool={pool_spec} statement_timeout_ms={statement_timeout_ms}")
    print(f"[layer_probe] queries={[qid for qid, _ in queries]}")

    out_rows: List[Dict[str, str]] = []

    for db in dbs:
        print(f"[db] start db={db}")
        clear_artifacts(db)
        clear_rls_indexes_and_policies(db)
        print_clean_state(db, tag="clean_start")

        for k in ks:
            enabled_ids, enabled = select_enabled_policies(policy_lines, policy_pool, k)
            policy_ids = ",".join(str(x) for x in enabled_ids)
            enabled_path_k = enabled_policy_path_for_k(enabled_base, db, k)
            print(f"[policy_set] db={db} K={k} enabled_ids={enabled_ids}")

            write_enabled_policy_file(enabled, enabled_path_k)

            clear_artifacts(db)
            clear_rls_indexes_and_policies(db)
            print_clean_state(db, tag=f"clean_before_k K={k}")

            try:
                setup_ours_for_k_with_sizes(db, k, enabled_path_k, statement_timeout_ms)
            except Exception as exc:  # noqa: BLE001
                msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:240]
                print(f"[layer_probe] setup_error db={db} K={k} err={msg}")
                for qid, _qsql in queries:
                    row = {
                        "run_id": run_id,
                        "ts": now_ts(),
                        "db": db,
                        "K": str(k),
                        "query_id": str(qid),
                        "policy_total_ms": "",
                        "artifact_load_ms": "",
                        "artifact_parse_ms": "",
                        "atoms_ms": "",
                        "ctid_map_ms": "",
                        "filter_ms": "",
                        "child_exec_ms": "",
                        "ctid_extract_ms": "",
                        "ctid_to_rid_ms": "",
                        "allow_check_ms": "",
                        "projection_ms": "",
                        "rss_mb": "",
                        "rows_filtered": "",
                        "rows_returned": "",
                        "pe_total_ms": "",
                        "pe_load_ms": "",
                        "pe_local_ms": "",
                        "pe_prop_ms": "",
                        "pe_decode_ms": "",
                        "local_stamp_ms": "0.000",
                        "local_bin_ms": "0.000",
                        "local_eval_ms": "0.000",
                        "local_fill_ms": "0.000",
                        "prop_ms_bundle": "0.000",
                        "status": "error",
                        "error_type": "setup_error",
                        "error_msg": msg,
                        "policy_profile_lines": "0",
                        "policy_profile_query_lines": "0",
                        "policy_profile_bundle_lines": "0",
                    }
                    append_csv_row(layer_csv, LAYER_PROBE_COLUMNS, row)
                    out_rows.append(row)
                clear_artifacts(db)
                print_clean_state(db, tag=f"after_setup_error K={k}")
                continue

            for qid, qsql in queries:
                print(f"[progress] db={db} K={k} baseline=ours query={qid}")
                metrics, payload, kv, cnt_pp, notices = run_ours_profile_capture(
                    db,
                    qsql,
                    enabled_path_k,
                    statement_timeout_ms,
                    ours_profile_rescan=False,
                    ours_debug_mode="trace",
                    query_id=qid,
                    profile_k=k,
                    profile_query=qid,
                )

                _ppq_payload, kv_pe, cnt_pe = extract_policy_profile_query(notices)
                cnt_bundle, bundle_agg = extract_policy_profile_bundle_agg(notices)
                load_ms_sum, _load_cnt = extract_policy_load_ms_sum(notices)

                # policy_profile keys
                def g(key: str) -> str:
                    return kv.get(key, "")

                rows_seen = 0
                rows_passed = 0
                try:
                    rows_seen = int(float(g("rows_seen") or 0))
                    rows_passed = int(float(g("rows_passed") or 0))
                except Exception:
                    pass
                rows_filtered = max(0, rows_seen - rows_passed)

                rss_kb = 0
                try:
                    rss_kb = int(float(g("peak_rss_kb_end") or 0))
                except Exception:
                    rss_kb = 0
                if rss_kb <= 0:
                    rss_kb = int(metrics.peak_rss_kb or 0)
                rss_mb = float(rss_kb) / 1024.0 if rss_kb else 0.0

                row = {
                    "run_id": run_id,
                    "ts": now_ts(),
                    "db": db,
                    "K": str(k),
                    "query_id": str(qid),
                    "policy_total_ms": g("policy_total_ms"),
                    "artifact_load_ms": g("artifact_load_ms"),
                    "artifact_parse_ms": g("artifact_parse_ms"),
                    "atoms_ms": g("atoms_ms"),
                    "presence_ms": g("presence_ms"),
                    "project_ms": g("project_ms"),
                    "ctid_map_ms": g("ctid_map_ms"),
                    "filter_ms": g("filter_ms"),
                    "child_exec_ms": g("child_exec_ms"),
                    "ctid_extract_ms": g("ctid_extract_ms"),
                    "ctid_to_rid_ms": g("ctid_to_rid_ms"),
                    "allow_check_ms": g("allow_check_ms"),
                    "projection_ms": g("projection_ms"),
                    "rss_mb": f"{rss_mb:.3f}",
                    "rows_filtered": str(rows_filtered),
                    "rows_returned": str(rows_passed),
                    "pe_total_ms": kv_pe.get("total_ms", ""),
                    "pe_load_ms": f"{load_ms_sum:.3f}" if load_ms_sum > 0 else "",
                    "pe_local_ms": kv_pe.get("local_ms", ""),
                    "pe_prop_ms": kv_pe.get("prop_ms", ""),
                    "pe_decode_ms": kv_pe.get("decode_ms", ""),
                    "local_stamp_ms": f"{bundle_agg['local_stamp_ms']:.3f}",
                    "local_bin_ms": f"{bundle_agg['local_bin_ms']:.3f}",
                    "local_eval_ms": f"{bundle_agg['local_eval_ms']:.3f}",
                    "local_fill_ms": f"{bundle_agg['local_fill_ms']:.3f}",
                    "prop_ms_bundle": f"{bundle_agg['prop_ms_bundle']:.3f}",
                    "status": metrics.status,
                    "error_type": metrics.error_type,
                    "error_msg": metrics.error_msg,
                    "policy_profile_lines": str(cnt_pp),
                    "policy_profile_query_lines": str(cnt_pe),
                    "policy_profile_bundle_lines": str(cnt_bundle),
                }

                append_csv_row(layer_csv, LAYER_PROBE_COLUMNS, row)
                out_rows.append(row)

            clear_artifacts(db)
            print_clean_state(db, tag=f"after_ours_drop K={k}")

        print(f"[db] done db={db}")

    write_layer_probe_summary(out_rows, summary_md)
    print(f"[done] run_dir={run_dir}")
    print(f"[done] layer_probe_csv={layer_csv}")
    print(f"[done] layer_probe_summary={summary_md}")


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
    enabled_path_k = enabled_policy_path_for_k(enabled_path, db, k)
    policy_ids = ",".join(str(x) for x in enabled_ids)
    print(f"[smoke] Running K={k} (pool-full), queries {{3,13}}, hot-runs=2")
    print(f"[smoke] enabled_ids={enabled_ids}")
    write_enabled_policy_file(enabled, enabled_path_k)
    setup_ours_for_k(db, k, enabled_path_k, statement_timeout_ms)
    apply_rls_policies_for_k(db, enabled)
    create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)

    qmap = {qid: q for qid, q in queries}
    for qid in ["3", "13"]:
        if qid not in qmap:
            raise HarnessError(f"smoke query id {qid} missing from query file")
        q = qmap[qid]
        cold_o, hot_o = run_query_series(db, "ours", q, 2, enabled_path_k, statement_timeout_ms, query_id=qid)
        cold_r, hot_r = run_query_series(db, "rls_with_index", q, 2, enabled_path_k, statement_timeout_ms, query_id=qid)
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

        ours_count = count_query(db, "ours", q, enabled_path_k, statement_timeout_ms)
        rls_count = count_query(db, "rls_with_index", q, enabled_path_k, statement_timeout_ms)
        print(f"[smoke] K={k} q={qid} policy_ids={policy_ids} ours_count={ours_count} rls_count={rls_count}")
        if ours_count != rls_count:
            raise HarnessError(f"smoke failed: count mismatch for q={qid} ours={ours_count} rls={rls_count}")

    prof_metrics, prof_payload, prof_kv, prof_cnt, _notices = run_ours_profile_capture(
        db, qmap["3"], enabled_path_k, statement_timeout_ms, query_id="3"
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
    if hot_runs < 1 or hot_runs > 5:
        raise HarnessError("--hot-runs must be in 1..5")
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
        clear_artifacts(db)
        clear_rls_indexes_and_policies(db)
        print(f"[phase] db={db} clean_start artifacts=0 indexes=0")
        for k in args.ks:
            enabled_ids, enabled = select_enabled_policies(policy_lines, policy_pool, k)
            enabled_path_k = enabled_policy_path_for_k(enabled_path, db, k)
            policy_ids = ",".join(str(x) for x in enabled_ids)
            print(f"[policy_set] db={db} K={k} enabled_ids={enabled_ids}")
            write_enabled_policy_file(enabled, enabled_path_k)
            clear_artifacts(db)
            clear_rls_indexes_and_policies(db)
            print(f"[phase] db={db} K={k} clean_before_k artifacts=0 indexes=0")

            correctness_queries = choose_correctness_queries(queries, args.correctness_sample, rng)
            correctness_qids = {qid for qid, _ in correctness_queries}
            ours_counts: Dict[str, Optional[int]] = {}
            rls_counts: Dict[str, Optional[int]] = {}
            ours_count_err: Dict[str, str] = {}
            rls_count_err: Dict[str, str] = {}
            print(f"[correctness_sample] db={db} K={k} queries={[qid for qid, _ in correctness_queries]}")

            # OURS phase: build artifacts -> run all queries.
            ours_setup_ms, ours_disk = setup_ours_for_k(db, k, enabled_path_k, statement_timeout_ms)
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

            for qid, qsql in queries:
                print(f"[progress] db={db} K={k} baseline=ours query={qid}")
                cold, hots = run_query_series(
                    db, "ours", qsql, hot_runs, enabled_path_k, statement_timeout_ms, query_id=qid
                )
                row = build_time_row(db, k, policy_ids, "ours", qid, cold, hots, expected_hot=hot_runs)
                append_csv_row(times_csv, TIMES_COLUMNS, row)

                prof_metrics, prof_payload, prof_kv, prof_cnt, notices = run_ours_profile_capture(
                    db,
                    qsql,
                    enabled_path_k,
                    statement_timeout_ms,
                    ours_profile_rescan=bool(args.ours_profile_rescan),
                    ours_debug_mode=str(args.profile_debug_mode),
                    query_id=qid,
                )
                prow = build_profile_row(
                    db, k, policy_ids, qid, prof_metrics, prof_payload, prof_kv, prof_cnt
                )
                append_csv_row(profile_csv, PROFILE_COLUMNS, prow)
                if args.dump_ours_notices and notices:
                    out_path = profile_csv.parent / f"ours_notices_db={db}_K={k}_q={qid}.txt"
                    out_path.write_text("\n".join(notices) + "\n", encoding="utf-8")

                if qid in correctness_qids:
                    fb = count_fallback_sql(qid)
                    try:
                        if fb is not None:
                            oc = count_query_sql(db, "ours", fb, enabled_path_k, statement_timeout_ms)
                        else:
                            oc = count_query(db, "ours", qsql, enabled_path_k, statement_timeout_ms)
                        ours_counts[qid] = oc
                    except Exception as exc:  # noqa: BLE001
                        ours_counts[qid] = None
                        ours_count_err[qid] = str(exc).replace("\n", " ")[:160]

            clear_artifacts(db)
            print(f"[phase] db={db} K={k} artifacts_dropped=1")

            # RLS phase: build indexes -> run all queries.
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

            for qid, qsql in queries:
                print(f"[progress] db={db} K={k} baseline=rls_with_index query={qid}")
                cold, hots = run_query_series(
                    db, "rls_with_index", qsql, hot_runs, enabled_path_k, statement_timeout_ms, query_id=qid
                )
                row = build_time_row(db, k, policy_ids, "rls_with_index", qid, cold, hots, expected_hot=hot_runs)
                append_csv_row(times_csv, TIMES_COLUMNS, row)

                if qid in correctness_qids:
                    fb = count_fallback_sql(qid)
                    try:
                        if fb is not None:
                            rc = count_query_sql(db, "rls_with_index", fb, enabled_path_k, statement_timeout_ms)
                        else:
                            rc = count_query(db, "rls_with_index", qsql, enabled_path_k, statement_timeout_ms)
                        rls_counts[qid] = rc
                    except Exception as exc:  # noqa: BLE001
                        rls_counts[qid] = None
                        rls_count_err[qid] = str(exc).replace("\n", " ")[:160]

            clear_rls_indexes_and_policies(db)
            print(f"[phase] db={db} K={k} indexes_dropped=1")

            for qid, qsql in correctness_queries:
                if qid not in ours_counts or ours_counts[qid] is None:
                    cr = {
                        "db": db,
                        "K": str(k),
                        "query_id": qid,
                        "correctness": "skip",
                        "ours_count": "",
                        "rls_count": "",
                        "reason": f"ours_count_failed: {ours_count_err.get(qid, 'missing ours count')}",
                    }
                elif qid not in rls_counts or rls_counts[qid] is None:
                    cr = {
                        "db": db,
                        "K": str(k),
                        "query_id": qid,
                        "correctness": "skip",
                        "ours_count": str(ours_counts[qid]),
                        "rls_count": "",
                        "reason": f"rls_count_failed: {rls_count_err.get(qid, 'missing rls count')}",
                    }
                else:
                    oc = int(ours_counts[qid])
                    rc = int(rls_counts[qid])
                    cr = {
                        "db": db,
                        "K": str(k),
                        "query_id": qid,
                        "correctness": "1" if oc == rc else "0",
                        "ours_count": str(oc),
                        "rls_count": str(rc),
                        "reason": "" if oc == rc else "count_mismatch",
                    }
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
    if args.smoke_only and not args.smoke_check:
        raise HarnessError("--smoke-only requires --smoke-check")

    # Allow overriding .so locations (useful when the DB backend can't traverse the harness user's $HOME).
    global CUSTOM_FILTER_SO, ARTIFACT_BUILDER_SO
    CUSTOM_FILTER_SO = str(args.custom_filter_so)
    ARTIFACT_BUILDER_SO = str(args.artifact_builder_so)

    if args.layer_probe:
        run_layer_probe(args)
        return

    if args.matrix_tpch_scale:
        run_matrix_tpch_scale(args)
        return

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
        if args.smoke_only or not args.run:
            return

    if not args.run:
        raise HarnessError("Use --run")

    run_experiment(args)


if __name__ == "__main__":
    try:
        main()
    except HarnessError as exc:
        raise SystemExit(f"Error: {exc}")
