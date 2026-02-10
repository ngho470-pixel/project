#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
import time
import threading
from typing import Dict, Iterable, List, Tuple

import psycopg2
from psycopg2 import errors, extensions


HOST = "localhost"
PORT = 5432

DEFAULT_DBS = ["tpch0_1", "tpch1"]
BASELINE_ORDER = [
    "nopolicy",
    "rls_with_index",
    "sieve_with_index",
    "rls_no_index",
    "sieve_no_index",
    "view_security_barrier",
]

SESSION_SETTINGS: Tuple[str, ...] = (
    "SET max_parallel_workers_per_gather = 0;",
    "SET statement_timeout = '5min';",
)

ROLE_CONFIG: Dict[str, Dict[str, object]] = {
    "postgres": {
        "user": "postgres",
        "password": "12345",
    },
    "rls_user": {
        "user": "rls_user",
        "password": "secret",
    },
}

BASE_COLUMNS = [
    "row_type",
    "baseline",
    "db",
    "query_id",
    "trial_type",
    "trial_idx",
    "exec_role",
    "elapsed_ms",
    "rewrite_ms",
    "peak_mem_mb",
    "mem_delta_mb",
    "setup_ms",
    "disk_overhead_bytes",
    "status",
    "error_type",
]

CSV_COLUMNS = BASE_COLUMNS + [
    "dataset",
    "policy_id",
    "num_policies",
    "query_num_tables",
    "query_num_joins",
    "query_num_predicates",
    "query_complexity",
    "policy_num_predicates",
    "policy_join_depth",
    "policy_complexity",
    "db_scale",
]

VIEW_NAME = "orders_auth"
VIEW_CANONICAL_SQL = (
    "SELECT o.* FROM orders o "
    "WHERE EXISTS (SELECT 1 FROM customer c "
    "WHERE c.c_custkey = o.o_custkey AND c.c_mktsegment = 'AUTOMOBILE');"
)

DB_SCALE = {"tpch0_1": 0.1, "tpch1": 1.0}


class HarnessError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment harness for PostgreSQL baselines"
    )
    parser.add_argument(
        "--dbs",
        nargs="*",
        default=DEFAULT_DBS,
        help="Databases to target (default: tpch0_1 tpch1 )",
    )
    parser.add_argument(
        "--queries",
        default=os.path.join(os.path.dirname(__file__), "queries.txt"),
        help="Path to queries.txt",
    )
    parser.add_argument(
        "--policy",
        default=os.path.join(os.path.dirname(__file__), "policy.txt"),
        help="Path to policy.txt",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(__file__), "runs_stage4.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--sieve_cmd",
        default=None,
        help="Command to invoke Sieve rewriter CLI (default: java -jar <sieve_dir>/target/sieve-rewriter.jar)",
    )
    parser.add_argument(
        "--sieve_dir",
        default=os.path.join(os.path.dirname(__file__), "Sieve-master"),
        help="Directory containing Sieve repo (used if --sieve_cmd not set)",
    )
    return parser.parse_args()


def load_queries(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip()]

    queries: List[str] = []
    for line in lines:
        # Strip optional numeric prefix like "1." or "Q1:" while keeping SQL intact.
        sql_text = re.sub(r"^\s*[A-Za-z0-9_]+[.:]\s*", "", line, count=1)
        queries.append(sql_text)

    if len(queries) != 3:
        raise HarnessError(f"Expected 3 queries in {path}, found {len(queries)}")

    return queries


def load_policy(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        contents = f.read().lower()
    if "orders" not in contents or "automobile" not in contents:
        raise HarnessError(
            "Policy file does not contain expected orders + 'AUTOMOBILE' condition"
        )
    return VIEW_CANONICAL_SQL


def connect(dbname: str, role: str) -> extensions.connection:
    role_cfg = ROLE_CONFIG[role]
    conn = psycopg2.connect(
        host=HOST,
        port=PORT,
        dbname=dbname,
        user=role_cfg["user"],
        password=role_cfg["password"],
    )
    conn.autocommit = True
    return conn


def apply_session_settings(cur: extensions.cursor) -> None:
    for stmt in SESSION_SETTINGS:
        cur.execute(stmt)


def create_indexes(dbname: str, record_time: bool) -> Tuple[float, int]:
    elapsed_ms = 0.0
    disk_bytes = 0
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            start = time.perf_counter()
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_orders_o_custkey ON orders(o_custkey);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_customer_c_custkey_mktsegment "
                "ON customer(c_custkey, c_mktsegment);"
            )
            if record_time:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
            size_query = (
                "SELECT "
                "COALESCE(pg_total_relation_size(to_regclass('idx_orders_o_custkey')), 0) + "
                "COALESCE(pg_total_relation_size(to_regclass('idx_customer_c_custkey_mktsegment')), 0);"
            )
            cur.execute(size_query)
            disk_bytes = int(cur.fetchone()[0] or 0)
    return elapsed_ms, disk_bytes


def drop_indexes(dbname: str) -> None:
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            cur.execute("DROP INDEX IF EXISTS idx_orders_o_custkey;")
            cur.execute("DROP INDEX IF EXISTS idx_customer_c_custkey_mktsegment;")


def create_security_barrier_view(dbname: str, view_sql: str, record_time: bool) -> float:
    elapsed_ms = 0.0
    ddl = (
        f"CREATE OR REPLACE VIEW {VIEW_NAME} "
        f"WITH (security_barrier = true) AS {view_sql}"
    )
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            start = time.perf_counter()
            cur.execute(ddl)
            cur.execute(f"GRANT SELECT ON {VIEW_NAME} TO rls_user;")
            if record_time:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms


def disable_orders_rls(dbname: str) -> None:
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE orders DISABLE ROW LEVEL SECURITY;")


def enable_orders_rls(dbname: str) -> None:
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE orders ENABLE ROW LEVEL SECURITY;")


def rewrite_query_for_view(query_sql: str) -> str:
    patterns = [
        (r"(?i)\bFROM\s+orders\b", "FROM orders_auth"),
        (r"(?i)\bJOIN\s+orders\b", "JOIN orders_auth"),
    ]
    rewritten = query_sql
    for pattern, repl in patterns:
        rewritten = re.sub(pattern, repl, rewritten)
    return rewritten


def call_sieve_wrapper(
    cmd_base: List[str], dbname: str, query_sql: str, policy_path: str
) -> Tuple[str, float]:
    jdbc_url = f"jdbc:postgresql://{HOST}:{PORT}/{dbname}"
    cmd = cmd_base + [
        "--jdbc",
        jdbc_url,
        "--user",
        ROLE_CONFIG["postgres"]["user"],
        "--password",
        ROLE_CONFIG["postgres"]["password"],
        "--policy",
        policy_path,
        "--query",
        query_sql,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise HarnessError(f"Sieve wrapper failed: {proc.stderr.strip()}")
    try:
        payload = json.loads(proc.stdout.strip())
    except Exception as exc:
        raise HarnessError(f"Sieve wrapper returned invalid JSON ({exc}): {proc.stdout!r}")
    if payload.get("error"):
        raise HarnessError(f"Sieve wrapper error: {payload.get('error')}")
    rewritten_sql = payload.get("rewritten_sql")
    if not rewritten_sql:
        raise HarnessError("Sieve wrapper did not provide rewritten_sql")
    rewrite_ms = float(payload.get("rewrite_ms", 0.0))
    return rewritten_sql, rewrite_ms


def enable_custom_filter(cur: extensions.cursor) -> None:
    so_path = os.environ.get("CUSTOM_FILTER_SO")
    if not so_path:
        so_path = os.path.join(os.path.dirname(__file__), "custom_filter", "custom_filter.so")
    cur.execute("LOAD %s;", (so_path,))
    cur.execute("SET custom_filter.enabled = on;")


def get_files_table_size(dbname: str) -> int:
    with connect(dbname, "postgres") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_total_relation_size('public.files'::regclass);")
            res = cur.fetchone()
            if res is None or res[0] is None:
                raise HarnessError("files table size not available")
            return int(res[0])


def query_stats(query_sql: str) -> Tuple[int, int, int]:
    # Very small heuristic for current workload.
    tables = len(re.findall(r"(?i)\bFROM\b", query_sql)) + len(
        re.findall(r"(?i)\bJOIN\b", query_sql)
    )
    joins = len(re.findall(r"(?i)\bJOIN\b", query_sql))
    predicates = len(re.findall(r"[<>=]", query_sql))
    return tables, joins, predicates


def row_metadata(db: str, baseline: str, query_id: str, query_sql: str) -> Dict[str, object]:
    if query_id == "__setup__":
        tables = joins = predicates = 0
    else:
        tables, joins, predicates = query_stats(query_sql)
    query_complexity = 3 * joins + 2 * tables + predicates
    policy_id = "none" if baseline == "nopolicy" else "P1"
    num_policies = 0 if baseline == "nopolicy" else 1
    policy_num_predicates = 0 if baseline == "nopolicy" else 2
    policy_join_depth = 0 if baseline == "nopolicy" else 1
    policy_complexity = policy_num_predicates if baseline != "nopolicy" else 0
    return {
        "dataset": db,
        "policy_id": policy_id,
        "num_policies": num_policies,
        "query_num_tables": tables,
        "query_num_joins": joins,
        "query_num_predicates": predicates,
        "query_complexity": query_complexity,
        "policy_num_predicates": policy_num_predicates,
        "policy_join_depth": policy_join_depth,
        "policy_complexity": policy_complexity,
        "db_scale": DB_SCALE.get(db, 0.0),
    }


def read_mem_kb(pid: int) -> Tuple[int, int]:
    rss_kb = 0
    hwm_kb = 0
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        rss_kb = int(parts[1])
                elif line.startswith("VmHWM:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        hwm_kb = int(parts[1])
    except Exception:
        return 0, 0
    return rss_kb, hwm_kb


def run_single_execution(
    cur: extensions.cursor, query_sql: str, pid: int = None
) -> Tuple[float, int, str, float, float]:
    peak_rss_kb = 0
    peak_hwm_kb = 0
    start_hwm_kb = 0
    stop_evt = None
    sampler = None
    if pid:
        stop_evt = threading.Event()
        _, start_hwm_kb = read_mem_kb(pid)

        def sample():
            nonlocal peak_rss_kb, peak_hwm_kb
            while not stop_evt.is_set():
                rss_kb, hwm_kb = read_mem_kb(pid)
                if rss_kb > peak_rss_kb:
                    peak_rss_kb = rss_kb
                if hwm_kb > peak_hwm_kb:
                    peak_hwm_kb = hwm_kb
                stop_evt.wait(0.01)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()

    start = time.perf_counter()
    status = 1
    error_type = ""
    try:
        cur.execute(query_sql)
        # Fetch to ensure full execution before timing stops.
        cur.fetchall()
    except (errors.QueryCanceled, extensions.QueryCanceledError):
        status = 0
        error_type = "timeout"
    except Exception:
        status = 0
        error_type = "db_error"
    finally:
        if stop_evt:
            stop_evt.set()
        if sampler:
            sampler.join(timeout=0.5)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    peak_kb = peak_hwm_kb if peak_hwm_kb else peak_rss_kb
    peak_mem_mb = (peak_kb / 1024.0) if peak_kb else 0.0
    mem_delta_mb = 0.0
    if peak_hwm_kb and start_hwm_kb and peak_hwm_kb >= start_hwm_kb:
        mem_delta_mb = (peak_hwm_kb - start_hwm_kb) / 1024.0
    return elapsed_ms, status, error_type, peak_mem_mb, mem_delta_mb


def run_trials_for_query(
    dbname: str,
    baseline: str,
    query_id: str,
    query_sql: str,
    exec_role: str,
    rewrite_ms_for_cold: float = 0.0,
    session_setup=None,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    with connect(dbname, exec_role) as conn:
        with conn.cursor() as cur:
            if session_setup:
                session_setup(cur)
            apply_session_settings(cur)
            pid = cur.connection.get_backend_pid()
            for idx in range(6):
                trial_type = "cold" if idx == 0 else "hot"
                print(f"{dbname} | {baseline} | {query_id} | {trial_type} {idx}")
                elapsed_ms, status, error_type, peak_mem_mb, mem_delta_mb = run_single_execution(
                    cur, query_sql, pid=pid
                )
                rewrite_ms = rewrite_ms_for_cold if idx == 0 else 0.0
                meta = row_metadata(dbname, baseline, query_id, query_sql)
                rows.append(
                    {
                        "row_type": "trial",
                        "baseline": baseline,
                        "db": dbname,
                        "query_id": query_id,
                        "trial_type": trial_type,
                        "trial_idx": idx,
                        "exec_role": exec_role,
                        "elapsed_ms": f"{elapsed_ms:.3f}",
                        "rewrite_ms": f"{rewrite_ms:.3f}",
                        "peak_mem_mb": f"{peak_mem_mb:.3f}",
                        "mem_delta_mb": f"{mem_delta_mb:.3f}",
                        "setup_ms": "0",
                        "disk_overhead_bytes": "0",
                        "status": status,
                        "error_type": error_type,
                        **meta,
                    }
                )
    return rows


def write_csv(path: str, rows: Iterable[Dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=BASE_COLUMNS)
        writer.writeheader()
        for row in rows:
            base_row = {k: row.get(k, "") for k in BASE_COLUMNS}
            writer.writerow(base_row)


def write_stage5_csv(path: str, rows: Iterable[Dict[str, object]]) -> None:
    # CSV_COLUMNS already include new fields.
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize_trials(rows: List[Dict[str, object]], out_path: str) -> None:
    import math

    allowed_dbs = {"tpch0_1", "tpch1"}

    setups: Dict[Tuple[str, str], Dict[str, object]] = {}
    for row in rows:
        if row["row_type"] == "setup":
            setups[(row["db"], row["baseline"])] = row

    summaries: List[Dict[str, object]] = []
    by_key: Dict[Tuple[str, str, str], List[Dict[str, object]]] = {}
    for row in rows:
        if row["row_type"] != "trial":
            continue
        if row["db"] not in allowed_dbs:
            continue
        key = (row["db"], row["baseline"], row["query_id"])
        by_key.setdefault(key, []).append(row)

    for (db, baseline, qid), trials in by_key.items():
        cold = [t for t in trials if t["trial_type"] == "cold"][0]
        hot = [t for t in trials if t["trial_type"] == "hot"]
        hot_vals = [float(t["elapsed_ms"]) for t in hot]
        hot_peaks = [float(t["peak_mem_mb"]) for t in hot]
        mean_hot = sum(hot_vals) / len(hot_vals)
        var_hot = sum((v - mean_hot) ** 2 for v in hot_vals) / len(hot_vals)
        std_hot = math.sqrt(var_hot)
        setup = setups.get((db, baseline), {})
        summaries.append(
            {
                "db": db,
                "db_scale": cold["db_scale"],
                "dataset": cold["dataset"],
                "baseline": baseline,
                "exec_role": cold["exec_role"],
                "query_id": qid,
                "cold_ms": float(cold["elapsed_ms"]),
                "hot_ms": mean_hot,
                "hot_std_ms": std_hot,
                "rewrite_ms": float(cold.get("rewrite_ms", 0)),
                "setup_ms": float(setup.get("setup_ms", 0)),
                "disk_overhead_bytes": int(setup.get("disk_overhead_bytes", 0)),
                "hot_peak_mem_mb": max(hot_peaks) if hot_peaks else 0.0,
                "query_num_tables": cold["query_num_tables"],
                "query_num_joins": cold["query_num_joins"],
                "query_num_predicates": cold["query_num_predicates"],
                "query_complexity": cold["query_complexity"],
                "policy_id": cold["policy_id"],
                "num_policies": cold["num_policies"],
                "policy_num_predicates": cold["policy_num_predicates"],
                "policy_join_depth": cold["policy_join_depth"],
                "policy_complexity": cold["policy_complexity"],
            }
        )

    fieldnames = [
        "db",
        "db_scale",
        "dataset",
        "baseline",
        "exec_role",
        "query_id",
        "cold_ms",
        "hot_ms",
        "hot_std_ms",
        "rewrite_ms",
        "setup_ms",
        "disk_overhead_bytes",
        "hot_peak_mem_mb",
        "query_num_tables",
        "query_num_joins",
        "query_num_predicates",
        "query_complexity",
        "policy_id",
        "num_policies",
        "policy_num_predicates",
        "policy_join_depth",
        "policy_complexity",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summaries:
            writer.writerow(row)


def generate_plots(runs_path: str, summary_path: str, out_dir: str) -> List[str]:
    import matplotlib.pyplot as plt
    import pandas as pd
    os.makedirs(out_dir, exist_ok=True)
    plots = []

    runs = pd.read_csv(runs_path)
    summary = pd.read_csv(summary_path)

    order_baseline = [
        "nopolicy",
        "rls_with_index",
        "rls_no_index",
        "view_security_barrier",
        "sieve_with_index",
        "sieve_no_index",
        "ours",
    ]

    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2"]
    scales = [0.1, 1.0]

    # Combined time boxplot (scales on x, 7 boxes per scale)
    fig, ax = plt.subplots(figsize=(10, 5))
    data = []
    positions = []
    labels = []
    gap = len(order_baseline) + 1
    for i, scale in enumerate(scales):
        df = summary[summary["db_scale"] == scale]
        for j, bl in enumerate(order_baseline):
            vals = df[df["baseline"] == bl]["hot_ms"]
            if not vals.empty:
                data.append(vals)
                positions.append(i * gap + j + 1)
            else:
                data.append(pd.Series([], dtype=float))
                positions.append(i * gap + j + 1)
            labels.append(bl)
    bp = ax.boxplot(data, positions=positions, patch_artist=True)
    for patch_idx, patch in enumerate(bp["boxes"]):
        color = colors[patch_idx % len(colors)]
        patch.set_facecolor(color)
    ax.set_yscale("log")
    ax.set_ylabel("hot_ms (ms, log scale)")
    ax.set_xlabel("scale")
    ax.set_title("Hot runtime distribution across queries")
    scale_positions = [(i * gap) + (len(order_baseline) + 1) / 2 for i in range(len(scales))]
    ax.set_xticks(scale_positions)
    ax.set_xticklabels([f"SF{scale}" for scale in scales])
    legend_patches = [plt.Rectangle((0, 0), 1, 1, facecolor=colors[i], edgecolor="black") for i in range(len(order_baseline))]
    ax.legend(legend_patches, order_baseline, title="baseline", bbox_to_anchor=(1.02, 1), loc="upper left")
    fname = os.path.join(out_dir, "time_hot_combined.png")
    fig.tight_layout()
    fig.savefig(fname, bbox_inches="tight")
    plt.close(fig)
    plots.append(fname)

    # Combined memory boxplot
    fig, ax = plt.subplots(figsize=(10, 5))
    data = []
    positions = []
    for i, scale in enumerate(scales):
        df = summary[summary["db_scale"] == scale]
        for j, bl in enumerate(order_baseline):
            vals = df[df["baseline"] == bl]["hot_peak_mem_mb"]
            data.append(vals if not vals.empty else pd.Series([], dtype=float))
            positions.append(i * gap + j + 1)
    bp = ax.boxplot(data, positions=positions, patch_artist=True)
    for patch_idx, patch in enumerate(bp["boxes"]):
        color = colors[patch_idx % len(colors)]
        patch.set_facecolor(color)
    ax.set_yscale("log")
    ax.set_ylabel("hot_peak_mem_mb (MB, log)")
    ax.set_yticks([1e1, 5e1, 1e2, 2e2])
    ax.set_yticklabels([r"$10^{1}$",r"$5\times10^{1}$", r"$10^{2}$", r"$2\times10^{2}$"])
    ax.set_xlabel("scale")
    ax.set_title("Hot peak memory distribution across queries")
    ax.set_xticks(scale_positions)
    ax.set_xticklabels([f"SF{scale}" for scale in scales])
    legend_patches = [plt.Rectangle((0, 0), 1, 1, facecolor=colors[i], edgecolor="black") for i in range(len(order_baseline))]
    ax.legend(legend_patches, order_baseline, title="baseline", bbox_to_anchor=(1.02, 1), loc="upper left")
    fname = os.path.join(out_dir, "mem_hot_peak_combined.png")
    fig.tight_layout()
    fig.savefig(fname, bbox_inches="tight")
    plt.close(fig)
    plots.append(fname)

    # Disk overhead plot (setup info)
    disk_df = summary[
        summary["baseline"].isin(["rls_with_index", "sieve_with_index", "ours"])
    ]
    fig, ax = plt.subplots(figsize=(7, 4))
    x_ticks = [0, 1]
    x_labels = ["SF0.1", "SF1"]
    width = 0.2
    bases = ["rls_with_index", "sieve_with_index", "ours"]
    colors_disk = ["#1f77b4", "#ff7f0e", "#2ca02c"]
    for i, bl in enumerate(bases):
        vals = []
        for scale in [0.1, 1.0]:
            sub = disk_df[(disk_df["baseline"] == bl) & (disk_df["db_scale"] == scale)]
            vals.append(sub["disk_overhead_bytes"].iloc[0] if not sub.empty else 0)
        positions = [p + (i - 1) * width for p in x_ticks]
        ax.bar(positions, vals, width=width, label=bl, color=colors_disk[i])
    center_positions = [p for p in x_ticks]
    ax.set_xticks(center_positions)
    ax.set_xticklabels(x_labels)
    ax.set_yscale("log")
    ax.yaxis.set_major_locator(plt.LogLocator(base=10))
    ax.yaxis.set_minor_locator(plt.LogLocator(base=10, subs=range(1, 10)))
    ax.yaxis.set_minor_formatter(plt.NullFormatter())
    ax.set_yticks([1e5, 1e6, 1e7, 1e8])
    ax.set_yticklabels([r"$10^{5}$", r"$10^{6}$", r"$10^{7}$", r"$10^{8}$"])

    ax.set_ylabel("disk_overhead_bytes")
    ax.set_xlabel("scale")
    ax.set_title("Disk overhead by scale and baseline")
    ax.legend(title="baseline")
    ax.grid(False)
    fname = os.path.join(out_dir, "disk_overhead_bytes.png")
    fig.tight_layout()
    fig.savefig(fname, bbox_inches="tight")
    plt.close(fig)
    plots.append(fname)

    # Rewrite overhead plot
    rew_df = summary[
        summary["baseline"].isin(["sieve_with_index", "sieve_no_index"])
    ]
    fig, ax = plt.subplots(figsize=(6, 4))
    for bl in ["sieve_with_index", "sieve_no_index"]:
        vals = []
        for scale in [0.1, 1.0]:
            sub = rew_df[(rew_df["baseline"] == bl) & (rew_df["db_scale"] == scale)]
            vals.append(sub["rewrite_ms"].mean() if not sub.empty else 0)
        ax.plot([0.1, 1.0], vals, marker="o", label=bl)
    ax.set_xticks([0.1, 1.0])
    ax.set_xticklabels(["SF0.1", "SF1"])
    ax.set_ylabel("rewrite_ms (ms)")
    ax.set_title("Sieve rewrite overhead by scale")
    ax.legend()
    fname = os.path.join(out_dir, "rewrite_overhead.png")
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plots.append(fname)

    return plots


def main() -> None:
    args = parse_args()
    queries = load_queries(args.queries)
    policy_sql = load_policy(args.policy)
    sieve_cmd_base = (
        (
            ["java", "-jar", os.path.join(args.sieve_dir, "target", "sieve-rewriter.jar")]
            if args.sieve_cmd is None
            else shlex.split(args.sieve_cmd)
        )
    )
    rows: List[Dict[str, object]] = []

    for dbname in args.dbs:
        try:
            enable_orders_rls(dbname)
        except Exception as exc:
            print(f"{dbname} | init | failed to ensure RLS enabled: {exc}")
        # Baseline A: nopolicy
        rows.append(
            {
                "row_type": "setup",
                "baseline": "nopolicy",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": "0",
                "disk_overhead_bytes": 0,
                "status": 1,
                "error_type": "",
                **row_metadata(dbname, "nopolicy", "__setup__", ""),
            }
        )
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            rows.extend(
                run_trials_for_query(
                    dbname=dbname,
                    baseline="nopolicy",
                    query_id=query_id,
                    query_sql=query_sql,
                    exec_role="postgres",
                    rewrite_ms_for_cold=0.0,
                )
            )

        # Phase B: create indexes once
        try:
            index_build_ms, disk_bytes = create_indexes(dbname, record_time=True)
            index_status = 1
            index_error = ""
        except Exception as exc:
            index_build_ms = 0.0
            disk_bytes = 0
            index_status = 0
            index_error = "db_error"
            print(f"{dbname} | index build failed: {exc}")

        # Setup for rls_with_index and sieve_with_index
        rows.append(
            {
                "row_type": "setup",
                "baseline": "rls_with_index",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": "0",
                "disk_overhead_bytes": disk_bytes,
                "status": index_status,
                "error_type": index_error,
                **row_metadata(dbname, "rls_with_index", "__setup__", ""),
            }
        )
        rows.append(
            {
                "row_type": "setup",
                "baseline": "sieve_with_index",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": f"{index_build_ms:.3f}",
                "disk_overhead_bytes": disk_bytes,
                "status": index_status,
                "error_type": index_error,
                **row_metadata(dbname, "sieve_with_index", "__setup__", ""),
            }
        )

        # Baseline C: rls_with_index
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            rows.extend(
                run_trials_for_query(
                    dbname=dbname,
                    baseline="rls_with_index",
                    query_id=query_id,
                    query_sql=query_sql,
                    exec_role="rls_user",
                    rewrite_ms_for_cold=0.0,
                )
            )

        # Baseline D: sieve_with_index
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            try:
                rewritten_sql, rewrite_ms = call_sieve_wrapper(
                    sieve_cmd_base, dbname, query_sql, args.policy
                )
                status_ok = True
            except Exception as exc:
                print(f"{dbname} | sieve_with_index | {query_id} | rewrite failed: {exc}")
                rewritten_sql = query_sql
                rewrite_ms = 0.0
                status_ok = False
            rows.extend(
                run_trials_for_query(
                    dbname=dbname,
                    baseline="sieve_with_index",
                    query_id=query_id,
                    query_sql=rewritten_sql,
                    exec_role="postgres",
                    rewrite_ms_for_cold=rewrite_ms,
                )
            )
            if not status_ok:
                # Mark rows with failure
                for row in rows[-6:]:
                    row["status"] = 0
                    row["error_type"] = "db_error"

        # Phase E: drop indexes once
        try:
            drop_indexes(dbname)
            drop_status = 1
            drop_error = ""
        except Exception as exc:
            drop_status = 0
            drop_error = "db_error"
            print(f"{dbname} | drop indexes failed: {exc}")

        # Setup for rls_no_index and sieve_no_index
        rows.append(
            {
                "row_type": "setup",
                "baseline": "rls_no_index",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": "0",
                "disk_overhead_bytes": 0,
                "status": drop_status,
                "error_type": drop_error,
                **row_metadata(dbname, "rls_no_index", "__setup__", ""),
            }
        )
        rows.append(
            {
                "row_type": "setup",
                "baseline": "sieve_no_index",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": "0",
                "disk_overhead_bytes": 0,
                "status": drop_status,
                "error_type": drop_error,
                **row_metadata(dbname, "sieve_no_index", "__setup__", ""),
            }
        )

        # Baseline F: rls_no_index
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            rows.extend(
                run_trials_for_query(
                    dbname=dbname,
                    baseline="rls_no_index",
                    query_id=query_id,
                    query_sql=query_sql,
                    exec_role="rls_user",
                    rewrite_ms_for_cold=0.0,
                )
            )

        # Baseline G: sieve_no_index
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            try:
                rewritten_sql, rewrite_ms = call_sieve_wrapper(
                    sieve_cmd_base, dbname, query_sql, args.policy
                )
                status_ok = True
            except Exception as exc:
                print(f"{dbname} | sieve_no_index | {query_id} | rewrite failed: {exc}")
                rewritten_sql = query_sql
                rewrite_ms = 0.0
                status_ok = False
            rows.extend(
                run_trials_for_query(
                    dbname=dbname,
                    baseline="sieve_no_index",
                    query_id=query_id,
                    query_sql=rewritten_sql,
                    exec_role="postgres",
                    rewrite_ms_for_cold=rewrite_ms,
                )
            )
            if not status_ok:
                for row in rows[-6:]:
                    row["status"] = 0
                    row["error_type"] = "db_error"

        # Baseline H: view_security_barrier
        try:
            view_setup_ms = create_security_barrier_view(
                dbname, policy_sql, record_time=True
            )
            view_status = 1
            view_error = ""
        except Exception as exc:
            view_setup_ms = 0.0
            view_status = 0
            view_error = "db_error"
            print(f"{dbname} | view setup failed: {exc}")
        rows.append(
            {
                "row_type": "setup",
                "baseline": "view_security_barrier",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": f"{view_setup_ms:.3f}",
                "disk_overhead_bytes": 0,
                "status": view_status,
                "error_type": view_error,
                **row_metadata(dbname, "view_security_barrier", "__setup__", ""),
            }
        )
        for idx, query_sql in enumerate(queries):
            query_id = f"Q{idx + 1}"
            query_to_run = rewrite_query_for_view(query_sql)
            print(f"{dbname} | view_security_barrier | {query_id} | DISABLE RLS")
            try:
                disable_orders_rls(dbname)
            except Exception as exc:
                print(f"{dbname} | view_security_barrier | {query_id} | failed to disable RLS: {exc}")
            try:
                rows.extend(
                    run_trials_for_query(
                        dbname=dbname,
                        baseline="view_security_barrier",
                        query_id=query_id,
                        query_sql=query_to_run,
                        exec_role="rls_user",
                        rewrite_ms_for_cold=0.0,
                    )
                )
            finally:
                print(f"{dbname} | view_security_barrier | {query_id} | ENABLE RLS")
                try:
                    enable_orders_rls(dbname)
                except Exception as exc:
                    print(f"{dbname} | view_security_barrier | {query_id} | failed to enable RLS: {exc}")

        # Baseline I: ours
        try:
            files_size = get_files_table_size(dbname)
            ours_status = 1
            ours_error = ""
        except Exception as exc:
            files_size = 0
            ours_status = 0
            ours_error = "db_error"
            print(f"{dbname} | ours setup failed: {exc}")
        rows.append(
            {
                "row_type": "setup",
                "baseline": "ours",
                "db": dbname,
                "query_id": "__setup__",
                "trial_type": "__setup__",
                "trial_idx": -1,
                "exec_role": "postgres",
                "elapsed_ms": "0",
                "rewrite_ms": "0",
                "peak_mem_mb": "0",
                "mem_delta_mb": "0",
                "setup_ms": "0",
                "disk_overhead_bytes": files_size,
                "status": ours_status,
                "error_type": ours_error,
                **row_metadata(dbname, "ours", "__setup__", ""),
            }
        )
        if ours_status == 1:
            for idx, query_sql in enumerate(queries):
                query_id = f"Q{idx + 1}"
                rows.extend(
                    run_trials_for_query(
                        dbname=dbname,
                        baseline="ours",
                        query_id=query_id,
                        query_sql=query_sql,
                        exec_role="postgres",
                        rewrite_ms_for_cold=0.0,
                        session_setup=enable_custom_filter,
                    )
                )

        # Clean up indexes after finishing a database.
        try:
            drop_indexes(dbname)
        except Exception as exc:
            print(f"{dbname} | cleanup | drop indexes failed: {exc}")
        try:
            enable_orders_rls(dbname)
        except Exception as exc:
            print(f"{dbname} | cleanup | failed to re-enable RLS: {exc}")

    write_csv(args.out, rows)
    print(f"Wrote {len(rows)} rows to {args.out}")

    stage5_path = os.path.join(os.path.dirname(args.out), "runs_stage5.csv")
    write_stage5_csv(stage5_path, rows)
    print(f"Wrote stage5 CSV to {stage5_path}")

    summary_path = os.path.join(os.path.dirname(args.out), "summary_stage5.csv")
    summarize_trials(rows, summary_path)
    print(f"Wrote summary CSV to {summary_path}")

    plots = generate_plots(stage5_path, summary_path, os.path.join("stage5_out", "plots"))
    print("Generated plots:", plots)


if __name__ == "__main__":
    try:
        main()
    except HarnessError as exc:
        sys.stderr.write(f"Error: {exc}\\n")
        sys.exit(1)
