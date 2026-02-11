#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import fast_sweep_profile_60s as h


@dataclass
class TimingRow:
    db: str
    K: int
    query_id: str
    rls_setup_ms: float
    disk_rls_bytes: int
    cold_ms: float
    cold_peak_rss_kb: int
    hot_ms: float
    hot_peak_rss_kb: int
    status: str
    error_type: str
    error_msg: str


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Measure q20 runtime under RLS+index for K in {1,10,20}.")
    p.add_argument("--db", default="tpch0_1")
    p.add_argument("--ks", nargs="*", type=int, default=[1, 10, 20])
    p.add_argument("--policy-pool", default="1-20")
    p.add_argument("--policy", default="/tmp/z3_lab/policy.txt")
    p.add_argument("--queries", default="/tmp/z3_lab/queries.txt")
    p.add_argument("--enabled-path", default="/tmp/z3_lab/policies_enabled.txt")
    p.add_argument("--statement-timeout", default="600s")
    p.add_argument("--out-dir", default="")
    p.add_argument("--hot-runs", type=int, default=1, help="Number of hot runs (default 1)")
    return p.parse_args()


def extract_q20_count_sql(queries_path: Path) -> Tuple[str, str]:
    queries = h.load_queries(queries_path)
    qmap = {qid: qsql for qid, qsql in queries}
    if "20" not in qmap:
        raise SystemExit("q20 not found in queries file")
    q20 = qmap["20"]
    wrapped = h.count_wrapper(q20)
    if wrapped is None:
        raise SystemExit("q20 is not a single SELECT; cannot COUNT-wrap")
    return q20, wrapped


def ensure_out_dir(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cmd.txt").write_text(" ".join([os.path.basename(__file__)] + os.sys.argv[1:]) + "\n", encoding="utf-8")
    try:
        core = [
            "/tmp/z3_lab/policy.txt",
            "/tmp/z3_lab/queries.txt",
            "/tmp/z3_lab/custom_filter.so",
            "/tmp/z3_lab/artifact_builder.so",
        ]
        (out_dir / "sha256.txt").write_bytes(subprocess.check_output(["sha256sum"] + core))
    except Exception:
        pass


def run_explain(db: str, sql_text: str, out_path: Path, timeout_ms: int) -> None:
    conn = h.connect(db, "rls_user")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, timeout_ms)
            cur.execute("SET enable_indexonlyscan = off;")
            cur.execute("SET enable_tidscan = off;")
            cur.execute("SET custom_filter.enabled = off;")
            cur.execute("EXPLAIN (VERBOSE, COSTS OFF) " + sql_text)
            lines = [" | ".join(str(x) for x in row) for row in cur.fetchall()]
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        conn.close()


def run_q20_once(db: str, sql_text: str, timeout_ms: int) -> h.RunMetrics:
    conn = h.connect(db, "rls_user")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, timeout_ms)
            cur.execute("SET enable_indexonlyscan = off;")
            cur.execute("SET enable_tidscan = off;")
            cur.execute("SET custom_filter.enabled = off;")
            return h.execute_with_rss(cur, sql_text)
    finally:
        conn.close()


def main() -> int:
    args = parse_args()

    db = str(args.db)
    ks = [int(k) for k in args.ks]
    policy_path = Path(args.policy)
    queries_path = Path(args.queries)
    enabled_path = Path(args.enabled_path)
    timeout_ms = h.parse_timeout_ms(str(args.statement_timeout))

    out_dir = Path(args.out_dir) if args.out_dir else (Path("logs") / f"q20_rls_timing_{time.strftime('%Y%m%d_%H%M%S')}")
    ensure_out_dir(out_dir)

    policy_lines = h.load_policy_lines(policy_path)
    pool_ids = h.parse_policy_pool(str(args.policy_pool), max_policy_id=len(policy_lines))

    q20_sql, q20_count_sql = extract_q20_count_sql(queries_path)
    (out_dir / "q20.sql").write_text(q20_sql, encoding="utf-8")
    (out_dir / "q20_count.sql").write_text(q20_count_sql, encoding="utf-8")

    rows: List[TimingRow] = []

    for k in ks:
        enabled_ids, enabled_lines = h.select_enabled_policies(policy_lines, pool_ids, k)
        h.write_enabled_policy_file(enabled_lines, enabled_path)
        (out_dir / f"enabled_ids_k{k}.txt").write_text(",".join(str(x) for x in enabled_ids) + "\n", encoding="utf-8")

        print(f"[setup] db={db} K={k} enabled_ids={enabled_ids}", flush=True)
        h.apply_rls_policies_for_k(db, enabled_lines)
        rls_setup_ms, disk_rls_bytes, created = h.create_rls_indexes_for_k(db, k, enabled_lines, timeout_ms)
        (out_dir / f"rls_indexes_k{k}.txt").write_text("\n".join(created) + "\n", encoding="utf-8")

        # Plan capture (fast, but keep a short timeout anyway).
        run_explain(db, q20_count_sql, out_dir / f"explain_q20_count_k{k}.txt", timeout_ms=min(timeout_ms, 60_000))

        print(f"[run] db={db} K={k} q20 cold (rls_with_index)", flush=True)
        cold = run_q20_once(db, q20_count_sql, timeout_ms)

        hot = h.make_error_metrics("", "")
        if cold.status == "ok":
            # "Hot" run is just another invocation; relies on shared buffers/file cache.
            # Keep it bounded by the same statement_timeout.
            print(f"[run] db={db} K={k} q20 hot x{int(args.hot_runs)} (rls_with_index)", flush=True)
            hot_vals: List[h.RunMetrics] = []
            for _ in range(int(args.hot_runs)):
                hot_vals.append(run_q20_once(db, q20_count_sql, timeout_ms))
            ok_vals = [m for m in hot_vals if m.status == "ok"]
            if ok_vals:
                # Take the median-like first ok for simplicity (n is small).
                hot = ok_vals[-1]
            else:
                hot = hot_vals[-1]

        status = cold.status if cold.status != "ok" else hot.status
        etype = cold.error_type if cold.status != "ok" else hot.error_type
        emsg = cold.error_msg if cold.status != "ok" else hot.error_msg

        rows.append(
            TimingRow(
                db=db,
                K=k,
                query_id="20",
                rls_setup_ms=float(rls_setup_ms),
                disk_rls_bytes=int(disk_rls_bytes),
                cold_ms=float(cold.elapsed_ms),
                cold_peak_rss_kb=int(cold.peak_rss_kb),
                hot_ms=float(hot.elapsed_ms),
                hot_peak_rss_kb=int(hot.peak_rss_kb),
                status=str(status),
                error_type=str(etype or ""),
                error_msg=str(emsg or ""),
            )
        )

    out_csv = out_dir / "q20_rls_timing.csv"
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "db",
                "K",
                "query_id",
                "rls_setup_ms",
                "disk_rls_bytes",
                "cold_ms",
                "cold_peak_rss_kb",
                "hot_ms",
                "hot_peak_rss_kb",
                "status",
                "error_type",
                "error_msg",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    r.db,
                    r.K,
                    r.query_id,
                    f"{r.rls_setup_ms:.3f}",
                    r.disk_rls_bytes,
                    f"{r.cold_ms:.3f}",
                    r.cold_peak_rss_kb,
                    f"{r.hot_ms:.3f}",
                    r.hot_peak_rss_kb,
                    r.status,
                    r.error_type,
                    r.error_msg,
                ]
            )

    print(f"[done] out_csv={out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

