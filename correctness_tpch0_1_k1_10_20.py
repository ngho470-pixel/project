#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List

import fast_sweep_profile_60s as h


@dataclass
class CountResult:
    count: Optional[int]
    error_type: str
    error_msg: str


def now_ts() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def classify_exc(exc: Exception) -> Tuple[str, str]:
    msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
    low = msg.lower()
    if "statement timeout" in low:
        return "timeout", msg[:240]
    if "engine_error" in low or "custom_filter[engine_error]" in low:
        return "engine_error", msg[:240]
    if "connection refused" in low or "terminating connection" in low:
        return "conn_error", msg[:240]
    return "db_error", msg[:240]


def run_count(
    *,
    db: str,
    baseline: str,
    sql_text: str,
    enabled_path: Path,
    statement_timeout_ms: int,
    watchdog_grace_s: int,
) -> CountResult:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = h.connect(db, role)
    conn.autocommit = True
    killer_thr = None
    done = threading.Event()
    backend_pid: Optional[int] = None

    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            cur.execute("SET enable_tidscan = off;")
            cur.execute("SET client_min_messages = warning;")
            cur.execute("SELECT pg_backend_pid();")
            backend_pid = int(cur.fetchone()[0])

            def _killer():
                if done.wait((statement_timeout_ms / 1000.0) + float(watchdog_grace_s)):
                    return
                try:
                    kconn = h.connect(db, "postgres")
                    kconn.autocommit = True
                    try:
                        with kconn.cursor() as kcur:
                            kcur.execute("SELECT pg_terminate_backend(%s);", [backend_pid])
                    finally:
                        kconn.close()
                except Exception:
                    # Best-effort: if this fails, the caller will hang, but we've tried.
                    pass

            killer_thr = threading.Thread(target=_killer, name=f"kill_pid_{backend_pid}", daemon=True)
            killer_thr.start()

            cur.execute(sql_text)
            row = cur.fetchone()
            done.set()
            if killer_thr:
                killer_thr.join(timeout=1.0)
            if not row:
                return CountResult(count=0, error_type="", error_msg="")
            return CountResult(count=int(row[0]), error_type="", error_msg="")
    except Exception as exc:  # noqa: BLE001
        done.set()
        if killer_thr:
            killer_thr.join(timeout=1.0)
        etype, emsg = classify_exc(exc)
        if backend_pid is not None:
            emsg = f"pid={backend_pid} {emsg}"
        return CountResult(count=None, error_type=etype, error_msg=emsg)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Correctness-only sweep: tpch0_1, K in {1,10,20}, q1..q22, OURS vs RLS+index")
    p.add_argument("--db", default="tpch0_1")
    p.add_argument("--ks", nargs="*", type=int, default=[1, 10, 20])
    p.add_argument("--policy-pool", default="1-20")
    p.add_argument("--policy", default="/tmp/z3_lab/policy.txt")
    p.add_argument("--queries", default="/tmp/z3_lab/queries.txt")
    p.add_argument("--enabled-path", default="/tmp/z3_lab/policies_enabled.txt")
    p.add_argument("--custom-filter-so", default="/tmp/z3_lab/custom_filter.so")
    p.add_argument("--artifact-builder-so", default="/tmp/z3_lab/artifact_builder.so")
    p.add_argument("--statement-timeout", default="600s")
    p.add_argument("--watchdog-grace-s", type=int, default=15)
    p.add_argument("--out-dir", default="")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    db = str(args.db)
    ks = [int(k) for k in args.ks]
    policy_path = Path(args.policy)
    queries_path = Path(args.queries)
    enabled_path = Path(args.enabled_path)
    statement_timeout_ms = h.parse_timeout_ms(str(args.statement_timeout))

    # Make sure the backend loads the /tmp/z3_lab/... build, not the repo-local .so.
    h.CUSTOM_FILTER_SO = str(args.custom_filter_so)
    h.ARTIFACT_BUILDER_SO = str(args.artifact_builder_so)

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = Path("logs") / f"correctness_tpch0_1_k1_10_20_{now_ts()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Record core hashes for reproducibility (best-effort: on drona these exist).
    try:
        import subprocess

        core = [
            "/tmp/z3_lab/policy.txt",
            "/tmp/z3_lab/queries.txt",
            "/tmp/z3_lab/custom_filter.so",
            "/tmp/z3_lab/artifact_builder.so",
        ]
        out_dir.joinpath("sha256.txt").write_bytes(subprocess.check_output(["sha256sum"] + core))
    except Exception:
        pass

    out_dir.joinpath("cmd.txt").write_text(" ".join([os.path.basename(__file__)] + os.sys.argv[1:]) + "\n", encoding="utf-8")

    queries = h.load_queries(queries_path)
    policy_lines = h.load_policy_lines(policy_path)
    pool_ids = h.parse_policy_pool(str(args.policy_pool), max_policy_id=len(policy_lines))

    csv_path = out_dir / "correctness.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "db",
                "K",
                "query_id",
                "status",
                "ours_count",
                "rls_count",
                "error_type",
                "error_msg",
            ],
        )
        w.writeheader()

        for k in ks:
            enabled_ids, enabled_lines = h.select_enabled_policies(policy_lines, pool_ids, k)
            h.write_enabled_policy_file(enabled_lines, enabled_path)

            print(f"[K] db={db} K={k} enabled_ids={enabled_ids}", flush=True)

            # Setup once per K.
            h.setup_ours_for_k(db, k, enabled_path, statement_timeout_ms)
            h.apply_rls_policies_for_k(db, enabled_lines)
            h.create_rls_indexes_for_k(db, k, enabled_lines, statement_timeout_ms)

            ok = mismatch = err = 0
            for qid, qsql in queries:
                fb = h.count_fallback_sql(qid)
                count_sql = fb if fb is not None else (h.count_wrapper(qsql) or "")
                if not count_sql:
                    w.writerow(
                        {
                            "db": db,
                            "K": str(k),
                            "query_id": qid,
                            "status": "error",
                            "ours_count": "",
                            "rls_count": "",
                            "error_type": "unsupported_query",
                            "error_msg": "cannot COUNT-wrap query",
                        }
                    )
                    err += 1
                    continue

                print(f"[q] db={db} K={k} q={qid} ours_count...", flush=True)
                ours = run_count(
                    db=db,
                    baseline="ours",
                    sql_text=count_sql,
                    enabled_path=enabled_path,
                    statement_timeout_ms=statement_timeout_ms,
                    watchdog_grace_s=int(args.watchdog_grace_s),
                )

                print(f"[q] db={db} K={k} q={qid} rls_count...", flush=True)
                rls = run_count(
                    db=db,
                    baseline="rls_with_index",
                    sql_text=count_sql,
                    enabled_path=enabled_path,
                    statement_timeout_ms=statement_timeout_ms,
                    watchdog_grace_s=int(args.watchdog_grace_s),
                )

                status = "ok"
                etype = ""
                emsg = ""
                if ours.count is None:
                    status = "error"
                    etype = ours.error_type
                    emsg = f"ours: {ours.error_msg}"
                elif rls.count is None:
                    status = "error"
                    etype = rls.error_type
                    emsg = f"rls: {rls.error_msg}"
                elif ours.count != rls.count:
                    status = "mismatch"
                    etype = "count_mismatch"
                    emsg = ""

                w.writerow(
                    {
                        "db": db,
                        "K": str(k),
                        "query_id": qid,
                        "status": status,
                        "ours_count": "" if ours.count is None else str(ours.count),
                        "rls_count": "" if rls.count is None else str(rls.count),
                        "error_type": etype,
                        "error_msg": emsg,
                    }
                )
                f.flush()

                if status == "ok":
                    ok += 1
                elif status == "mismatch":
                    mismatch += 1
                else:
                    err += 1

            print(f"[K] done db={db} K={k} ok={ok} mismatch={mismatch} error={err}", flush=True)

    out_dir.joinpath("DONE.txt").write_text("done\n", encoding="utf-8")
    print(f"[done] out_dir={out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
