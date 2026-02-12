#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import fast_sweep_profile_60s as h


def now_ts() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def drain_notices(conn) -> List[str]:
    notes = [str(x).rstrip("\n") for x in getattr(conn, "notices", [])]
    try:
        conn.notices.clear()
    except Exception:
        pass
    return notes


def write_lines(p: Path, lines: List[str]) -> None:
    if not lines:
        return
    with p.open("a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln)
            if not ln.endswith("\n"):
                f.write("\n")


def explain(cur, sql_text: str) -> List[str]:
    cur.execute("EXPLAIN (VERBOSE, COSTS OFF) " + sql_text)
    return [r[0] for r in cur.fetchall()]


def count(cur, sql_text: str) -> int:
    cur.execute(sql_text)
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def build_count_sqls(qmap: Dict[str, str], qids: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for qid in qids:
        fb = h.count_fallback_sql(qid)
        if fb is not None:
            out[qid] = fb.rstrip().rstrip(";") + ";"
            continue
        w = h.count_wrapper(qmap[qid])
        if w is None:
            raise SystemExit(f"cannot COUNT-wrap q{qid}")
        out[qid] = w.rstrip().rstrip(";") + ";"
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Single-session sweep-like repro with debug_ids notices (OURS vs RLS).")
    p.add_argument("--db", default="tpch0_1")
    p.add_argument("--k", type=int, required=True)
    p.add_argument("--target-qid", required=True)
    p.add_argument("--policy-pool", default="1-20")
    p.add_argument("--policy", default="/tmp/z3_lab/policy.txt")
    p.add_argument("--queries", default="/tmp/z3_lab/queries.txt")
    p.add_argument("--enabled-path", default="", help="If empty, uses /tmp/z3_lab/policies_enabled_<ts>.txt")
    p.add_argument("--custom-filter-so", default="/tmp/z3_lab/custom_filter.so")
    p.add_argument("--artifact-builder-so", default="/tmp/z3_lab/artifact_builder.so")
    p.add_argument("--statement-timeout", default="600s")
    p.add_argument("--pre-qids", default="", help="Comma/range like 1-12,1,2,3; executed once before target.")
    p.add_argument("--target-reps", type=int, default=1, help="How many times to run target query after pre-qids.")
    p.add_argument("--out-dir", default="", help="If empty: logs/drona/sweeplike_<db>_K<k>_q<qid>_<ts>/")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    db = str(args.db)
    k = int(args.k)
    target_qid = str(args.target_qid).strip()
    timeout_ms = h.parse_timeout_ms(str(args.statement_timeout))

    # Ensure backend-loadable .so is used.
    h.CUSTOM_FILTER_SO = str(args.custom_filter_so)
    h.ARTIFACT_BUILDER_SO = str(args.artifact_builder_so)

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = Path("logs") / "drona" / f"sweeplike_{db}_K{k}_q{target_qid}_{now_ts()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    enabled_path = Path(args.enabled_path) if args.enabled_path else Path("/tmp/z3_lab") / f"policies_enabled_sweeplike_{db}_K{k}_q{target_qid}_{now_ts()}.txt"

    out_dir.joinpath("cmd.txt").write_text(" ".join([os.path.basename(__file__)] + os.sys.argv[1:]) + "\n", encoding="utf-8")
    out_dir.joinpath("enabled_tmp_path.txt").write_text(str(enabled_path) + "\n", encoding="utf-8")

    policy_lines = h.load_policy_lines(Path(args.policy))
    pool_ids = h.parse_policy_pool(str(args.policy_pool), max_policy_id=len(policy_lines))
    enabled_ids, enabled_lines = h.select_enabled_policies(policy_lines, pool_ids, k)
    h.write_enabled_policy_file(enabled_lines, enabled_path)
    out_dir.joinpath("enabled_ids.txt").write_text(",".join(str(x) for x in enabled_ids) + "\n", encoding="utf-8")
    out_dir.joinpath("enabled_policies.txt").write_text("".join(enabled_lines), encoding="utf-8")

    # Setup for this K.
    h.setup_ours_for_k(db, k, enabled_path, timeout_ms)
    h.apply_rls_policies_for_k(db, enabled_lines)
    h.create_rls_indexes_for_k(db, k, enabled_lines, timeout_ms)

    qmap = {qid: qsql for qid, qsql in h.load_queries(Path(args.queries))}
    if target_qid not in qmap:
        raise SystemExit(f"target qid {target_qid} not found in queries")

    pre_qids: List[str] = []
    if args.pre_qids.strip():
        pre_qids = [qid for qid, _ in h.filter_queries_by_args(list(qmap.items()), args.pre_qids, None)]
    run_qids = pre_qids + [target_qid]

    count_sqls = build_count_sqls(qmap, list(dict.fromkeys(run_qids)))
    out_dir.joinpath("target_query.sql").write_text(qmap[target_qid].rstrip() + "\n", encoding="utf-8")
    out_dir.joinpath("target_count.sql").write_text(count_sqls[target_qid] + "\n", encoding="utf-8")

    # Hashes for reproducibility.
    try:
        core = ["/tmp/z3_lab/policy.txt", "/tmp/z3_lab/queries.txt", h.CUSTOM_FILTER_SO, h.ARTIFACT_BUILDER_SO, str(enabled_path)]
        out_dir.joinpath("sha256_bundle.txt").write_bytes(subprocess.check_output(["sha256sum"] + core))
    except Exception:
        pass

    # Explain plans for target.
    ours_explain_p = out_dir / "explain_ours_verbose.txt"
    rls_explain_p = out_dir / "explain_rls_verbose.txt"

    # OURS run: single session, pre_qids once, then target reps.
    ours_notices_p = out_dir / "ours_notices.txt"
    ours_counts_p = out_dir / "ours_counts.txt"
    rls_counts_p = out_dir / "rls_counts.txt"
    rls_notices_p = out_dir / "rls_notices.txt"

    ours_count_val: Optional[int] = None
    rls_count_val: Optional[int] = None

    # OURS connection
    conn_o = h.connect(db, "postgres")
    conn_o.autocommit = True
    try:
        with conn_o.cursor() as cur:
            h.set_session_for_baseline(cur, "ours", enabled_path, timeout_ms)
            cur.execute("SET client_min_messages = notice;")
            cur.execute("SET custom_filter.debug_ids = on;")
            drain_notices(conn_o)

            ours_explain_p.write_text("\n".join(explain(cur, count_sqls[target_qid])) + "\n", encoding="utf-8")
            write_lines(ours_notices_p, drain_notices(conn_o))

            for qid in pre_qids:
                write_lines(ours_counts_p, [f"pre q{qid}..."])
                t0 = time.perf_counter()
                c = count(cur, count_sqls[qid])
                ms = (time.perf_counter() - t0) * 1000.0
                write_lines(ours_counts_p, [f"pre q{qid} count={c} elapsed_ms={ms:.3f}"])
                write_lines(ours_notices_p, drain_notices(conn_o))

            for rep in range(1, int(args.target_reps) + 1):
                write_lines(ours_counts_p, [f"target q{target_qid} rep={rep}..."])
                t0 = time.perf_counter()
                c = count(cur, count_sqls[target_qid])
                ms = (time.perf_counter() - t0) * 1000.0
                ours_count_val = c
                write_lines(ours_counts_p, [f"target q{target_qid} rep={rep} count={c} elapsed_ms={ms:.3f}"])
                write_lines(ours_notices_p, drain_notices(conn_o))
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        etype, emsg = h.classify_error(exc, msg)
        out_dir.joinpath("ours_error.txt").write_text(f"{etype}: {emsg}\n", encoding="utf-8")
        write_lines(ours_notices_p, drain_notices(conn_o))
        return 2
    finally:
        conn_o.close()

    # RLS connection (use postgres, then SET ROLE rls_user; keep custom_filter off)
    conn_r = h.connect(db, "postgres")
    conn_r.autocommit = True
    try:
        with conn_r.cursor() as cur:
            h.apply_timing_session_settings(cur, timeout_ms)
            cur.execute("SET client_min_messages = notice;")
            cur.execute("SET custom_filter.enabled = off;")
            cur.execute("SET ROLE rls_user;")
            drain_notices(conn_r)

            rls_explain_p.write_text("\n".join(explain(cur, count_sqls[target_qid])) + "\n", encoding="utf-8")
            write_lines(rls_notices_p, drain_notices(conn_r))

            # Only need the target count for mismatch confirmation; still run it once.
            t0 = time.perf_counter()
            c = count(cur, count_sqls[target_qid])
            ms = (time.perf_counter() - t0) * 1000.0
            rls_count_val = c
            write_lines(rls_counts_p, [f"target q{target_qid} count={c} elapsed_ms={ms:.3f}"])
            write_lines(rls_notices_p, drain_notices(conn_r))
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        etype, emsg = h.classify_error(exc, msg)
        out_dir.joinpath("rls_error.txt").write_text(f"{etype}: {emsg}\n", encoding="utf-8")
        write_lines(rls_notices_p, drain_notices(conn_r))
        return 3
    finally:
        conn_r.close()

    # Summary
    status = "ok"
    if ours_count_val is None or rls_count_val is None:
        status = "error"
    elif ours_count_val != rls_count_val:
        status = "mismatch"
    out_dir.joinpath("summary.txt").write_text(
        "\n".join(
            [
                f"db={db}",
                f"K={k}",
                f"target_qid={target_qid}",
                f"enabled_ids={enabled_ids}",
                f"enabled_path={enabled_path}",
                f"ours_count={ours_count_val}",
                f"rls_count={rls_count_val}",
                f"status={status}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

