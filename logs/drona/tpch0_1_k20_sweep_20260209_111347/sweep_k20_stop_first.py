#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import fast_sweep_profile_60s as h

DB = "tpch0_1"
K = 20
STATEMENT_TIMEOUT_MS = 30 * 60 * 1000

POLICY_PATH = Path("/tmp/z3_lab/policy.txt")
QUERIES_PATH = Path("/tmp/z3_lab/queries.txt")
ENABLED_PATH = POLICY_PATH  # backend-readable file listing enabled policies

# backend-readable .so paths
h.CUSTOM_FILTER_SO = "/tmp/z3_lab/custom_filter.so"
h.ARTIFACT_BUILDER_SO = "/tmp/z3_lab/artifact_builder.so"

RUN_DIR = Path(__file__).resolve().parent
SUMMARY = RUN_DIR / "sweep_summary.csv"
FAIL_REPORT = RUN_DIR / "first_failure_report.txt"


@dataclass
class CountResult:
    count: int
    policy_profile_lines: int
    policy_profile_payload: str


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{now_ts()}] {msg}", flush=True)


def run_count_with_profile(qid: str, count_sql: str) -> CountResult:
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "ours", ENABLED_PATH, STATEMENT_TIMEOUT_MS, ours_debug_mode="off")
            cur.execute("SET client_min_messages = notice;")
            del conn.notices[:]
            cur.execute(count_sql)
            val = int(cur.fetchone()[0])
            notices = [n.replace("\n", " ").strip() for n in conn.notices]
            del conn.notices[:]
            payload, _kv, cnt = h.extract_policy_profile(notices)
            return CountResult(count=val, policy_profile_lines=cnt, policy_profile_payload=payload)
    finally:
        conn.close()


def run_count_rls(count_sql: str) -> int:
    conn = h.connect(DB, "rls_user")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "rls_with_index", ENABLED_PATH, STATEMENT_TIMEOUT_MS)
            # Required for robustness testing.
            cur.execute("SET enable_tidscan = off;")
            cur.execute(count_sql)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def explain_query(qsql: str) -> str:
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, STATEMENT_TIMEOUT_MS)
            # Disable custom_filter for EXPLAIN safety.
            try:
                cur.execute("SET custom_filter.enabled = off;")
            except Exception:
                pass
            cur.execute("SET enable_indexonlyscan = off;")
            cur.execute("SET enable_tidscan = off;")
            cur.execute("EXPLAIN (VERBOSE, COSTS OFF) " + qsql.rstrip(";"))
            rows = cur.fetchall()
            return "\n".join(r[0] for r in rows)
    finally:
        conn.close()


def main() -> int:
    SUMMARY.write_text(
        "query_id,ours_count,rls_count,policy_profile_lines,status,error\n",
        encoding="utf-8",
    )

    policy_lines = h.load_policy_lines(POLICY_PATH)
    if len(policy_lines) < K:
        raise RuntimeError(f"policy file has {len(policy_lines)} lines, need K={K}")
    enabled_lines = policy_lines[:K]

    queries = h.load_queries(QUERIES_PATH)
    qmap = {qid: sql for qid, sql in queries}

    # Setup phase: build artifacts + apply RLS + indexes.
    log(f"setup_ours: build artifacts from {ENABLED_PATH}")
    h.setup_ours_for_k(DB, K, ENABLED_PATH, STATEMENT_TIMEOUT_MS)

    log("setup_rls: apply policies + inferred indexes")
    h.apply_rls_policies_for_k(DB, enabled_lines)
    h.create_rls_indexes_for_k(DB, K, enabled_lines, STATEMENT_TIMEOUT_MS)

    for q in range(1, 23):
        qid = str(q)
        qsql = qmap.get(qid)
        if not qsql:
            raise RuntimeError(f"missing query id {qid} in {QUERIES_PATH}")

        fb = h.count_fallback_sql(qid)
        if fb is not None:
            count_sql = fb
        else:
            wrapped = h.count_wrapper(qsql)
            if wrapped is None:
                raise RuntimeError(f"cannot count-wrap query {qid}")
            count_sql = wrapped

        log(f"q{qid}: running ours count")
        try:
            ours = run_count_with_profile(qid, count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            FAIL_REPORT.write_text(
                f"Failure: ours error\n"
                f"db={DB} K={K} query_id={qid}\n"
                f"error={msg[:500]}\n",
                encoding="utf-8",
            )
            log(f"STOP: ours error q{qid}: {msg[:240]}")
            SUMMARY.write_text(
                SUMMARY.read_text(encoding="utf-8") + f"{qid},,,,{ours.policy_profile_lines if 'ours' in locals() else ''},error,{msg[:240]}\n",
                encoding="utf-8",
            )
            return 1

        if ours.policy_profile_lines != 1:
            msg = f"policy_profile_lines={ours.policy_profile_lines}"
            FAIL_REPORT.write_text(
                f"Failure: duplicate/missing policy_profile\n"
                f"db={DB} K={K} query_id={qid}\n"
                f"{msg}\n"
                f"profile_payload={ours.policy_profile_payload}\n",
                encoding="utf-8",
            )
            log(f"STOP: q{qid} {msg}")
            SUMMARY.write_text(
                SUMMARY.read_text(encoding="utf-8") + f"{qid},{ours.count},, {ours.policy_profile_lines},error,{msg}\n",
                encoding="utf-8",
            )
            return 1

        log(f"q{qid}: running rls count")
        try:
            rls_count = run_count_rls(count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            FAIL_REPORT.write_text(
                f"Failure: rls error\n"
                f"db={DB} K={K} query_id={qid}\n"
                f"error={msg[:500]}\n",
                encoding="utf-8",
            )
            log(f"STOP: rls error q{qid}: {msg[:240]}")
            SUMMARY.write_text(
                SUMMARY.read_text(encoding="utf-8") + f"{qid},{ours.count},,1,error,rls_error:{msg[:240]}\n",
                encoding="utf-8",
            )
            return 1

        status = "ok" if ours.count == rls_count else "mismatch"
        SUMMARY.write_text(
            SUMMARY.read_text(encoding="utf-8") + f"{qid},{ours.count},{rls_count},1,{status},\n",
            encoding="utf-8",
        )

        if ours.count != rls_count:
            # Capture explain for context (best-effort).
            plan = ""
            try:
                plan = explain_query(qsql)
            except Exception as exc:  # noqa: BLE001
                plan = f"<explain_failed: {str(exc).replace(chr(10), ' ')[:240]}>"

            FAIL_REPORT.write_text(
                f"Failure: count mismatch\n"
                f"db={DB} K={K} query_id={qid}\n"
                f"ours_count={ours.count} rls_count={rls_count}\n\n"
                f"SQL:\n{qsql}\n\n"
                f"EXPLAIN (custom_filter disabled):\n{plan}\n",
                encoding="utf-8",
            )
            log(f"STOP: mismatch q{qid}: ours={ours.count} rls={rls_count}")
            return 2

    log("DONE: q1..q22 all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
