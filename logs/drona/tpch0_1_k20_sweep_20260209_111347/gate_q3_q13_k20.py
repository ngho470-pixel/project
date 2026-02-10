#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from pathlib import Path

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


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{now_ts()}] {msg}", flush=True)


def count_sql_for(qsql: str) -> str:
    s = qsql.strip()
    if s.endswith(";"):
        s = s[:-1]
    return f"SELECT COUNT(*) AS cnt FROM ({s}) q;"


def run_count_ours(count_sql: str) -> tuple[int, int, str]:
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(
                cur,
                "ours",
                ENABLED_PATH,
                STATEMENT_TIMEOUT_MS,
                ours_debug_mode="off",
            )
            cur.execute("SET client_min_messages = notice;")
            del conn.notices[:]
            cur.execute(count_sql)
            val = int(cur.fetchone()[0])
            notices = [n.replace("\n", " ").strip() for n in conn.notices]
            del conn.notices[:]
            payload, _kv, cnt = h.extract_policy_profile(notices)
            return val, cnt, payload
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


def main() -> int:
    policy_lines = h.load_policy_lines(POLICY_PATH)
    if len(policy_lines) < K:
        print(f"ERROR: policy file has {len(policy_lines)} lines, need K={K}", file=sys.stderr)
        return 2
    enabled_lines = policy_lines[:K]

    qmap = {qid: sql for qid, sql in h.load_queries(QUERIES_PATH)}
    for qid in ("3", "13"):
        if qid not in qmap:
            print(f"ERROR: missing q{qid} in {QUERIES_PATH}", file=sys.stderr)
            return 2

    log(f"setup_ours: build artifacts from {ENABLED_PATH}")
    h.setup_ours_for_k(DB, K, ENABLED_PATH, STATEMENT_TIMEOUT_MS)

    log("setup_rls: apply policies + inferred indexes")
    h.apply_rls_policies_for_k(DB, enabled_lines)
    h.create_rls_indexes_for_k(DB, K, enabled_lines, STATEMENT_TIMEOUT_MS)

    for qid in ("3", "13"):
        qsql = qmap[qid]
        count_sql = count_sql_for(qsql)

        log(f"q{qid}: running ours count")
        try:
            ours_count, profile_lines, payload = run_count_ours(count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            print(f"FAIL q{qid}: ours error: {msg}", file=sys.stderr)
            return 1

        if profile_lines != 1:
            print(
                f"FAIL q{qid}: policy_profile_lines={profile_lines} payload={payload}",
                file=sys.stderr,
            )
            return 1

        log(f"q{qid}: running rls count")
        try:
            rls_count = run_count_rls(count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            print(f"FAIL q{qid}: rls error: {msg}", file=sys.stderr)
            return 1

        if ours_count != rls_count:
            print(f"FAIL q{qid}: mismatch ours={ours_count} rls={rls_count}", file=sys.stderr)
            return 1

        log(f"q{qid}: ok (count={ours_count})")

    log("GATE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
