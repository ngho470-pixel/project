#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path

import fast_sweep_profile_60s as h

DB = "tpch0_1"
K = 20
N_ITERS = 20
STATEMENT_TIMEOUT_MS = 30 * 60 * 1000

POLICY_PATH = Path("/tmp/z3_lab/policy.txt")
QUERIES_PATH = Path("/tmp/z3_lab/queries.txt")
ENABLED_PATH = POLICY_PATH

# backend-readable .so paths
h.CUSTOM_FILTER_SO = "/tmp/z3_lab/custom_filter.so"
h.ARTIFACT_BUILDER_SO = "/tmp/z3_lab/artifact_builder.so"

RUN_DIR = Path(__file__).resolve().parent
FLAKY_CSV = RUN_DIR / "flaky_matrix.csv"
FAIL_REPORT = RUN_DIR / "flaky_first_failure.txt"


@dataclass
class OursResult:
    count: int
    policy_profile_lines: int
    policy_profile_payload: str


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{now_ts()}] {msg}", flush=True)


def run_count_ours(count_sql: str) -> OursResult:
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
            return OursResult(count=val, policy_profile_lines=cnt, policy_profile_payload=payload)
    finally:
        conn.close()


def run_count_rls(count_sql: str) -> int:
    conn = h.connect(DB, "rls_user")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "rls_with_index", ENABLED_PATH, STATEMENT_TIMEOUT_MS)
            cur.execute("SET enable_tidscan = off;")
            cur.execute(count_sql)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def main() -> int:
    FLAKY_CSV.write_text("query_id,iter,status,ours_count,rls_count,error\n", encoding="utf-8")

    policy_lines = h.load_policy_lines(POLICY_PATH)
    if len(policy_lines) < K:
        raise RuntimeError(f"policy file has {len(policy_lines)} lines, need K={K}")
    enabled_lines = policy_lines[:K]

    qmap = {qid: sql for qid, sql in h.load_queries(QUERIES_PATH)}

    log(f"setup_ours: build artifacts from {ENABLED_PATH}")
    h.setup_ours_for_k(DB, K, ENABLED_PATH, STATEMENT_TIMEOUT_MS)

    log("setup_rls: apply policies + inferred indexes")
    h.apply_rls_policies_for_k(DB, enabled_lines)
    h.create_rls_indexes_for_k(DB, K, enabled_lines, STATEMENT_TIMEOUT_MS)

    for qid in map(str, range(1, 23)):
        qsql = qmap[qid]

        fb = h.count_fallback_sql(qid)
        if fb is not None:
            count_sql = fb
        else:
            wrapped = h.count_wrapper(qsql)
            if wrapped is None:
                raise RuntimeError(f"cannot count-wrap query {qid}")
            count_sql = wrapped

        log(f"q{qid}: ground truth (rls) count")
        try:
            rls_count = run_count_rls(count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            FAIL_REPORT.write_text(
                f"Failure: rls error\n"
                f"db={DB} K={K} query_id={qid}\n"
                f"error={msg}\n",
                encoding="utf-8",
            )
            log(f"STOP: rls error q{qid}: {msg[:240]}")
            FLAKY_CSV.write_text(
                FLAKY_CSV.read_text(encoding="utf-8") + f"{qid},0,error,,,rls_error:{msg[:240]}\n",
                encoding="utf-8",
            )
            return 1

        log(f"q{qid}: running ours count {N_ITERS}x")
        for it in range(1, N_ITERS + 1):
            try:
                ours = run_count_ours(count_sql)
            except Exception as exc:  # noqa: BLE001
                msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
                FAIL_REPORT.write_text(
                    f"Failure: ours error\n"
                    f"db={DB} K={K} query_id={qid} iter={it}\n"
                    f"error={msg}\n",
                    encoding="utf-8",
                )
                log(f"STOP: ours error q{qid} iter={it}: {msg[:240]}")
                FLAKY_CSV.write_text(
                    FLAKY_CSV.read_text(encoding="utf-8") + f"{qid},{it},error,,{rls_count},ours_error:{msg[:240]}\n",
                    encoding="utf-8",
                )
                return 1

            if ours.policy_profile_lines != 1:
                msg = f"policy_profile_lines={ours.policy_profile_lines}"
                FAIL_REPORT.write_text(
                    f"Failure: policy_profile_lines\n"
                    f"db={DB} K={K} query_id={qid} iter={it}\n"
                    f"{msg}\n"
                    f"profile_payload={ours.policy_profile_payload}\n",
                    encoding="utf-8",
                )
                log(f"STOP: q{qid} iter={it} {msg}")
                FLAKY_CSV.write_text(
                    FLAKY_CSV.read_text(encoding="utf-8") + f"{qid},{it},error,{ours.count},{rls_count},{msg}\n",
                    encoding="utf-8",
                )
                return 1

            if ours.count != rls_count:
                msg = f"mismatch ours={ours.count} rls={rls_count}"
                FAIL_REPORT.write_text(
                    f"Failure: count mismatch\n"
                    f"db={DB} K={K} query_id={qid} iter={it}\n"
                    f"{msg}\n",
                    encoding="utf-8",
                )
                log(f"STOP: q{qid} iter={it} {msg}")
                FLAKY_CSV.write_text(
                    FLAKY_CSV.read_text(encoding="utf-8") + f"{qid},{it},mismatch,{ours.count},{rls_count},{msg}\n",
                    encoding="utf-8",
                )
                return 2

            # record ok
            FLAKY_CSV.write_text(
                FLAKY_CSV.read_text(encoding="utf-8") + f"{qid},{it},ok,{ours.count},{rls_count},\n",
                encoding="utf-8",
            )

        log(f"q{qid}: OK ({N_ITERS}/{N_ITERS})")

    log(f"DONE: all q1..q22 stable for N={N_ITERS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
