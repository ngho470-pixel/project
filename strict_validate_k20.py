#!/usr/bin/env python3
from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import fast_sweep_profile_60s as h

DB = "tpch0_1"
K_FULL = 20
STATEMENT_TIMEOUT_MS = 30 * 60 * 1000

POLICY_PATH = Path("/tmp/z3_lab/policy.txt")
QUERIES_PATH = Path("/tmp/z3_lab/queries.txt")

# backend-readable .so paths
h.CUSTOM_FILTER_SO = "/tmp/z3_lab/custom_filter.so"
h.ARTIFACT_BUILDER_SO = "/tmp/z3_lab/artifact_builder.so"

RUN_DIR = Path(__file__).resolve().parent

SUMMARY_CSV = RUN_DIR / "strict_summary.csv"
FAIL_DIR = RUN_DIR / "FAIL_BUNDLE"

MARKER_RE = re.compile(r"Custom Scan \(custom_filter\)", flags=re.IGNORECASE)


@dataclass
class OursRun:
    count: int
    policy_profile_lines: int
    policy_profile_payload: str
    policy_profile_kv: Dict[str, str]


def now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(f"[{now_ts()}] {msg}", flush=True)


def sh(cmd: List[str], *, out_path: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> int:
    """Run a command, capturing combined stdout/stderr if out_path is provided."""
    if out_path is None:
        return subprocess.call(cmd, env=env)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        p = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
        return int(p.returncode)


def sha256s(paths: List[Path], out_file: Path) -> None:
    cmd = ["sha256sum"] + [str(p) for p in paths]
    out = subprocess.check_output(cmd)
    out_file.write_bytes(out)


def write_repro_sql(path: Path, sql_text: str) -> None:
    path.write_text(sql_text.strip() + "\n", encoding="utf-8")


def fail(kind: str, msg: str, *, repro_sql: Optional[str] = None, explain_sql: Optional[str] = None) -> None:
    FAIL_DIR.mkdir(parents=True, exist_ok=True)
    (FAIL_DIR / "FAIL_KIND.txt").write_text(kind + "\n", encoding="utf-8")
    (FAIL_DIR / "FAIL_MSG.txt").write_text(msg + "\n", encoding="utf-8")

    # Always capture sha256s for debugging.
    sha256s(
        [
            POLICY_PATH,
            QUERIES_PATH,
            Path(h.CUSTOM_FILTER_SO),
            Path(h.ARTIFACT_BUILDER_SO),
        ],
        FAIL_DIR / "sha256s_core.txt",
    )

    if repro_sql is not None:
        write_repro_sql(FAIL_DIR / "repro.sql", repro_sql)
        # Best-effort run of repro script.
        env = os.environ.copy()
        env["PGPASSWORD"] = h.ROLE_CONFIG["postgres"]["password"]
        sh(
            [
                "psql",
                "-h",
                "localhost",
                "-U",
                h.ROLE_CONFIG["postgres"]["user"],
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                str(FAIL_DIR / "repro.sql"),
            ],
            out_path=FAIL_DIR / "repro.out",
            env=env,
        )

    if explain_sql is not None:
        # Explain in a fresh session with custom_filter enabled.
        env = os.environ.copy()
        env["PGPASSWORD"] = h.ROLE_CONFIG["postgres"]["password"]
        explain_script = "\n".join(
            [
                "\\set ON_ERROR_STOP on",
                "SET max_parallel_workers_per_gather=0;",
                "SET enable_indexonlyscan=off;",
                "SET enable_tidscan=off;",
                "SET statement_timeout='30min';",
                f"LOAD '{h.CUSTOM_FILTER_SO}';",
                "SET custom_filter.enabled=on;",
                "SET custom_filter.contract_mode=off;",
                "SET custom_filter.debug_mode='off';",
                f"SET custom_filter.policy_path='{POLICY_PATH}';",
                "SET client_min_messages = warning;",
                "EXPLAIN (VERBOSE, COSTS OFF) " + explain_sql.strip().rstrip(";") + ";",
            ]
        )
        write_repro_sql(FAIL_DIR / "explain.sql", explain_script)
        sh(
            [
                "psql",
                "-h",
                "localhost",
                "-U",
                h.ROLE_CONFIG["postgres"]["user"],
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                str(FAIL_DIR / "explain.sql"),
            ],
            out_path=FAIL_DIR / "explain.out",
            env=env,
        )

    # Evidence-bundle invariant: always have repro.{sql,out}. For explain-only failures (e.g. missing marker),
    # the EXPLAIN script itself is the minimal reproducer.
    if not (FAIL_DIR / "repro.sql").exists() and (FAIL_DIR / "explain.sql").exists():
        shutil.copyfile(FAIL_DIR / "explain.sql", FAIL_DIR / "repro.sql")
    if not (FAIL_DIR / "repro.out").exists() and (FAIL_DIR / "explain.out").exists():
        shutil.copyfile(FAIL_DIR / "explain.out", FAIL_DIR / "repro.out")

    log(f"FAIL ({kind}): {msg}")
    raise SystemExit(1)


def count_sql_for(qid: str, qsql: str) -> str:
    fb = h.count_fallback_sql(qid)
    if fb is not None:
        return fb
    wrapped = h.count_wrapper(qsql)
    if wrapped is None:
        raise RuntimeError(f"cannot count-wrap query {qid}")
    return wrapped


def repro_psql_for_count(count_sql: str, *, debug_mode: str = "off") -> str:
    """Single psql script that runs OURS and RLS counts and fails on mismatch."""
    q = count_sql.strip().rstrip(";")
    return "\n".join(
        [
            "\\set ON_ERROR_STOP on",
            "SET max_parallel_workers_per_gather=0;",
            "SET enable_indexonlyscan=off;",
            "SET enable_tidscan=off;",
            "SET statement_timeout='30min';",
            "",
            "-- OURS",
            f"LOAD '{h.CUSTOM_FILTER_SO}';",
            "SET custom_filter.enabled=on;",
            "SET custom_filter.contract_mode=off;",
            f"SET custom_filter.debug_mode='{debug_mode}';",
            f"SET custom_filter.policy_path='{POLICY_PATH}';",
            "SET client_min_messages = notice;",
            f"{q} \\gset ours_",
            "",
            "-- RLS (as rls_user via SET ROLE, no password needed)",
            "SET custom_filter.enabled=off;",
            "RESET enable_indexscan;",
            "RESET enable_bitmapscan;",
            "SET client_min_messages = warning;",
            "SET ROLE rls_user;",
            f"{q} \\gset rls_",
            "RESET ROLE;",
            "",
            "\\echo ours=:ours_count rls=:rls_count",
            "DO $$ BEGIN",
            "  IF :ours_count::bigint <> :rls_count::bigint THEN",
            "    RAISE EXCEPTION 'count mismatch ours=% rls=%', :ours_count, :rls_count;",
            "  END IF;",
            "END $$;",
            "\\echo OK",
        ]
    )


def is_single_statement(sql: str) -> bool:
    # Good-enough heuristic for tpch queries (no semicolons inside string literals).
    parts = [p.strip() for p in sql.strip().split(";") if p.strip()]
    return len(parts) == 1


def run_explain_marker(sql: str) -> Tuple[bool, str]:
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "ours", POLICY_PATH, STATEMENT_TIMEOUT_MS, ours_debug_mode="off")
            cur.execute("SET client_min_messages = warning;")
            cur.execute("EXPLAIN (VERBOSE, COSTS OFF) " + sql.strip().rstrip(";") + ";")
            plan = "\n".join(r[0] for r in cur.fetchall())
            return bool(MARKER_RE.search(plan)), plan
    finally:
        conn.close()


def run_count_ours(count_sql: str, *, debug_mode: str = "off") -> OursRun:
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "ours", POLICY_PATH, STATEMENT_TIMEOUT_MS, ours_debug_mode=debug_mode)
            cur.execute("SET client_min_messages = notice;")
            del conn.notices[:]
            cur.execute(count_sql)
            val = int(cur.fetchone()[0])
            notices = [n.replace("\n", " ").strip() for n in conn.notices]
            del conn.notices[:]
            payload, kv, cnt = h.extract_policy_profile(notices)
            return OursRun(count=val, policy_profile_lines=cnt, policy_profile_payload=payload, policy_profile_kv=kv)
    finally:
        conn.close()


def run_count_rls(count_sql: str) -> int:
    conn = h.connect(DB, "rls_user")
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "rls_with_index", POLICY_PATH, STATEMENT_TIMEOUT_MS)
            cur.execute("SET enable_tidscan = off;")
            cur.execute(count_sql)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def run_count_unenforced(count_sql: str) -> int:
    """No enforcement: postgres role with custom_filter disabled."""
    conn = h.connect(DB, "postgres")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, STATEMENT_TIMEOUT_MS)
            cur.execute("SET enable_indexonlyscan = off;")
            cur.execute("SET enable_tidscan = off;")
            # Ensure custom_filter is not active.
            try:
                cur.execute("SET custom_filter.enabled = off;")
            except Exception:
                pass
            cur.execute(count_sql)
            return int(cur.fetchone()[0])
    finally:
        conn.close()


def parse_psql_count(out_path: Path) -> int:
    txt = out_path.read_text(encoding="utf-8", errors="replace")
    # psql prints a line with the count as a standalone integer in our scripts.
    m = re.search(r"\n\s*(\d+)\s*\n\(1 row\)", txt)
    if not m:
        m = re.search(r"\n\s*(\d+)\s*\n", txt)
    if not m:
        raise RuntimeError(f"could not parse count from {out_path}")
    return int(m.group(1))


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    # Core file hashes for this run.
    sha256s(
        [
            POLICY_PATH,
            QUERIES_PATH,
            Path(h.CUSTOM_FILTER_SO),
            Path(h.ARTIFACT_BUILDER_SO),
        ],
        RUN_DIR / "sha256s_core.txt",
    )

    policy_lines = h.load_policy_lines(POLICY_PATH)
    if len(policy_lines) < K_FULL:
        fail("setup", f"policy file has {len(policy_lines)} lines, need K={K_FULL}")
    enabled_lines = policy_lines[:K_FULL]

    queries = h.load_queries(QUERIES_PATH)
    qmap = {qid: sql for qid, sql in queries}
    for qid in map(str, range(1, 23)):
        if qid not in qmap:
            fail("setup", f"missing q{qid} in {QUERIES_PATH}")

    # Setup phase: build artifacts + apply RLS + indexes.
    log(f"setup_ours: build artifacts from {POLICY_PATH}")
    h.setup_ours_for_k(DB, K_FULL, POLICY_PATH, STATEMENT_TIMEOUT_MS)

    log("setup_rls: apply policies + inferred indexes")
    h.apply_rls_policies_for_k(DB, enabled_lines)
    h.create_rls_indexes_for_k(DB, K_FULL, enabled_lines, STATEMENT_TIMEOUT_MS)

    # C) q15 explicit rerun via fresh psql invocations.
    log("q15: dump raw query text (queries.txt)")
    (RUN_DIR / "q15_raw_query.txt").write_text(qmap["15"].strip() + "\n", encoding="utf-8")

    q15_count_sql = count_sql_for("15", qmap["15"])
    (RUN_DIR / "q15_count_sql.sql").write_text(q15_count_sql.strip() + "\n", encoding="utf-8")

    q15_ours_sql = "\n".join(
        [
            "\\set ON_ERROR_STOP on",
            "SET max_parallel_workers_per_gather=0;",
            "SET enable_indexonlyscan=off;",
            "SET enable_tidscan=off;",
            "SET statement_timeout='30min';",
            f"LOAD '{h.CUSTOM_FILTER_SO}';",
            "SET custom_filter.enabled=on;",
            "SET custom_filter.contract_mode=off;",
            "SET custom_filter.debug_mode='off';",
            f"SET custom_filter.policy_path='{POLICY_PATH}';",
            "SET client_min_messages = notice;",
            q15_count_sql.strip().rstrip(";") + ";",
        ]
    )
    write_repro_sql(RUN_DIR / "q15_ours.sql", q15_ours_sql)

    q15_rls_sql = "\n".join(
        [
            "\\set ON_ERROR_STOP on",
            "SET max_parallel_workers_per_gather=0;",
            "SET enable_indexonlyscan=off;",
            "SET enable_tidscan=off;",
            "SET statement_timeout='30min';",
            "SET custom_filter.enabled=off;",
            q15_count_sql.strip().rstrip(";") + ";",
        ]
    )
    write_repro_sql(RUN_DIR / "q15_rls.sql", q15_rls_sql)

    env_pg = os.environ.copy()
    env_pg["PGPASSWORD"] = h.ROLE_CONFIG["postgres"]["password"]
    env_rls = os.environ.copy()
    env_rls["PGPASSWORD"] = h.ROLE_CONFIG["rls_user"]["password"]

    log("q15: run ours via psql")
    rc = sh(
        ["psql", "-h", "localhost", "-U", h.ROLE_CONFIG["postgres"]["user"], "-d", DB, "-v", "ON_ERROR_STOP=1", "-f", str(RUN_DIR / "q15_ours.sql")],
        out_path=RUN_DIR / "q15_ours.out",
        env=env_pg,
    )
    if rc != 0:
        fail("q15_ours_psql", f"psql rc={rc}", repro_sql=q15_ours_sql, explain_sql=q15_count_sql)

    log("q15: run rls via psql")
    rc = sh(
        ["psql", "-h", "localhost", "-U", h.ROLE_CONFIG["rls_user"]["user"], "-d", DB, "-v", "ON_ERROR_STOP=1", "-f", str(RUN_DIR / "q15_rls.sql")],
        out_path=RUN_DIR / "q15_rls.out",
        env=env_rls,
    )
    if rc != 0:
        fail("q15_rls_psql", f"psql rc={rc}", repro_sql=q15_rls_sql, explain_sql=q15_count_sql)

    q15_oc = parse_psql_count(RUN_DIR / "q15_ours.out")
    q15_rc = parse_psql_count(RUN_DIR / "q15_rls.out")
    (RUN_DIR / "q15_check.txt").write_text(
        f"ours={q15_oc} rls={q15_rc} status={'OK' if q15_oc==q15_rc else 'MISMATCH'}\n",
        encoding="utf-8",
    )
    if q15_oc != q15_rc:
        fail("q15_mismatch", f"q15 mismatch ours={q15_oc} rls={q15_rc}", repro_sql=q15_ours_sql, explain_sql=q15_count_sql)

    # B) Strict sweep with plan-marker + profile sanity.
    SUMMARY_CSV.write_text(
        "query_id,ours_count,rls_count,status,policy_profile_lines,n_filters,n_policy_targets\n",
        encoding="utf-8",
    )

    for qid in map(str, range(1, 23)):
        qsql = qmap[qid]
        count_sql = count_sql_for(qid, qsql)

        log(f"q{qid}: explain marker check")
        # Marker check must validate the actual SQL we execute for correctness.
        # For multi-statement queries (e.g. q15), count_sql_for() already returns a safe single statement.
        marker_sql = count_sql
        try:
            ok_marker, plan = run_explain_marker(marker_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            fail(
                "explain_error",
                f"q{qid}: {msg}",
                repro_sql=repro_psql_for_count(count_sql),
                explain_sql=marker_sql,
            )
        if not ok_marker:
            (RUN_DIR / f"q{qid}_explain_missing_marker.txt").write_text(plan + "\n", encoding="utf-8")
            fail(
                "missing_marker",
                f"q{qid}: EXPLAIN missing 'Custom Scan (custom_filter)' marker",
                repro_sql=None,
                explain_sql=marker_sql,
            )

        log(f"q{qid}: ours count + profile")
        try:
            ours = run_count_ours(count_sql, debug_mode="off")
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            fail("ours_error", f"q{qid}: {msg}", repro_sql=repro_psql_for_count(count_sql), explain_sql=count_sql)

        if ours.policy_profile_lines != 1:
            fail(
                "policy_profile_lines",
                f"q{qid}: policy_profile_lines={ours.policy_profile_lines}",
                repro_sql=repro_psql_for_count(count_sql),
                explain_sql=count_sql,
            )

        n_filters = int(ours.policy_profile_kv.get("n_filters", "-1"))
        n_targets = int(ours.policy_profile_kv.get("n_policy_targets", "-1"))
        if n_filters <= 0 or n_targets <= 0:
            fail(
                "profile_noop",
                f"q{qid}: suspicious profile n_filters={n_filters} n_policy_targets={n_targets}",
                repro_sql=repro_psql_for_count(count_sql),
                explain_sql=count_sql,
            )

        log(f"q{qid}: rls count")
        try:
            rls_count = run_count_rls(count_sql)
        except Exception as exc:  # noqa: BLE001
            msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
            fail("rls_error", f"q{qid}: {msg}", repro_sql=repro_psql_for_count(count_sql), explain_sql=count_sql)

        status = "ok" if ours.count == rls_count else "mismatch"
        SUMMARY_CSV.write_text(
            SUMMARY_CSV.read_text(encoding="utf-8")
            + f"{qid},{ours.count},{rls_count},{status},{ours.policy_profile_lines},{n_filters},{n_targets}\n",
            encoding="utf-8",
        )
        if ours.count != rls_count:
            fail(
                "count_mismatch",
                f"q{qid}: mismatch ours={ours.count} rls={rls_count}",
                repro_sql=repro_psql_for_count(count_sql),
                explain_sql=count_sql,
            )

    log("strict sweep: q1..q22 all OK")

    # B) Control experiment (enforcement really on): ours enabled vs ours disabled vs RLS.
    control_qids = ["16", "19", "14"]
    ctrl_lines: List[str] = ["query_id,ours_enabled,ours_disabled,rls,status\n"]
    saw_disabled_diff = False

    for qid in control_qids:
        qsql = qmap[qid]
        count_sql = count_sql_for(qid, qsql)
        log(f"control q{qid}: ours enabled")
        ours = run_count_ours(count_sql, debug_mode="off")
        log(f"control q{qid}: ours disabled")
        unenf = run_count_unenforced(count_sql)
        log(f"control q{qid}: rls")
        rls = run_count_rls(count_sql)
        ok = ours.count == rls
        if unenf != rls:
            saw_disabled_diff = True
        ctrl_lines.append(
            f"{qid},{ours.count},{unenf},{rls},{'ok' if ok else 'FAIL'}\n"
        )
        if not ok:
            fail(
                "control_mismatch",
                f"control q{qid}: ours_enabled={ours.count} rls={rls}",
                repro_sql=repro_psql_for_count(count_sql),
                explain_sql=count_sql,
            )

    (RUN_DIR / "control_experiment.csv").write_text("".join(ctrl_lines), encoding="utf-8")
    if not saw_disabled_diff:
        repro_lines: List[str] = [
            "\\set ON_ERROR_STOP on",
            "SET max_parallel_workers_per_gather=0;",
            "SET enable_indexonlyscan=off;",
            "SET enable_tidscan=off;",
            "SET statement_timeout='30min';",
            "",
            f"LOAD '{h.CUSTOM_FILTER_SO}';",
            f"SET custom_filter.policy_path='{POLICY_PATH}';",
            "SET custom_filter.contract_mode=off;",
            "SET custom_filter.debug_mode='off';",
            "",
        ]
        for qid in control_qids:
            qsql = qmap[qid]
            count_sql = count_sql_for(qid, qsql).strip().rstrip(";")
            repro_lines += [
                f"\\echo '=== control q{qid} ==='",
                "SET custom_filter.enabled=on;",
                "SET client_min_messages = notice;",
                f"{count_sql} \\gset ours_",
                "\\echo ours_enabled=:ours_count",
                "SET custom_filter.enabled=off;",
                "SET client_min_messages = warning;",
                f"{count_sql} \\gset unenf_",
                "\\echo ours_disabled=:unenf_count",
                "SET ROLE rls_user;",
                f"{count_sql} \\gset rls_",
                "RESET ROLE;",
                "\\echo rls=:rls_count",
                "",
            ]
        fail(
            "control_no_diff",
            "control: ours_disabled matched rls for all sampled queries (expected at least one difference)",
            repro_sql="\n".join(repro_lines),
        )

    # D) Regression: subset policies {16,17,18,19} on q3 with trace.
    subset_ids = [16, 17, 18, 19]
    subset_lines = [policy_lines[i - 1] for i in subset_ids]
    subset_path_local = RUN_DIR / "policy_subset_16_19.txt"
    subset_path_local.write_text("\n".join(subset_lines) + "\n", encoding="utf-8")
    subset_path_tmp = Path("/tmp/z3_lab/policy_subset_16_19.txt")
    subset_path_tmp.write_text("\n".join(subset_lines) + "\n", encoding="utf-8")

    log("subset {16..19}: build artifacts")
    h.setup_ours_for_k(DB, len(subset_ids), subset_path_tmp, STATEMENT_TIMEOUT_MS)

    log("subset {16..19}: apply RLS + inferred indexes")
    h.apply_rls_policies_for_k(DB, subset_lines)
    h.create_rls_indexes_for_k(DB, len(subset_ids), subset_lines, STATEMENT_TIMEOUT_MS)

    q3_sql = qmap["3"]
    q3_count_sql = count_sql_for("3", q3_sql)

    # Run ours with trace via psql to capture logs.
    q3_trace_sql = "\n".join(
        [
            "\\set ON_ERROR_STOP on",
            "SET max_parallel_workers_per_gather=0;",
            "SET enable_indexonlyscan=off;",
            "SET enable_tidscan=off;",
            "SET statement_timeout='30min';",
            f"LOAD '{h.CUSTOM_FILTER_SO}';",
            "SET custom_filter.enabled=on;",
            "SET custom_filter.contract_mode=off;",
            "SET custom_filter.debug_mode='trace';",
            f"SET custom_filter.policy_path='{subset_path_tmp}';",
            "SET client_min_messages = notice;",
            q3_count_sql.strip().rstrip(";") + ";",
        ]
    )
    write_repro_sql(RUN_DIR / "q3_subset_trace.sql", q3_trace_sql)

    log("subset {16..19}: q3 ours trace via psql")
    rc = sh(
        ["psql", "-h", "localhost", "-U", h.ROLE_CONFIG["postgres"]["user"], "-d", DB, "-v", "ON_ERROR_STOP=1", "-f", str(RUN_DIR / "q3_subset_trace.sql")],
        out_path=RUN_DIR / "q3_subset_trace.out",
        env=env_pg,
    )
    if rc != 0:
        fail("subset_q3_ours_error", f"subset q3 ours trace rc={rc}", repro_sql=q3_trace_sql, explain_sql=q3_count_sql)

    log("subset {16..19}: q3 rls")
    rls_q3 = run_count_rls(q3_count_sql)
    ours_q3 = parse_psql_count(RUN_DIR / "q3_subset_trace.out")
    (RUN_DIR / "q3_subset_check.txt").write_text(
        f"ours={ours_q3} rls={rls_q3} status={'OK' if ours_q3==rls_q3 else 'MISMATCH'}\n",
        encoding="utf-8",
    )
    if ours_q3 != rls_q3:
        fail("subset_q3_mismatch", f"subset q3 mismatch ours={ours_q3} rls={rls_q3}", repro_sql=q3_trace_sql, explain_sql=q3_count_sql)

    # Extract DNF-related trace lines for quick auditing.
    trace_txt = (RUN_DIR / "q3_subset_trace.out").read_text(encoding="utf-8", errors="replace")
    dnf_lines = []
    for line in trace_txt.splitlines():
        low = line.lower()
        if "dnf" in low or "multi-join" in low or "expand" in low or "max_terms" in low:
            dnf_lines.append(line)
    (RUN_DIR / "q3_subset_trace_dnf_lines.txt").write_text("\n".join(dnf_lines) + "\n", encoding="utf-8")

    log("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
