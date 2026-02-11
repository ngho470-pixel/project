#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import fast_sweep_profile_60s as h


def now_ts() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


@dataclass(frozen=True)
class Case:
    k: int
    qid: str


@dataclass
class RunOut:
    status: str
    count: Optional[int]
    elapsed_ms: float
    error_type: str
    error_msg: str
    notices: List[str]


def parse_cases(vals: Sequence[str]) -> List[Case]:
    out: List[Case] = []
    for v in vals:
        v = str(v).strip()
        if not v:
            continue
        if ":" not in v:
            raise SystemExit(f"bad --cases entry {v!r}; expected K:QID, e.g. 10:13")
        k_s, qid = v.split(":", 1)
        out.append(Case(k=int(k_s), qid=str(qid).strip()))
    if not out:
        raise SystemExit("no cases provided")
    return out


def _drain_notices(conn) -> List[str]:
    # psycopg2 accumulates notices on the connection object.
    notes = [str(x).rstrip("\n") for x in getattr(conn, "notices", [])]
    try:
        conn.notices.clear()
    except Exception:
        pass
    return notes


def run_count_and_explain(
    *,
    db: str,
    baseline: str,
    enabled_path: Path,
    statement_timeout_ms: int,
    count_sql: str,
    explain_out: Path,
    run_out: Path,
    notices_out: Path,
    marker_required: bool,
    debug_ids: bool,
) -> RunOut:
    role = "postgres" if baseline == "ours" else "rls_user"
    conn = h.connect(db, role)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, statement_timeout_ms)
            cur.execute("SET client_min_messages = notice;")
            if baseline == "ours" and debug_ids:
                cur.execute("SET custom_filter.debug_ids = on;")

            _drain_notices(conn)
            cur.execute("EXPLAIN (VERBOSE, COSTS OFF) " + count_sql)
            plan_lines = [r[0] for r in cur.fetchall()]
            explain_out.write_text("\n".join(plan_lines) + "\n", encoding="utf-8")
            notes = _drain_notices(conn)
            if notes:
                notices_out.write_text("\n".join(notes) + "\n", encoding="utf-8")

            if marker_required:
                marker = "Custom Scan (custom_filter)"
                if not any(marker in ln for ln in plan_lines):
                    out = RunOut(
                        status="error",
                        count=None,
                        elapsed_ms=0.0,
                        error_type="marker_missing",
                        error_msg=f"plan missing marker {marker!r}",
                        notices=notes,
                    )
                    run_out.write_text(f"ERROR: {out.error_type}: {out.error_msg}\n", encoding="utf-8")
                    return out

            _drain_notices(conn)
            t0 = time.perf_counter()
            try:
                cur.execute(count_sql)
                row = cur.fetchone()
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                cnt = int(row[0]) if row and row[0] is not None else 0
                notes2 = _drain_notices(conn)
                run_out.write_text(f"count={cnt}\nelapsed_ms={elapsed_ms:.3f}\n", encoding="utf-8")
                if notes2:
                    # Append additional notices from execution.
                    with notices_out.open("a", encoding="utf-8") as f:
                        f.write("\n".join(notes2) + "\n")
                return RunOut(status="ok", count=cnt, elapsed_ms=elapsed_ms, error_type="", error_msg="", notices=notes + notes2)
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
                etype, emsg = h.classify_error(exc, msg)
                notes2 = _drain_notices(conn)
                out = RunOut(status="error", count=None, elapsed_ms=elapsed_ms, error_type=etype, error_msg=emsg[:240], notices=notes + notes2)
                run_out.write_text(f"ERROR: {etype}: {out.error_msg}\nelapsed_ms={elapsed_ms:.3f}\n", encoding="utf-8")
                if notes2:
                    with notices_out.open("a", encoding="utf-8") as f:
                        f.write("\n".join(notes2) + "\n")
                return out
    finally:
        conn.close()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate repro bundles for failing tpch0_1 cases (OURS vs RLS+index).")
    p.add_argument("--db", default="tpch0_1")
    p.add_argument("--policy", default="/tmp/z3_lab/policy.txt")
    p.add_argument("--queries", default="/tmp/z3_lab/queries.txt")
    p.add_argument("--policy-pool", default="1-20")
    p.add_argument("--enabled-dir", default="/tmp/z3_lab")
    p.add_argument("--custom-filter-so", default="/tmp/z3_lab/custom_filter.so")
    p.add_argument("--artifact-builder-so", default="/tmp/z3_lab/artifact_builder.so")
    p.add_argument("--statement-timeout", default="600s")
    p.add_argument("--out-root", default="", help="If empty, uses logs/drona/repro_failures_<ts>/")
    p.add_argument("--cases", nargs="+", required=True, help="One or more K:QID entries, e.g. 10:10 15:13 15:22")
    p.add_argument("--debug-ids", action="store_true", help="Enable custom_filter.debug_ids for OURS runs.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    db = str(args.db)

    # Ensure we run the backend-loadable artifacts on drona.
    h.CUSTOM_FILTER_SO = str(args.custom_filter_so)
    h.ARTIFACT_BUILDER_SO = str(args.artifact_builder_so)

    statement_timeout_ms = h.parse_timeout_ms(str(args.statement_timeout))
    policy_path = Path(args.policy)
    queries_path = Path(args.queries)
    enabled_dir = Path(args.enabled_dir)
    enabled_dir.mkdir(parents=True, exist_ok=True)

    cases = parse_cases(args.cases)
    if args.out_root:
        out_root = Path(args.out_root)
    else:
        out_root = Path("logs") / "drona" / f"repro_failures_{now_ts()}"
    out_root.mkdir(parents=True, exist_ok=True)

    out_root.joinpath("cmd.txt").write_text(" ".join([os.path.basename(__file__)] + os.sys.argv[1:]) + "\n", encoding="utf-8")

    policy_lines = h.load_policy_lines(policy_path)
    pool_ids = h.parse_policy_pool(str(args.policy_pool), max_policy_id=len(policy_lines))
    queries = {qid: qsql for qid, qsql in h.load_queries(queries_path)}

    # Best-effort hashes for reproducibility.
    try:
        core = [str(policy_path), str(queries_path), h.CUSTOM_FILTER_SO, h.ARTIFACT_BUILDER_SO]
        out_root.joinpath("sha256_core.txt").write_bytes(subprocess.check_output(["sha256sum"] + core))
    except Exception:
        pass

    for case in cases:
        qid = case.qid
        if qid not in queries:
            raise SystemExit(f"query_id {qid} not found in {queries_path}")
        qsql = queries[qid]

        enabled_ids, enabled_lines = h.select_enabled_policies(policy_lines, pool_ids, case.k)
        enabled_tmp = enabled_dir / f"policies_enabled_db={db}_K={case.k}_q={qid}_{now_ts()}.txt"
        h.write_enabled_policy_file(enabled_lines, enabled_tmp)

        out_dir = out_root / f"tpch0_1_K{case.k}_q{qid}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_dir.joinpath("enabled_policies.txt").write_text("".join(enabled_lines), encoding="utf-8")
        out_dir.joinpath("enabled_ids.txt").write_text(",".join(str(x) for x in enabled_ids) + "\n", encoding="utf-8")
        out_dir.joinpath("enabled_tmp_path.txt").write_text(str(enabled_tmp) + "\n", encoding="utf-8")

        # Setup for this K.
        h.setup_ours_for_k(db, case.k, enabled_tmp, statement_timeout_ms)
        h.apply_rls_policies_for_k(db, enabled_lines)
        h.create_rls_indexes_for_k(db, case.k, enabled_lines, statement_timeout_ms)

        fb = h.count_fallback_sql(qid)
        count_sql = fb if fb is not None else (h.count_wrapper(qsql) or "")
        if not count_sql:
            out_dir.joinpath("ERROR.txt").write_text("unsupported_query: cannot COUNT-wrap\n", encoding="utf-8")
            continue
        out_dir.joinpath("count.sql").write_text(count_sql + "\n", encoding="utf-8")
        out_dir.joinpath("query.sql").write_text(qsql.rstrip() + "\n", encoding="utf-8")

        ours = run_count_and_explain(
            db=db,
            baseline="ours",
            enabled_path=enabled_tmp,
            statement_timeout_ms=statement_timeout_ms,
            count_sql=count_sql,
            explain_out=out_dir / "explain_ours_verbose.txt",
            run_out=out_dir / "ours_count.out",
            notices_out=out_dir / "ours_notices.txt",
            marker_required=True,
            debug_ids=bool(args.debug_ids),
        )
        rls = run_count_and_explain(
            db=db,
            baseline="rls_with_index",
            enabled_path=enabled_tmp,
            statement_timeout_ms=statement_timeout_ms,
            count_sql=count_sql,
            explain_out=out_dir / "explain_rls_verbose.txt",
            run_out=out_dir / "rls_count.out",
            notices_out=out_dir / "rls_notices.txt",
            marker_required=False,
            debug_ids=False,
        )

        summary = [
            f"db={db}",
            f"K={case.k}",
            f"query_id={qid}",
            f"enabled_ids={enabled_ids}",
            f"enabled_tmp={enabled_tmp}",
            f"ours_status={ours.status} ours_count={ours.count} ours_ms={ours.elapsed_ms:.3f} ours_err={ours.error_type} {ours.error_msg}",
            f"rls_status={rls.status} rls_count={rls.count} rls_ms={rls.elapsed_ms:.3f} rls_err={rls.error_type} {rls.error_msg}",
        ]
        if ours.status == "ok" and rls.status == "ok" and ours.count != rls.count:
            summary.append(f"MISMATCH ours={ours.count} rls={rls.count}")
        out_dir.joinpath("summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

        # Bundle-specific hashes (include enabled tmp file).
        try:
            out_dir.joinpath("sha256_bundle.txt").write_bytes(
                subprocess.check_output(
                    ["sha256sum", str(policy_path), str(queries_path), h.CUSTOM_FILTER_SO, h.ARTIFACT_BUILDER_SO, str(enabled_tmp)]
                )
            )
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

