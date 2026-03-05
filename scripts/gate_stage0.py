#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import fast_sweep_profile_60s as h
from baselines import no_policy, ours, rls_index, sieve_index, view_based
from baselines.common import BaselineAdapter, BaselineSetup
from utils.pg import explain_text, parallelism_off_verified, run_count_hash, run_hygiene, run_query_trials

# ==============================
# Config
# ==============================
DBS: List[str] = ["tpch0_1", "tpch1"]
BASELINES: List[str] = ["no_policy", "view_based", "rls_index", "sieve_index", "ours"]

POLICY_SETS: List[Tuple[str, List[int]]] = [
    ("S_A", list(range(1, 6))),
    ("S_B", list(range(1, 11))),
    ("S_C", list(range(11, 16))),
    ("S_D", list(range(11, 21))),
    ("S_E", list(range(21, 26))),
    ("S_F", list(range(21, 31))),
    ("S_G", list(range(5, 16)) + list(range(25, 31))),
]

QUERY_IDS: List[str] = ["1", "3", "6", "10", "11"]
STATEMENT_TIMEOUT = "5min"
HOT_RUNS = 1

POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"
LOG_DIR = REPO_ROOT / "logs"

EXPLAIN_CASES: Dict[str, List[Tuple[str, str]]] = {
    "tpch0_1": [("S_A", "1"), ("S_A", "3"), ("S_B", "3")],
    "tpch1": [("S_A", "1"), ("S_D", "3"), ("S_F", "6")],
}

SMOKE_CASES: List[Tuple[str, str, str]] = [
    ("S_A", "1", "rls_index"),
    ("S_A", "1", "ours"),
]

CSV_COLUMNS = [
    "db",
    "baseline",
    "policy_set",
    "query_id",
    "status",
    "error_type",
    "error_msg",
    "hot_ms",
    "peak_rss_kb",
    "rows",
    "hash",
    "gt_rows",
    "gt_hash",
    "match_gt",
    "setup_ms",
    "disk_bytes",
    "scan_mode",
    "scan_mode_reason",
    "allow_density",
    "parallelism_off_verified",
    "proj_sig_count",
    "proj_mask_or_ops",
    "proj_rid_iters",
    "cf_exec_ms_total",
    "cf_exec_child_next_calls_total",
    "cf_exec_rows_seen_total",
    "cf_exec_rows_pass_total",
    "cf_exec_rows_reject_total",
    "cf_exec_allow_lookup_total",
    "cf_exec_allow_lookup_ms",
    "tid_count",
    "tid_fetch_calls",
    "tid_fetch_ms",
    "tid_heap_pages_touched",
]


@dataclass
class RunCtx:
    db: str
    policy_set: str
    policy_ids: List[int]
    enabled_path: Path
    setup_state: BaselineSetup


def _safe_err(msg: object) -> str:
    return str(msg or "").replace("\n", " ").replace("\r", " ").strip()[:500]


def _ids_csv(ids: List[int]) -> str:
    return ",".join(str(x) for x in ids)


def _parse_policy_ids(lines: List[str], ids: List[int]) -> List[str]:
    want = set(ids)
    out: List[str] = []
    for ln in lines:
        pid, _target, _expr = h.parse_policy_entry_with_id(ln)
        if pid is not None and int(pid) in want:
            out.append(ln)
    return out


def _parse_scan_mode(notices: List[str]) -> Tuple[str, str, str]:
    modes: List[str] = []
    reasons: List[str] = []
    densities: List[str] = []
    rx = re.compile(
        r"scan_mode_decision:\s+rel=(\S+)\s+mode=(\S+)\s+allow_rows=\S+\s+allow_blocks=\S+\s+relpages=\S+\s+density=([0-9.]+)\s+reason=(\S+)"
    )
    for line in notices:
        m = rx.search(line)
        if not m:
            continue
        modes.append(m.group(2))
        densities.append(m.group(3))
        reasons.append(m.group(4))
    mode_s = "|".join(sorted(set(modes))) if modes else ""
    reason_s = "|".join(sorted(set(reasons))) if reasons else ""
    density_s = "|".join(densities) if densities else ""
    return mode_s, reason_s, density_s


def _make_adapters() -> Dict[str, BaselineAdapter]:
    return {
        "no_policy": BaselineAdapter(
            name="no_policy",
            role="postgres",
            setup=no_policy.setup,
            teardown=no_policy.teardown,
            session_setup=no_policy.session_setup,
            prepare_query=no_policy.prepare_query,
            captures_notices=False,
        ),
        "view_based": BaselineAdapter(
            name="view_based",
            role="postgres",
            setup=view_based.setup,
            teardown=view_based.teardown,
            session_setup=view_based.session_setup,
            prepare_query=view_based.prepare_query,
            captures_notices=False,
        ),
        "rls_index": BaselineAdapter(
            name="rls_index",
            role="rls_user",
            setup=rls_index.setup,
            teardown=rls_index.teardown,
            session_setup=rls_index.session_setup,
            prepare_query=rls_index.prepare_query,
            captures_notices=False,
        ),
        "sieve_index": BaselineAdapter(
            name="sieve_index",
            role="postgres",
            setup=lambda db, policy_lines, enabled_path, timeout_ms: sieve_index.setup(
                db, policy_lines, enabled_path, timeout_ms, REPO_ROOT
            ),
            teardown=sieve_index.teardown,
            session_setup=sieve_index.session_setup,
            prepare_query=lambda qid, qsql, st, db, host, port: sieve_index.prepare_query(
                qid, qsql, st, db, host, port
            ),
            captures_notices=False,
        ),
        "ours": BaselineAdapter(
            name="ours",
            role="postgres",
            setup=ours.setup,
            teardown=ours.teardown,
            session_setup=ours.session_setup,
            prepare_query=ours.prepare_query,
            captures_notices=True,
        ),
    }


def _prepare_sql(adapter: BaselineAdapter, qid: str, qsql: str, setup_state: BaselineSetup, db: str) -> Tuple[str, str]:
    try:
        if adapter.name.startswith("sieve"):
            return adapter.prepare_query(qid, qsql, setup_state, db, h.PG_HOST, h.PG_PORT)
        return adapter.prepare_query(qid, qsql, setup_state)
    except Exception as exc:  # noqa: BLE001
        return "", _safe_err(getattr(exc, "pgerror", None) or exc)


def _run_single_case(
    adapter: BaselineAdapter,
    ctx: RunCtx,
    query_id: str,
    query_sql: str,
    statement_timeout_ms: int,
) -> Dict[str, str]:
    out: Dict[str, str] = {
        "db": ctx.db,
        "baseline": adapter.name,
        "policy_set": ctx.policy_set,
        "query_id": query_id,
        "status": "0",
        "error_type": "",
        "error_msg": "",
        "hot_ms": "",
        "peak_rss_kb": "",
        "rows": "",
        "hash": "",
        "gt_rows": "",
        "gt_hash": "",
        "match_gt": "UNKNOWN",
        "setup_ms": f"{(ctx.setup_state.pre_run_memory_building_ms or 0.0):.3f}",
        "disk_bytes": str(int(ctx.setup_state.disk_overhead_bytes or 0)),
        "scan_mode": "",
        "scan_mode_reason": "",
        "allow_density": "",
        "parallelism_off_verified": "false",
        "proj_sig_count": "",
        "proj_mask_or_ops": "",
        "proj_rid_iters": "",
        "cf_exec_ms_total": "",
        "cf_exec_child_next_calls_total": "",
        "cf_exec_rows_seen_total": "",
        "cf_exec_rows_pass_total": "",
        "cf_exec_rows_reject_total": "",
        "cf_exec_allow_lookup_total": "",
        "cf_exec_allow_lookup_ms": "",
        "tid_count": "",
        "tid_fetch_calls": "",
        "tid_fetch_ms": "",
        "tid_heap_pages_touched": "",
    }

    prepared_sql, prep_err = _prepare_sql(adapter, query_id, query_sql, ctx.setup_state, ctx.db)
    if prep_err:
        out["error_type"] = "prepare_error"
        out["error_msg"] = prep_err
        return out

    def _session_setup(cur):
        return adapter.session_setup(cur, ctx.enabled_path, statement_timeout_ms, ctx.setup_state)

    run = run_query_trials(
        db=ctx.db,
        role=adapter.role,
        query_sql=prepared_sql,
        statement_timeout_ms=statement_timeout_ms,
        hot_runs=HOT_RUNS,
        session_setup=_session_setup,
        capture_notices_cold=adapter.captures_notices,
    )
    if run.status != 1:
        out["error_type"] = run.error_type
        out["error_msg"] = _safe_err(run.error_msg)
        return out

    out["status"] = "1"
    out["hot_ms"] = f"{run.hot_ms:.3f}"
    out["peak_rss_kb"] = str(int(run.hot_peak_rss_kb))

    cnt, hh, cerr = run_count_hash(
        db=ctx.db,
        role=adapter.role,
        query_id=query_id,
        query_sql=prepared_sql,
        statement_timeout_ms=statement_timeout_ms,
        session_setup=_session_setup,
    )
    if cnt is None:
        out["status"] = "0"
        out["error_type"] = "count"
        out["error_msg"] = _safe_err(cerr)
        return out
    out["rows"] = str(int(cnt))
    out["hash"] = str(hh or "")

    ex_text, ex_err = explain_text(
        db=ctx.db,
        role=adapter.role,
        query_sql=prepared_sql,
        statement_timeout_ms=statement_timeout_ms,
        session_setup=_session_setup,
        analyze=False,
    )
    if not ex_err:
        out["parallelism_off_verified"] = "true" if parallelism_off_verified(ex_text) else "false"

    if adapter.name == "ours":
        payload_q, kv_q, _cnt_q = h.extract_policy_profile_query(run.notices)
        _ = payload_q
        payload_p, kv_p, _cnt_p = h.extract_policy_profile(run.notices)
        _ = payload_p

        out["proj_sig_count"] = str(kv_q.get("proj_sig_count", ""))
        out["proj_mask_or_ops"] = str(kv_q.get("proj_mask_or_ops", ""))
        out["proj_rid_iters"] = str(kv_q.get("proj_rid_iters", ""))

        rows_seen = int(float(kv_p.get("rows_seen", "0") or "0"))
        rows_pass = int(float(kv_p.get("rows_passed", "0") or "0"))
        out["cf_exec_ms_total"] = str(kv_p.get("filter_ms", ""))
        out["cf_exec_child_next_calls_total"] = str(rows_seen)
        out["cf_exec_rows_seen_total"] = str(rows_seen)
        out["cf_exec_rows_pass_total"] = str(rows_pass)
        out["cf_exec_rows_reject_total"] = str(max(0, rows_seen - rows_pass))
        out["cf_exec_allow_lookup_total"] = str(rows_seen)
        out["cf_exec_allow_lookup_ms"] = str(kv_p.get("allow_check_ms", ""))
        out["tid_count"] = str(kv_p.get("tid_count", kv_p.get("tid_tuples_fetched", "")))
        out["tid_fetch_calls"] = str(kv_p.get("tid_fetch_calls", kv_p.get("tid_tuples_fetched", "")))
        out["tid_fetch_ms"] = str(kv_p.get("tid_fetch_ms", ""))
        out["tid_heap_pages_touched"] = str(kv_p.get("tid_heap_pages_touched", kv_p.get("tid_blocks_visited", "")))

        sm, rsn, den = _parse_scan_mode(run.notices)
        if sm:
            out["scan_mode"] = sm
            out["scan_mode_reason"] = rsn
            out["allow_density"] = den
        else:
            sm_empty = int(float(kv_p.get("scan_mode_empty_tables", "0") or "0"))
            sm_tid = int(float(kv_p.get("scan_mode_tid_tables", "0") or "0"))
            sm_filter = int(float(kv_p.get("scan_mode_filter_tables", "0") or "0"))
            if sm_empty > 0:
                out["scan_mode"] = "EMPTY"
                out["scan_mode_reason"] = "summary_counter"
            elif sm_tid > 0:
                out["scan_mode"] = "TID"
                out["scan_mode_reason"] = "summary_counter"
            elif sm_filter > 0:
                out["scan_mode"] = "FILTER"
                out["scan_mode_reason"] = "summary_counter"
            else:
                out["scan_mode"] = "NONE_NO_TARGET"
                out["scan_mode_reason"] = "no_policy_target_scan"
            out["allow_density"] = den if den else "NA"

        # Ensure cf_exec and tid counters are always present for ours rows.
        for k in (
            "cf_exec_ms_total",
            "cf_exec_child_next_calls_total",
            "cf_exec_rows_seen_total",
            "cf_exec_rows_pass_total",
            "cf_exec_rows_reject_total",
            "cf_exec_allow_lookup_total",
            "cf_exec_allow_lookup_ms",
            "tid_count",
            "tid_fetch_calls",
            "tid_fetch_ms",
            "tid_heap_pages_touched",
        ):
            if out.get(k, "") == "":
                out[k] = "0"

        if out["proj_sig_count"] not in ("", "0", "0.000") or out["proj_mask_or_ops"] not in (
            "",
            "0",
            "0.000",
        ) or out["proj_rid_iters"] not in ("", "0", "0.000"):
            out["status"] = "0"
            out["error_type"] = "invariant"
            out["error_msg"] = (
                f"proj_sig_count={out['proj_sig_count']} proj_mask_or_ops={out['proj_mask_or_ops']} "
                f"proj_rid_iters={out['proj_rid_iters']}"
            )

    return out


def _run_explain_bundle(
    db: str,
    adapters: Dict[str, BaselineAdapter],
    policy_lines_all: List[str],
    qmap: Dict[str, str],
    statement_timeout_ms: int,
) -> List[str]:
    written: List[str] = []
    set_map = {name: ids for name, ids in POLICY_SETS}
    for set_name, qid in EXPLAIN_CASES.get(db, []):
        ids = set_map[set_name]
        active_policy_lines = _parse_policy_ids(policy_lines_all, ids)
        enabled_path = Path("/tmp") / f"gate_stage0_explain_{db}_{set_name}.txt"
        h.write_enabled_policy_file(active_policy_lines, enabled_path)
        for baseline in ("no_policy", "rls_index", "ours"):
            adapter = adapters[baseline]
            setup_state = BaselineSetup()
            setup_done = False
            setup_err = ""
            try:
                setup_state = adapter.setup(db, active_policy_lines, enabled_path, statement_timeout_ms)
                setup_done = True
            except Exception as exc:  # noqa: BLE001
                setup_err = _safe_err(getattr(exc, "pgerror", None) or exc)

            out_path = LOG_DIR / f"explain_{db}_{set_name}_q{qid}_{baseline}.md"
            if setup_err:
                out_path.write_text(f"# EXPLAIN\n\n- error: `{setup_err}`\n", encoding="utf-8")
                if setup_done:
                    try:
                        adapter.teardown(db, setup_state)
                    except Exception:
                        pass
                written.append(str(out_path))
                continue

            qsql = qmap[qid]
            prepared_sql, prep_err = _prepare_sql(adapter, qid, qsql, setup_state, db)
            if prep_err:
                out_path.write_text(f"# EXPLAIN\n\n- error: `{prep_err}`\n", encoding="utf-8")
            else:
                def _session_setup(cur):
                    return adapter.session_setup(cur, enabled_path, statement_timeout_ms, setup_state)

                plan_text, plan_err = explain_text(
                    db=db,
                    role=adapter.role,
                    query_sql=prepared_sql,
                    statement_timeout_ms=statement_timeout_ms,
                    session_setup=_session_setup,
                    analyze=True,
                )
                if plan_err:
                    out_path.write_text(f"# EXPLAIN\n\n- error: `{plan_err}`\n", encoding="utf-8")
                else:
                    verified = parallelism_off_verified(plan_text)
                    txt = [
                        f"# EXPLAIN {db} {set_name} q{qid} {baseline}",
                        "",
                        f"- parallelism_off_verified: `{str(verified).lower()}`",
                        "",
                        "```sql",
                        "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS) ...",
                        "```",
                        "",
                        "```text",
                        plan_text,
                        "```",
                        "",
                    ]
                    out_path.write_text("\n".join(txt), encoding="utf-8")
            if setup_done:
                try:
                    adapter.teardown(db, setup_state)
                except Exception:
                    pass
            written.append(str(out_path))
    return written


def _write_db_outputs(db: str, rows: List[Dict[str, str]]) -> Tuple[Path, Path]:
    out_csv = LOG_DIR / f"gate_{db}_stage0.csv"
    out_md = LOG_DIR / f"gate_{db}_stage0.md"

    _write_db_csv(out_csv, rows)

    total = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "1")
    errs = total - ok
    mismatches = [
        r
        for r in rows
        if r.get("status") == "1" and r.get("baseline") not in ("no_policy", "rls_index") and r.get("match_gt") == "FALSE"
    ]

    ours = {
        (r["policy_set"], r["query_id"]): float(r["hot_ms"])
        for r in rows
        if r["baseline"] == "ours" and r["status"] == "1" and r.get("hot_ms")
    }
    rlsi = {
        (r["policy_set"], r["query_id"]): float(r["hot_ms"])
        for r in rows
        if r["baseline"] == "rls_index" and r["status"] == "1" and r.get("hot_ms")
    }
    ratios = [ours[k] / rlsi[k] for k in ours if k in rlsi and rlsi[k] > 0]

    med_rss = {}
    for b in BASELINES:
        vals = [int(r["peak_rss_kb"]) for r in rows if r["baseline"] == b and r["status"] == "1" and r.get("peak_rss_kb")]
        med_rss[b] = statistics.median(vals) if vals else None

    lines = [
        f"# Gate Stage0 {db}",
        "",
        f"- csv: `{out_csv}`",
        f"- total_cases: {total}",
        f"- ok: {ok}",
        f"- error: {errs}",
        f"- mismatches_vs_rls_index: {len(mismatches)}",
    ]
    if ratios:
        lines.append(f"- median ours/rls_index ratio: {statistics.median(ratios):.3f}")

    lines.append("")
    lines.append("## Median RSS (KB)")
    for b in BASELINES:
        v = med_rss.get(b)
        lines.append(f"- {b}: {'NA' if v is None else int(v)}")

    sieve_mis = [
        r
        for r in rows
        if r.get("status") == "1" and r.get("baseline") == "sieve_index" and r.get("match_gt") == "FALSE"
    ]
    lines.append("")
    lines.append("## Sieve Equivalence")
    if sieve_mis:
        lines.append("- status: NOT_COMPARABLE (mismatch observed vs rls_index)")
        lines.append(f"- mismatches: {len(sieve_mis)}")
    else:
        lines.append("- status: COMPARABLE (matched rls_index on covered cases)")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_csv, out_md


def _write_db_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_COLUMNS})


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    statement_timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)
    policy_lines_all = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}
    adapters = _make_adapters()

    combined_rows: Dict[str, List[Dict[str, str]]] = {}
    written_explain: List[str] = []

    # Smoke first.
    for db in DBS:
        ok_h, diag = run_hygiene(REPO_ROOT, db)
        if not ok_h:
            raise RuntimeError(f"hygiene failed db={db}: {_safe_err(diag)}")

        set_ids = {name: ids for name, ids in POLICY_SETS}
        for set_name, qid, baseline in SMOKE_CASES:
            ids = set_ids[set_name]
            pols = _parse_policy_ids(policy_lines_all, ids)
            enabled = Path("/tmp") / f"gate_stage0_smoke_{db}_{set_name}.txt"
            h.write_enabled_policy_file(pols, enabled)
            adapter = adapters[baseline]
            st = BaselineSetup()
            done = False
            try:
                st = adapter.setup(db, pols, enabled, statement_timeout_ms)
                done = True
                ctx = RunCtx(db=db, policy_set=set_name, policy_ids=ids, enabled_path=enabled, setup_state=st)
                res = _run_single_case(adapter, ctx, qid, qmap[qid], statement_timeout_ms)
                if res["status"] != "1":
                    raise RuntimeError(
                        f"smoke failed db={db} set={set_name} baseline={baseline} q{qid}: {res['error_type']} {res['error_msg']}"
                    )
                if res.get("parallelism_off_verified") != "true":
                    raise RuntimeError(f"smoke parallelism check failed db={db} set={set_name} baseline={baseline} q{qid}")
            finally:
                if done:
                    try:
                        adapter.teardown(db, st)
                    except Exception:
                        pass

    # Full stage0 matrix.
    for db in DBS:
        ok_h, diag = run_hygiene(REPO_ROOT, db)
        if not ok_h:
            raise RuntimeError(f"hygiene failed db={db}: {_safe_err(diag)}")

        db_rows: List[Dict[str, str]] = []
        gt: Dict[Tuple[str, str], Tuple[str, str]] = {}
        db_csv = LOG_DIR / f"gate_{db}_stage0.csv"
        _write_db_csv(db_csv, db_rows)

        for set_name, ids in POLICY_SETS:
            active_policy_lines = _parse_policy_ids(policy_lines_all, ids)
            enabled = Path("/tmp") / f"gate_stage0_{db}_{set_name}.txt"
            h.write_enabled_policy_file(active_policy_lines, enabled)

            for baseline in BASELINES:
                adapter = adapters[baseline]
                setup_state = BaselineSetup()
                setup_done = False
                setup_err = ""
                t0 = time.perf_counter()
                try:
                    setup_state = adapter.setup(db, active_policy_lines, enabled, statement_timeout_ms)
                    setup_done = True
                except Exception as exc:  # noqa: BLE001
                    setup_err = _safe_err(getattr(exc, "pgerror", None) or exc)
                setup_ms = (time.perf_counter() - t0) * 1000.0
                if setup_state.pre_run_memory_building_ms <= 0.0:
                    setup_state.pre_run_memory_building_ms = setup_ms

                ctx = RunCtx(db=db, policy_set=set_name, policy_ids=ids, enabled_path=enabled, setup_state=setup_state)

                for qid in QUERY_IDS:
                    if qid not in qmap:
                        continue
                    if setup_err:
                        out = {k: "" for k in CSV_COLUMNS}
                        out.update(
                            {
                                "db": db,
                                "baseline": baseline,
                                "policy_set": set_name,
                                "query_id": qid,
                                "status": "0",
                                "error_type": "setup_error",
                                "error_msg": setup_err,
                                "setup_ms": f"{(setup_state.pre_run_memory_building_ms or setup_ms):.3f}",
                                "disk_bytes": str(int(setup_state.disk_overhead_bytes or 0)),
                                "parallelism_off_verified": "false",
                            }
                        )
                        db_rows.append(out)
                        _write_db_csv(db_csv, db_rows)
                        continue

                    out = _run_single_case(adapter, ctx, qid, qmap[qid], statement_timeout_ms)
                    db_rows.append(out)
                    _write_db_csv(db_csv, db_rows)
                    print(
                        f"[stage0] db={db} set={set_name} baseline={baseline} q{qid} "
                        f"status={out.get('status')} hot_ms={out.get('hot_ms','')} err={out.get('error_type','')}",
                        flush=True,
                    )

                    if baseline == "rls_index" and out["status"] == "1":
                        gt[(set_name, qid)] = (out.get("rows", ""), out.get("hash", ""))

                if setup_done:
                    try:
                        adapter.teardown(db, setup_state)
                    except Exception:
                        pass

        # Resolve GT and correctness flags.
        for r in db_rows:
            if r["baseline"] == "no_policy":
                r["match_gt"] = "NA"
                continue
            g = gt.get((r["policy_set"], r["query_id"]))
            if g is None:
                r["match_gt"] = "UNKNOWN"
                continue
            r["gt_rows"], r["gt_hash"] = g
            if r["status"] != "1":
                r["match_gt"] = "FALSE"
            else:
                r["match_gt"] = "TRUE" if (r.get("rows", "") == g[0] and r.get("hash", "") == g[1]) else "FALSE"

        _write_db_csv(db_csv, db_rows)
        combined_rows[db] = db_rows
        _write_db_outputs(db, db_rows)
        written_explain.extend(_run_explain_bundle(db, adapters, policy_lines_all, qmap, statement_timeout_ms))

    # Combined summary.
    combined_md = LOG_DIR / "gate_tpch0_1_tpch1_summary.md"
    lines = ["# Gate Stage0 Combined", ""]
    for db in DBS:
        rows = combined_rows.get(db, [])
        total = len(rows)
        ok = sum(1 for r in rows if r["status"] == "1")
        mis = sum(
            1
            for r in rows
            if r["status"] == "1" and r["baseline"] not in ("no_policy", "rls_index") and r.get("match_gt") == "FALSE"
        )
        ours = {
            (r["policy_set"], r["query_id"]): float(r["hot_ms"])
            for r in rows
            if r["baseline"] == "ours" and r["status"] == "1" and r.get("hot_ms")
        }
        gt = {
            (r["policy_set"], r["query_id"]): float(r["hot_ms"])
            for r in rows
            if r["baseline"] == "rls_index" and r["status"] == "1" and r.get("hot_ms")
        }
        ratios = [ours[k] / gt[k] for k in ours if k in gt and gt[k] > 0]
        lines.extend(
            [
                f"## {db}",
                f"- csv: `logs/gate_{db}_stage0.csv`",
                f"- md: `logs/gate_{db}_stage0.md`",
                f"- cases: {total}",
                f"- ok: {ok}",
                f"- mismatches_vs_rls_index: {mis}",
                f"- median ours/rls_index ratio: {statistics.median(ratios):.3f}" if ratios else "- median ours/rls_index ratio: NA",
                "",
            ]
        )

    lines.append("## Explain Bundles")
    for p in sorted(set(written_explain)):
        lines.append(f"- `{p}`")

    combined_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] wrote {combined_md}")


if __name__ == "__main__":
    main()
