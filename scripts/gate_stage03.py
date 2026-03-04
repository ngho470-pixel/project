#!/usr/bin/env python3
from __future__ import annotations

import csv
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
from baselines import ours, rls_index, sieve_index
from baselines.common import BaselineAdapter, BaselineSetup
from utils.pg import run_count_hash, run_hygiene, run_query_trials

DBS: List[str] = ["tpch0_1", "tpch1"]
BASELINES: List[str] = ["rls_index", "sieve_index", "ours"]
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
STATEMENT_TIMEOUT = "120s"
HOT_RUNS = 1

POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"
LOG_DIR = REPO_ROOT / "logs"

CSV_COLUMNS = [
    "db",
    "baseline",
    "policy_set",
    "policy_ids",
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
    "parallelism_off_verified",
    "scan_mode",
    "scan_mode_reason",
    "allow_density",
    "allow_page_density",
    "policy_eval_ms_total",
    "artifact_load_ms",
    "artifact_bytes_read",
    "allow_build_ms",
    "executor_init_ms_ours",
    "custom_scan_total_ms",
    "custom_scan_overhead_ms",
    "non_customscan_exec_ms",
    "cf_exec_child_next_calls_total",
    "cf_exec_rows_seen_total",
    "cf_exec_rows_pass_total",
    "cf_exec_rows_reject_total",
    "cf_exec_allow_lookup_total",
    "cf_exec_allow_lookup_ms",
    "child_exec_ms",
    "ctid_extract_ms",
    "ctid_to_rid_ms",
    "allow_check_ms",
    "projection_ms",
    "tid_count",
    "tid_fetch_calls",
    "tid_fetch_ms",
    "tid_heap_pages_touched",
    "tid_blocks_touched",
    "tid_offsets_total",
    "tid_pages_read_ms",
    "tid_tuple_extract_ms",
    "tid_heap_fetch_ms",
    "tid_slot_store_ms",
    "tid_visibility_ms",
    "sat_ms",
    "sat_models_total",
    "terms_total",
    "single_hub_ms",
    "two_hop_ms",
    "tree_ms",
    "cycle_rect_ms",
    "td_cycle_ms",
    "td_dp_ms",
    "td_reduction_ms",
    "td_msg_pairs",
    "td_peak_pairs",
    "cmp_summary_build_ms",
    "cmp_checks_total",
    "bin_eval_ms_total",
    "single_table_bin_fastpath_used",
    "bin_ops_total",
    "bins_touched_total",
    "bin_rids_scanned_total",
    "allow_cache_hit",
    "allow_cache_miss",
    "allow_cache_build_ms",
    "proj_sig_count",
    "proj_mask_or_ops",
    "proj_rid_iters",
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


def _make_adapters() -> Dict[str, BaselineAdapter]:
    return {
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


def _kv_any(kv: Dict[str, str], keys: List[str], default: str = "") -> str:
    for k in keys:
        v = kv.get(k)
        if v is not None and v != "":
            return str(v).rstrip(",")
    return default


def _extract_kv_line(notices: List[str], marker: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    payload = ""
    for line in notices:
        if marker not in line:
            continue
        payload = line.split(marker, 1)[1].strip()
    if payload:
        for key, val in re.findall(r"([A-Za-z0-9_]+)=([^\s]+)", payload):
            out[key] = val.rstrip(",")
    return out


def _parse_scan_mode(notices: List[str]) -> Tuple[str, str, str, str]:
    modes: List[str] = []
    reasons: List[str] = []
    densities: List[str] = []
    page_densities: List[str] = []
    rx = re.compile(
        r"scan_mode_decision:\s+rel=(\S+)\s+mode=(\S+)\s+allow_rows=\S+\s+allow_blocks=\S+\s+relpages=\S+\s+density=([0-9.]+)\s+page_density=([0-9.]+)\s+reason=(\S+)"
    )
    for line in notices:
        m = rx.search(line)
        if not m:
            continue
        modes.append(m.group(2))
        densities.append(m.group(3))
        page_densities.append(m.group(4))
        reasons.append(m.group(5))
    return (
        "|".join(sorted(set(modes))) if modes else "",
        "|".join(sorted(set(reasons))) if reasons else "",
        "|".join(densities) if densities else "",
        "|".join(page_densities) if page_densities else "",
    )


def _run_single_case(
    adapter: BaselineAdapter,
    ctx: RunCtx,
    query_id: str,
    query_sql: str,
    statement_timeout_ms: int,
) -> Dict[str, str]:
    out: Dict[str, str] = {k: "" for k in CSV_COLUMNS}
    out.update(
        {
            "db": ctx.db,
            "baseline": adapter.name,
            "policy_set": ctx.policy_set,
            "policy_ids": _ids_csv(ctx.policy_ids),
            "query_id": query_id,
            "status": "0",
            "match_gt": "UNKNOWN",
            "setup_ms": f"{(ctx.setup_state.pre_run_memory_building_ms or 0.0):.3f}",
            "disk_bytes": str(int(ctx.setup_state.disk_overhead_bytes or 0)),
            "parallelism_off_verified": "false",
        }
    )

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
        capture_notices_hot=adapter.captures_notices,
    )
    out["parallelism_off_verified"] = "true" if run.no_parallel_show_ok else "false"
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

    if adapter.name != "ours":
        return out

    notices = run.hot_notices if run.hot_notices else (run.notices if run.notices else run.cold_notices)
    _payload_q, kv_q, _cnt_q = h.extract_policy_profile_query(notices)
    _payload_p, kv_p, _cnt_p = h.extract_policy_profile(notices)
    kv_exec = _extract_kv_line(notices, "policy_profile_exec_stage03:")
    kv_s3 = _extract_kv_line(notices, "policy_profile_stage03:")

    out["proj_sig_count"] = _kv_any(kv_q, ["proj_sig_count"], "0")
    out["proj_mask_or_ops"] = _kv_any(kv_q, ["proj_mask_or_ops"], "0")
    out["proj_rid_iters"] = _kv_any(kv_q, ["proj_rid_iters"], "0")

    out["policy_eval_ms_total"] = _kv_any(kv_exec, ["policy_eval_ms_total", "policy_total_ms"], _kv_any(kv_p, ["policy_total_ms"], "0"))
    out["artifact_load_ms"] = _kv_any(kv_exec, ["artifact_load_ms"], _kv_any(kv_p, ["artifact_load_ms"], "0"))
    out["artifact_bytes_read"] = _kv_any(kv_exec, ["artifact_bytes_read"], _kv_any(kv_p, ["bytes_artifacts_loaded"], "0"))
    out["allow_build_ms"] = _kv_any(kv_exec, ["allow_build_ms"], "0")
    out["executor_init_ms_ours"] = _kv_any(kv_exec, ["executor_init_ms_ours"], "0")

    out["custom_scan_total_ms"] = _kv_any(kv_exec, ["custom_scan_total_ms"], _kv_any(kv_p, ["custom_scan_total_ms"], "0"))
    out["custom_scan_overhead_ms"] = _kv_any(kv_exec, ["custom_scan_overhead_ms"], _kv_any(kv_p, ["custom_scan_overhead_ms"], "0"))
    try:
        hot_ms = float(out["hot_ms"] or "0")
        cs_ms = float(out["custom_scan_total_ms"] or "0")
        out["non_customscan_exec_ms"] = f"{max(0.0, hot_ms - cs_ms):.3f}"
    except Exception:
        out["non_customscan_exec_ms"] = ""

    out["cf_exec_child_next_calls_total"] = _kv_any(kv_p, ["child_next_calls_total"], "0")
    out["cf_exec_rows_seen_total"] = _kv_any(kv_p, ["rows_seen"], "0")
    out["cf_exec_rows_pass_total"] = _kv_any(kv_p, ["rows_passed"], "0")
    try:
        rs = int(float(out["cf_exec_rows_seen_total"] or "0"))
        rp = int(float(out["cf_exec_rows_pass_total"] or "0"))
        out["cf_exec_rows_reject_total"] = str(max(0, rs - rp))
        out["cf_exec_allow_lookup_total"] = str(rs)
    except Exception:
        out["cf_exec_rows_reject_total"] = "0"
        out["cf_exec_allow_lookup_total"] = "0"

    out["cf_exec_allow_lookup_ms"] = _kv_any(kv_exec, ["allow_check_ms"], _kv_any(kv_p, ["allow_check_ms"], "0"))
    out["child_exec_ms"] = _kv_any(kv_exec, ["child_exec_ms"], _kv_any(kv_p, ["child_exec_ms"], "0"))
    out["ctid_extract_ms"] = _kv_any(kv_exec, ["ctid_extract_ms"], _kv_any(kv_p, ["ctid_extract_ms"], "0"))
    out["ctid_to_rid_ms"] = _kv_any(kv_exec, ["ctid_to_rid_ms"], _kv_any(kv_p, ["ctid_to_rid_ms"], "0"))
    out["allow_check_ms"] = _kv_any(kv_exec, ["allow_check_ms"], _kv_any(kv_p, ["allow_check_ms"], "0"))
    out["projection_ms"] = _kv_any(kv_exec, ["projection_ms"], _kv_any(kv_p, ["projection_ms"], "0"))

    out["tid_count"] = _kv_any(kv_p, ["tid_count", "tid_tuples_fetched"], "0")
    out["tid_fetch_calls"] = _kv_any(kv_p, ["tid_fetch_calls", "tid_tuples_fetched"], "0")
    out["tid_fetch_ms"] = _kv_any(kv_exec, ["tid_fetch_ms"], _kv_any(kv_p, ["tid_fetch_ms"], "0"))
    out["tid_heap_pages_touched"] = _kv_any(kv_p, ["tid_heap_pages_touched", "tid_blocks_visited"], "0")
    out["tid_blocks_touched"] = _kv_any(kv_exec, ["tid_blocks_touched"], _kv_any(kv_p, ["tid_blocks_visited"], "0"))
    out["tid_offsets_total"] = _kv_any(kv_exec, ["tid_offsets_total"], _kv_any(kv_p, ["tid_tuples_fetched"], "0"))
    out["tid_pages_read_ms"] = _kv_any(kv_exec, ["tid_pages_read_ms"], _kv_any(kv_p, ["tid_heap_fetch_ms"], "0"))
    out["tid_tuple_extract_ms"] = _kv_any(kv_exec, ["tid_tuple_extract_ms"], _kv_any(kv_p, ["tid_slot_store_ms"], "0"))
    out["tid_heap_fetch_ms"] = _kv_any(kv_exec, ["tid_heap_fetch_ms"], _kv_any(kv_p, ["tid_heap_fetch_ms"], "0"))
    out["tid_slot_store_ms"] = _kv_any(kv_exec, ["tid_slot_store_ms"], _kv_any(kv_p, ["tid_slot_store_ms"], "0"))
    out["tid_visibility_ms"] = _kv_any(kv_exec, ["tid_visibility_ms"], _kv_any(kv_p, ["tid_visibility_ms"], "0"))

    out["sat_ms"] = _kv_any(kv_s3, ["sat_ms"], _kv_any(kv_q, ["sat_ms"], "0"))
    out["sat_models_total"] = _kv_any(kv_s3, ["sat_models_total"], _kv_any(kv_q, ["sat_models_total"], "0"))
    out["terms_total"] = _kv_any(kv_s3, ["terms_total"], _kv_any(kv_q, ["terms_total"], "0"))
    out["single_hub_ms"] = _kv_any(kv_s3, ["single_hub_ms"], "0")
    out["two_hop_ms"] = _kv_any(kv_s3, ["two_hop_ms"], "0")
    out["tree_ms"] = _kv_any(kv_s3, ["tree_ms"], "0")
    out["cycle_rect_ms"] = _kv_any(kv_s3, ["cycle_rect_ms"], "0")
    out["td_cycle_ms"] = _kv_any(kv_s3, ["td_cycle_ms"], "0")
    out["td_dp_ms"] = _kv_any(kv_s3, ["td_dp_ms"], _kv_any(kv_q, ["class_td_dp_ms"], "0"))
    out["td_reduction_ms"] = _kv_any(kv_s3, ["td_reduction_ms"], _kv_any(kv_q, ["class_td_reduction_ms"], "0"))
    out["td_msg_pairs"] = _kv_any(kv_s3, ["td_msg_pairs"], _kv_any(kv_q, ["class_td_msg_pairs_total"], "0"))
    out["td_peak_pairs"] = _kv_any(kv_s3, ["td_peak_pairs"], _kv_any(kv_q, ["class_td_peak_msg_pairs"], "0"))
    out["cmp_summary_build_ms"] = _kv_any(kv_s3, ["cmp_summary_build_ms"], _kv_any(kv_q, ["pf2_cmp_summary_build_ms"], "0"))
    out["cmp_checks_total"] = _kv_any(kv_s3, ["cmp_checks_total"], _kv_any(kv_q, ["pf2_cmp_checks_total"], "0"))
    out["bin_eval_ms_total"] = _kv_any(kv_s3, ["bin_eval_ms_total"], "0")
    out["single_table_bin_fastpath_used"] = _kv_any(kv_s3, ["single_table_bin_fastpath_used"], "0")

    out["bin_ops_total"] = _kv_any(kv_q, ["bin_ops_total"], "0")
    out["bins_touched_total"] = _kv_any(kv_q, ["bins_touched_total"], "0")
    out["bin_rids_scanned_total"] = _kv_any(kv_q, ["bin_rids_scanned_total"], "0")
    out["allow_cache_hit"] = _kv_any(kv_q, ["allow_cache_hit"], "0")
    out["allow_cache_miss"] = _kv_any(kv_q, ["allow_cache_miss"], "0")
    out["allow_cache_build_ms"] = _kv_any(kv_q, ["allow_cache_build_ms"], "0")

    sm, rsn, den, pden = _parse_scan_mode(notices)
    out["scan_mode"] = sm or _kv_any(kv_p, ["scan_mode"], "")
    out["scan_mode_reason"] = rsn
    out["allow_density"] = den
    out["allow_page_density"] = pden
    return out


def _write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_COLUMNS})


def _write_md(path: Path, db: str, rows: List[Dict[str, str]]) -> None:
    total = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "1")
    timeout = sum(1 for r in rows if r.get("error_type") == "timeout")
    errs = total - ok
    mismatches = [
        r
        for r in rows
        if r.get("status") == "1" and r.get("baseline") != "rls_index" and r.get("match_gt") == "FALSE"
    ]
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
    lines = [
        f"# Gate Stage03 {db}",
        "",
        f"- total_cases: {total}",
        f"- ok: {ok}",
        f"- timeout: {timeout}",
        f"- error: {errs}",
        f"- mismatches_vs_rls_index: {len(mismatches)}",
        f"- median ours/rls_index ratio: {statistics.median(ratios):.3f}" if ratios else "- median ours/rls_index ratio: NA",
        "",
    ]
    if mismatches:
        lines.append("## Mismatches")
        for r in mismatches[:30]:
            lines.append(f"- {r['baseline']} {r['policy_set']} q{r['query_id']}: rows={r.get('rows')} gt_rows={r.get('gt_rows')}")
        lines.append("")
    lines.append("## Errors")
    err_rows = [r for r in rows if r.get("status") != "1"]
    if not err_rows:
        lines.append("- none")
    else:
        for r in err_rows[:60]:
            lines.append(f"- {r['baseline']} {r['policy_set']} q{r['query_id']}: {r.get('error_type')} {r.get('error_msg')}")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    statement_timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)
    policy_lines_all = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}
    adapters = _make_adapters()

    combined: Dict[str, List[Dict[str, str]]] = {}
    for db in DBS:
        ok_h, diag = run_hygiene(REPO_ROOT, db)
        if not ok_h:
            raise RuntimeError(f"hygiene failed db={db}: {_safe_err(diag)}")

        out_csv = LOG_DIR / f"gate_{db}_stage03.csv"
        out_md = LOG_DIR / f"gate_{db}_stage03.md"
        rows: List[Dict[str, str]] = []
        gt: Dict[Tuple[str, str], Tuple[str, str]] = {}
        _write_csv(out_csv, rows)

        for set_name, ids in POLICY_SETS:
            active_policy_lines = _parse_policy_ids(policy_lines_all, ids)
            enabled = Path("/tmp") / f"gate_stage03_{db}_{set_name}.txt"
            h.write_enabled_policy_file(active_policy_lines, enabled)
            for baseline in BASELINES:
                adapter = adapters[baseline]
                setup_state = BaselineSetup()
                setup_err = ""
                setup_done = False
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
                        row = {k: "" for k in CSV_COLUMNS}
                        row.update(
                            {
                                "db": db,
                                "baseline": baseline,
                                "policy_set": set_name,
                                "policy_ids": _ids_csv(ids),
                                "query_id": qid,
                                "status": "0",
                                "error_type": "setup_error",
                                "error_msg": setup_err,
                                "setup_ms": f"{(setup_state.pre_run_memory_building_ms or setup_ms):.3f}",
                                "disk_bytes": str(int(setup_state.disk_overhead_bytes or 0)),
                                "parallelism_off_verified": "false",
                            }
                        )
                    else:
                        row = _run_single_case(adapter, ctx, qid, qmap[qid], statement_timeout_ms)
                    rows.append(row)
                    _write_csv(out_csv, rows)
                    print(
                        f"[stage03] db={db} set={set_name} baseline={baseline} q{qid} "
                        f"status={row.get('status')} hot_ms={row.get('hot_ms','')} err={row.get('error_type','')}",
                        flush=True,
                    )

                    if baseline == "rls_index" and row.get("status") == "1":
                        gt[(set_name, qid)] = (row.get("rows", ""), row.get("hash", ""))

                if setup_done:
                    try:
                        adapter.teardown(db, setup_state)
                    except Exception:
                        pass

        for r in rows:
            g = gt.get((r["policy_set"], r["query_id"]))
            if g is None:
                r["match_gt"] = "UNKNOWN"
                continue
            r["gt_rows"], r["gt_hash"] = g
            if r.get("status") != "1":
                r["match_gt"] = "FALSE"
            else:
                r["match_gt"] = "TRUE" if (r.get("rows", "") == g[0] and r.get("hash", "") == g[1]) else "FALSE"

        _write_csv(out_csv, rows)
        _write_md(out_md, db, rows)
        combined[db] = rows

    summary = LOG_DIR / "gate_tpch0_1_tpch1_summary_stage03.md"
    lines = ["# Gate Stage03 Combined", ""]
    for db in DBS:
        rows = combined.get(db, [])
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
        bad = [r for r in rows if r.get("status") != "1"]
        mis = [r for r in rows if r.get("status") == "1" and r.get("baseline") in ("ours", "sieve_index") and r.get("match_gt") == "FALSE"]
        lines.extend(
            [
                f"## {db}",
                f"- csv: `logs/gate_{db}_stage03.csv`",
                f"- md: `logs/gate_{db}_stage03.md`",
                f"- cases: {len(rows)}",
                f"- errors_or_timeouts: {len(bad)}",
                f"- mismatches_vs_rls_index: {len(mis)}",
                f"- median ours/rls_index ratio: {statistics.median(ratios):.3f}" if ratios else "- median ours/rls_index ratio: NA",
                "",
            ]
        )
    summary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] wrote {summary}")


if __name__ == "__main__":
    main()

