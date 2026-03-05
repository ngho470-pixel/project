#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import fast_sweep_profile_60s as h
from baselines import ours
from fast_sweep_profile_60s import extract_policy_profile_query
from utils.pg import run_hygiene

DB = "tpch0_1"
POLICY_FILE = REPO / "policy.txt"
QUERY_FILE = REPO / "queries.txt"
STATEMENT_TIMEOUT = "30min"
OUT_A = REPO / "logs" / "tpch0_1_caseA_profile.md"
OUT_B = REPO / "logs" / "tpch0_1_caseB_profile.md"

CASE_A_SET = list(range(1, 6))
CASE_B_SET = list(range(1, 11))
QMAP = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}


def parse_policy_ids(lines: List[str], ids: List[int]) -> List[str]:
    want = set(ids)
    out: List[str] = []
    for ln in lines:
        pid, _target, _expr = h.parse_policy_entry_with_id(ln)
        if pid is not None and int(pid) in want:
            out.append(ln)
    return out


def parse_route_counts(notices: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for n in notices:
        if "class_route_term:" not in n:
            continue
        m = re.search(r"\broute=([^\s]+)", n)
        if not m:
            continue
        route = m.group(1)
        out[route] = out.get(route, 0) + 1
    return out


def run_ours_sequence(policy_ids: List[int], query_ids: List[str]) -> Tuple[float, Dict[str, object], Dict[str, Dict[str, object]]]:
    lines_all = h.load_policy_lines(POLICY_FILE)
    lines = parse_policy_ids(lines_all, policy_ids)
    enabled = Path("/tmp") / f"tpch0_1_case_{'_'.join(map(str, policy_ids[:2]))}_{len(policy_ids)}.txt"
    h.write_enabled_policy_file(lines, enabled)
    timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)

    ok, msg = run_hygiene(REPO, DB)
    if not ok:
        raise RuntimeError(f"hygiene failed: {msg}")

    setup = ours.setup(DB, lines, enabled, timeout_ms)
    setup_ms = float(setup.pre_run_memory_building_ms)

    per_query: Dict[str, Dict[str, object]] = {}
    conn = None
    try:
        conn = h.connect(DB, "postgres")
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, timeout_ms)
            ours.session_setup(cur, enabled, timeout_ms, setup)
            cur.execute("SET client_min_messages = notice;")
            for qid in query_ids:
                sql_text, _ = ours.prepare_query(qid, QMAP[qid], setup)
                metrics, notices = h.execute_with_rss_and_notices(cur, sql_text)
                payload, kv, cnt = extract_policy_profile_query(notices)
                per_query[qid] = {
                    "status": metrics.status,
                    "elapsed_ms": float(metrics.elapsed_ms),
                    "peak_rss_kb": int(metrics.peak_rss_kb),
                    "error_type": metrics.error_type,
                    "error_msg": metrics.error_msg,
                    "notice_count": len(notices),
                    "policy_profile_query_lines": cnt,
                    "policy_profile_payload": payload,
                    "profile": kv,
                    "route_counts": parse_route_counts(notices),
                    "route_lines": [n for n in notices if "class_route_term:" in n],
                }
    finally:
        try:
            ours.teardown(DB, setup)
        except Exception:
            pass
        if conn is not None:
            conn.close()
    return setup_ms, setup.state if setup.state is not None else {}, per_query


def kvnum(kv: Dict[str, str], k: str, default: str = "0") -> str:
    return str(kv.get(k, default))


def write_case_md(path: Path, title: str, setup_ms: float, policy_ids: List[int], query_order: List[str], per_query: Dict[str, Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- db: `{DB}`")
    lines.append(f"- policy_ids: `{','.join(map(str, policy_ids))}`")
    lines.append(f"- setup_ms: `{setup_ms:.3f}`")
    lines.append(f"- strict_mode: `on` (ours baseline session setup)")
    lines.append("")

    lines.append("## Per Query")
    for qid in query_order:
        q = per_query[qid]
        kv = q["profile"] if isinstance(q["profile"], dict) else {}
        lines.append(
            "- q{qid}: status={status} ms={ms:.3f} rss_kb={rss} sat_ms={sat_ms} sat_models_total={sat_models} "
            "sat_conflicts={sat_conf} sat_decisions={sat_dec} terms_total={terms} term_eval_ms_total={term_ms} "
            "combine_algebra_ms={combine_ms} allow_rows_total={allow_rows} route_terms={route_terms} "
            "bin_ops_total={bin_ops} bins_touched_total={bins_touched} bin_rids_scanned_total={bin_rids} "
            "heap_rows_scanned_total={heap_rows} allow_cache_hit={cache_hit} allow_cache_miss={cache_miss} "
            "allow_cache_build_ms={cache_build} inv_proj_sig={inv_sig} inv_proj_mask={inv_mask} inv_proj_rid={inv_rid} "
            "error_type={etype} error_msg={emsg}".format(
                qid=qid,
                status=q["status"],
                ms=q["elapsed_ms"],
                rss=q["peak_rss_kb"],
                sat_ms=kvnum(kv, "sat_ms"),
                sat_models=kvnum(kv, "sat_models_total"),
                sat_conf=kvnum(kv, "sat_conflicts"),
                sat_dec=kvnum(kv, "sat_decisions"),
                terms=kvnum(kv, "terms_total"),
                term_ms=kvnum(kv, "term_eval_ms_total"),
                combine_ms=kvnum(kv, "combine_algebra_ms"),
                allow_rows=kvnum(kv, "allow_rows_total"),
                route_terms=json.dumps(q["route_counts"], sort_keys=True),
                bin_ops=kvnum(kv, "bin_ops_total"),
                bins_touched=kvnum(kv, "bins_touched_total"),
                bin_rids=kvnum(kv, "bin_rids_scanned_total"),
                heap_rows=kvnum(kv, "heap_rows_scanned_total"),
                cache_hit=kvnum(kv, "allow_cache_hit"),
                cache_miss=kvnum(kv, "allow_cache_miss"),
                cache_build=kvnum(kv, "allow_cache_build_ms"),
                inv_sig=kvnum(kv, "proj_sig_count"),
                inv_mask=kvnum(kv, "proj_mask_or_ops"),
                inv_rid=kvnum(kv, "proj_rid_iters"),
                etype=(q.get("error_type") or ""),
                emsg=(q.get("error_msg") or "").replace("\n", " "),
            )
        )

    lines.append("")
    lines.append("## Raw Route Lines")
    for qid in query_order:
        lines.append(f"- q{qid}:")
        rl = per_query[qid].get("route_lines", [])
        if not rl:
            lines.append("  - (none)")
        else:
            for line in rl:
                lines.append(f"  - {line}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    # Case A: include full S_A query sequence to show cache reuse after first query.
    qa = ["1", "3", "6", "10", "11"]
    setup_ms_a, _state_a, perq_a = run_ours_sequence(CASE_A_SET, qa)
    write_case_md(OUT_A, "tpch0_1 Case A Profile (S_A, baseline=ours)", setup_ms_a, CASE_A_SET, qa, perq_a)

    # Case B: stuck query focus.
    qb = ["3"]
    setup_ms_b, _state_b, perq_b = run_ours_sequence(CASE_B_SET, qb)
    write_case_md(OUT_B, "tpch0_1 Case B Profile (S_B, baseline=ours, q3)", setup_ms_b, CASE_B_SET, qb, perq_b)


if __name__ == "__main__":
    main()
