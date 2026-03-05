#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import fast_sweep_profile_60s as h
from baselines import no_policy, ours, rls_index, sieve_index, view_based
from baselines.common import BaselineAdapter, BaselineSetup
from utils.pg import run_count_only, run_hygiene, run_query_trials

DB = "tpch0_1"
POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"

QUERY_IDS: List[str] = ["1", "3", "6", "10", "11"]
POLICY_SETS: List[Tuple[str, List[int]]] = [
    ("S_A", list(range(1, 6))),
    ("S_B", list(range(1, 11))),
]
BASELINES: List[str] = ["no_policy", "view_based", "rls_index", "sieve_index", "ours"]

STATEMENT_TIMEOUT = "30min"
HOT_RUNS = 1

OUT_CSV = REPO_ROOT / "logs" / "tpch0_1_gate_after_fix.csv"
OUT_MD = REPO_ROOT / "logs" / "tpch0_1_gate_after_fix.md"


def parse_policy_ids(lines: List[str], ids: List[int]) -> List[str]:
    want = set(ids)
    out: List[str] = []
    for ln in lines:
        pid, _target, _expr = h.parse_policy_entry_with_id(ln)
        if pid is not None and int(pid) in want:
            out.append(ln)
    return out


def policy_ids_csv(ids: List[int]) -> str:
    return ",".join(str(x) for x in ids)


def make_adapters() -> Dict[str, BaselineAdapter]:
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


def _safe_err(msg: object) -> str:
    return str(msg or "").replace("\n", " ").replace("\r", " ").strip()[:500]


def main() -> None:
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    statement_timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)
    adapters = make_adapters()
    policy_lines_all = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}

    run_hyg_ok, run_hyg_msg = run_hygiene(REPO_ROOT, DB)
    if not run_hyg_ok:
        raise RuntimeError(f"db hygiene failed before run: {_safe_err(run_hyg_msg)}")

    cases: List[Dict[str, object]] = []

    for policy_set_name, policy_ids in POLICY_SETS:
        active_policy_lines = parse_policy_ids(policy_lines_all, policy_ids)
        enabled_path = Path("/tmp") / f"tpch0_1_gate_after_fix_{policy_set_name}.txt"
        h.write_enabled_policy_file(active_policy_lines, enabled_path)

        for baseline in BASELINES:
            adapter = adapters[baseline]
            setup_state = BaselineSetup()
            setup_error = ""
            setup_done = False

            ok_h, hmsg = run_hygiene(REPO_ROOT, DB)
            if not ok_h:
                print(f"[gate_after_fix] hygiene warning baseline={baseline} set={policy_set_name}: {_safe_err(hmsg)}")

            t_setup0 = time.perf_counter()
            if not setup_error:
                try:
                    setup_state = adapter.setup(DB, active_policy_lines, enabled_path, statement_timeout_ms)
                    setup_done = True
                except Exception as exc:  # noqa: BLE001
                    setup_error = _safe_err(getattr(exc, "pgerror", None) or exc)
            setup_ms = (time.perf_counter() - t_setup0) * 1000.0
            disk_bytes = int(setup_state.disk_overhead_bytes or 0)

            for qid in QUERY_IDS:
                qsql = qmap[qid]
                row: Dict[str, object] = {
                    "db": DB,
                    "baseline": baseline,
                    "policy_set_name": policy_set_name,
                    "policy_ids": policy_ids_csv(policy_ids),
                    "query_id": qid,
                    "status": "ok",
                    "error_type": "",
                    "error_msg": "",
                    "hot_ms": 0.0,
                    "peak_rss_kb": 0,
                    "rows": "",
                    "_rows_int": None,
                    "gt_rows": "",
                    "match_gt": "NA",
                    "setup_ms": f"{setup_ms:.3f}",
                    "disk_bytes": str(disk_bytes),
                }

                if setup_error:
                    row["status"] = "error"
                    row["error_type"] = "setup"
                    row["error_msg"] = setup_error
                    cases.append(row)
                    continue

                try:
                    if baseline.startswith("sieve"):
                        prepared_sql, _ = adapter.prepare_query(
                            qid, qsql, setup_state, DB, h.PG_HOST, h.PG_PORT
                        )
                    else:
                        prepared_sql, _ = adapter.prepare_query(qid, qsql, setup_state)
                except Exception as exc:  # noqa: BLE001
                    row["status"] = "error"
                    row["error_type"] = "prepare"
                    row["error_msg"] = _safe_err(exc)
                    cases.append(row)
                    continue

                qr = run_query_trials(
                    db=DB,
                    role=adapter.role,
                    query_sql=prepared_sql,
                    statement_timeout_ms=statement_timeout_ms,
                    hot_runs=HOT_RUNS,
                    session_setup=(lambda cur, a=adapter, st=setup_state: a.session_setup(cur, enabled_path, statement_timeout_ms, st)),
                    capture_notices_cold=adapter.captures_notices,
                )
                if qr.status != 1:
                    row["status"] = "error"
                    row["error_type"] = qr.error_type
                    row["error_msg"] = _safe_err(qr.error_msg)
                    cases.append(row)
                    continue

                row["hot_ms"] = f"{qr.hot_ms:.3f}"
                row["peak_rss_kb"] = str(qr.hot_peak_rss_kb)

                cnt, ch_err = run_count_only(
                    db=DB,
                    role=adapter.role,
                    query_id=qid,
                    query_sql=prepared_sql,
                    statement_timeout_ms=statement_timeout_ms,
                    session_setup=(lambda cur, a=adapter, st=setup_state: a.session_setup(cur, enabled_path, statement_timeout_ms, st)),
                )
                if ch_err:
                    row["status"] = "error"
                    row["error_type"] = "count"
                    row["error_msg"] = _safe_err(ch_err)
                    cases.append(row)
                    continue

                row["_rows_int"] = int(cnt if cnt is not None else 0)
                row["rows"] = str(row["_rows_int"])

                cases.append(row)

            if setup_done:
                try:
                    adapter.teardown(DB, setup_state)
                except Exception:
                    pass

    gt_rows: Dict[Tuple[str, str], int] = {}
    for r in cases:
        if r["baseline"] == "rls_index" and r["status"] == "ok" and r.get("_rows_int") is not None:
            gt_rows[(str(r["policy_set_name"]), str(r["query_id"]))] = int(r["_rows_int"])

    for r in cases:
        if r["baseline"] == "no_policy":
            r["match_gt"] = "NA"
            r["gt_rows"] = ""
            continue
        gk = (str(r["policy_set_name"]), str(r["query_id"]))
        gv = gt_rows.get(gk)
        if gv is None:
            r["match_gt"] = "UNKNOWN"
            r["gt_rows"] = ""
            continue
        r["gt_rows"] = str(gv)
        if r["status"] != "ok" or r.get("_rows_int") is None:
            r["match_gt"] = "FALSE"
            continue
        r["match_gt"] = "TRUE" if int(r["_rows_int"]) == int(gv) else "FALSE"

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "db",
                "baseline",
                "policy_set_name",
                "policy_ids",
                "query_id",
                "status",
                "error_type",
                "error_msg",
                "hot_ms",
                "peak_rss_kb",
                "rows",
                "gt_rows",
                "match_gt",
                "setup_ms",
                "disk_bytes",
            ],
        )
        writer.writeheader()
        for r in cases:
            out = {k: r.get(k, "") for k in writer.fieldnames}
            writer.writerow(out)

    ok_rows = [r for r in cases if r["status"] == "ok"]
    err_rows = [r for r in cases if r["status"] != "ok"]
    mismatches = [
        r
        for r in ok_rows
        if r["baseline"] != "no_policy" and r.get("match_gt") == "FALSE"
    ]

    def med(vals: List[float]) -> str:
        if not vals:
            return "NA"
        return f"{statistics.median(vals):.3f}"

    ratio_lines: List[str] = []
    for b in ["view_based", "sieve_index", "ours"]:
        ratios: List[float] = []
        for ps_name, _ids in POLICY_SETS:
            for qid in QUERY_IDS:
                r_base = next((r for r in ok_rows if r["baseline"] == b and r["policy_set_name"] == ps_name and r["query_id"] == qid), None)
                r_gt = next((r for r in ok_rows if r["baseline"] == "rls_index" and r["policy_set_name"] == ps_name and r["query_id"] == qid), None)
                if not r_base or not r_gt:
                    continue
                try:
                    hb = float(r_base["hot_ms"])
                    hg = float(r_gt["hot_ms"])
                    if hg > 0:
                        ratios.append(hb / hg)
                except Exception:
                    continue
        ratio_lines.append(f"- median {b}/rls_index hot_ms ratio: {med(ratios)}")

    md: List[str] = []
    md.append("# tpch0_1 Gate After Fix")
    md.append("")
    md.append(f"- db: `{DB}`")
    md.append(f"- policy_sets: `{', '.join(name for name, _ in POLICY_SETS)}`")
    md.append(f"- baselines: `{', '.join(BASELINES)}`")
    md.append(f"- queries: `{', '.join('q'+q for q in QUERY_IDS)}`")
    md.append("")
    md.append(f"- total_cases: {len(cases)}")
    md.append(f"- ok: {len(ok_rows)}")
    md.append(f"- errors: {len(err_rows)}")
    md.append(f"- mismatches_vs_rls_index: {len(mismatches)}")
    md.append("")
    md.append("## Median Runtime Ratios")
    md.extend(ratio_lines)
    md.append("")

    md.append("## Errors")
    if not err_rows:
        md.append("- none")
    else:
        for r in err_rows[:50]:
            md.append(
                f"- {r['policy_set_name']} {r['baseline']} q{r['query_id']}: {r['error_type']} {r['error_msg']}"
            )
    md.append("")

    md.append("## Mismatches")
    if not mismatches:
        md.append("- none")
    else:
        for r in mismatches[:50]:
            md.append(
                f"- {r['policy_set_name']} {r['baseline']} q{r['query_id']}: rows={r['rows']} gt={r['gt_rows']}"
            )

    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
