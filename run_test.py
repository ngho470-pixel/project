#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import statistics
import time
from pathlib import Path
from typing import Dict, List, Tuple

import fast_sweep_profile_60s as h

from baselines import no_policy, ours, rls, rls_index, sieve, sieve_index, view_based
from baselines.common import BaselineAdapter, BaselineSetup
from utils.metrics import policy_complexity, policy_ids_csv, query_complexity
from utils.pg import run_count_hash, run_hygiene, run_query_trials


# ==============================
# Config (no argparse by design)
# ==============================
REPO_ROOT = Path(__file__).resolve().parent

DBS: List[str] = ["tpch0_1", "tpch1"]
BASELINES: List[str] = [
    "no_policy",
    "view_based",
    "rls",
    "rls_index",
    "sieve",
    "sieve_index",
    "ours",
]

POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"

POLICY_SETS: List[Tuple[str, List[int]]] = [
    ("1-5", list(range(1, 6))),
    ("1-10", list(range(1, 11))),
    ("11-15", list(range(11, 16))),
    ("11-20", list(range(11, 21))),
    ("21-25", list(range(21, 26))),
    ("21-30", list(range(21, 31))),
    ("5-15_U_25-30", list(range(5, 16)) + list(range(25, 31))),
]

QUERY_IDS: List[str] = [str(i) for i in range(1, 23)]

STATEMENT_TIMEOUT = "30min"
HOT_RUNS = 5

SMOKE_ONLY = False
if SMOKE_ONLY:
    DBS = ["tpch1"]
    POLICY_SETS = [
        ("1-5", list(range(1, 6))),
        ("11-20", list(range(11, 21))),
        ("21-30", list(range(21, 31))),
    ]
    QUERY_IDS = ["1", "3", "6", "10", "11"]
    BASELINES = ["no_policy", "view_based", "rls", "rls_index", "ours", "sieve", "sieve_index"]

# Connection target (reuses existing harness defaults)
PG_HOST = h.PG_HOST
PG_PORT = h.PG_PORT
h.PG_HOST = PG_HOST
h.PG_PORT = PG_PORT
# Avoid hanging on unavailable DB endpoints.
os.environ.setdefault("PGCONNECT_TIMEOUT", "5")

OUT_DIR = REPO_ROOT / "logs" / f"sweep_{time.strftime('%Y%m%d_%H%M%S')}"
OUT_CSV = OUT_DIR / "results.csv"
OUT_MD = OUT_DIR / "results.md"

RESULT_COLUMNS = [
    "db",
    "baseline",
    "query_id",
    "policy_set_name",
    "policy_ids",
    "num_policies",
    "query_complexity",
    "policy_complexity",
    "cold_ms",
    "hot_ms",
    "correctness",
    "mem_overhead_kb",
    "status",
    "error_type",
    "error_msg",
    "pre_run_memory_building_ms",
]


def parse_policy_ids(lines: List[str], ids: List[int]) -> List[str]:
    want = set(ids)
    out: List[str] = []
    for ln in lines:
        pid, _target, _expr = h.parse_policy_entry_with_id(ln)
        if pid is not None and int(pid) in want:
            out.append(ln)
    return out


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
        "rls": BaselineAdapter(
            name="rls",
            role="rls_user",
            setup=rls.setup,
            teardown=rls.teardown,
            session_setup=rls.session_setup,
            prepare_query=rls.prepare_query,
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
        "sieve": BaselineAdapter(
            name="sieve",
            role="postgres",
            setup=lambda db, policy_lines, enabled_path, timeout_ms: sieve.setup(
                db, policy_lines, enabled_path, timeout_ms, REPO_ROOT
            ),
            teardown=sieve.teardown,
            session_setup=sieve.session_setup,
            prepare_query=lambda qid, qsql, st, db, host, port: sieve.prepare_query(
                qid, qsql, st, db, host, port
            ),
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


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    statement_timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)
    policy_lines_all = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}

    adapters = make_adapters()

    rows: List[Dict[str, object]] = []

    # Ground truth cache from rls_index.
    gt: Dict[Tuple[str, str, str], Tuple[int, str, int]] = {}

    # No-policy memory baseline cache.
    mem_base: Dict[Tuple[str, str, str], int] = {}

    baseline_order = [b for b in BASELINES if b in adapters]

    for db in DBS:
        ok_h, hdiag = run_hygiene(REPO_ROOT, db)
        print(f"[hygiene] db={db} ok={int(ok_h)} diag={(hdiag or '')[:120]}")

        for policy_set_name, policy_ids in POLICY_SETS:
            active_policy_lines = parse_policy_ids(policy_lines_all, policy_ids)
            enabled_path = Path("/tmp") / f"run_test_{db}_{policy_set_name}.txt"
            h.write_enabled_policy_file(active_policy_lines, enabled_path)

            for baseline in baseline_order:
                adapter = adapters[baseline]
                setup_state = BaselineSetup()
                setup_error = ""
                setup_done = False

                ok_h2, hdiag2 = run_hygiene(REPO_ROOT, db)
                if not ok_h2:
                    setup_error = f"db_hygiene_failed: {hdiag2[:300]}".replace("\n", " ").replace("\r", " ")

                try:
                    if not setup_error:
                        setup_state = adapter.setup(db, active_policy_lines, enabled_path, statement_timeout_ms)
                        setup_done = True
                except Exception as exc:  # noqa: BLE001
                    setup_error = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:500]

                for qid in QUERY_IDS:
                    if qid not in qmap:
                        continue
                    raw_q = qmap[qid]
                    q_comp = query_complexity(raw_q)
                    p_comp = policy_complexity(active_policy_lines, raw_q, h.parse_policy_entry_with_id)

                    row = {
                        "db": db,
                        "baseline": baseline,
                        "query_id": qid,
                        "policy_set_name": policy_set_name,
                        "policy_ids": policy_ids_csv(policy_ids),
                        "num_policies": len(policy_ids),
                        "query_complexity": q_comp,
                        "policy_complexity": p_comp,
                        "cold_ms": "",
                        "hot_ms": "",
                        "correctness": "UNKNOWN",
                        "mem_overhead_kb": "",
                        "status": 0,
                        "error_type": "",
                        "error_msg": "",
                        "pre_run_memory_building_ms": f"{setup_state.pre_run_memory_building_ms:.3f}",
                        # internal keys
                        "_hot_peak_rss_kb": 0,
                        "_count": None,
                        "_hash": None,
                        "_inv_sig": "",
                        "_inv_mask": "",
                        "_inv_rid": "",
                    }

                    if setup_error:
                        row["status"] = 0
                        row["error_type"] = "setup_error"
                        row["error_msg"] = setup_error
                        rows.append(row)
                        continue

                    try:
                        if baseline.startswith("sieve"):
                            sql_to_run, prep_err = adapter.prepare_query(qid, raw_q, setup_state, db, PG_HOST, PG_PORT)
                        else:
                            sql_to_run, prep_err = adapter.prepare_query(qid, raw_q, setup_state)
                    except Exception as exc:  # noqa: BLE001
                        sql_to_run, prep_err = "", (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:500]

                    if prep_err:
                        row["status"] = 0
                        row["error_type"] = "prepare_error"
                        row["error_msg"] = prep_err
                        rows.append(row)
                        continue

                    def _session_setup(cur):
                        return adapter.session_setup(cur, enabled_path, statement_timeout_ms, setup_state)

                    run = run_query_trials(
                        db,
                        adapter.role,
                        sql_to_run,
                        statement_timeout_ms,
                        HOT_RUNS,
                        session_setup=_session_setup,
                        capture_notices_cold=adapter.captures_notices,
                    )

                    row["cold_ms"] = f"{run.cold_ms:.3f}"
                    row["hot_ms"] = f"{run.hot_ms:.3f}" if run.status == 1 else ""
                    row["status"] = int(run.status)
                    row["error_type"] = run.error_type
                    row["error_msg"] = run.error_msg
                    row["_hot_peak_rss_kb"] = int(run.hot_peak_rss_kb)

                    if baseline == "ours" and run.notices:
                        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(run.notices)
                        row["_inv_sig"] = str(ppq_kv.get("proj_sig_count", "0"))
                        row["_inv_mask"] = str(ppq_kv.get("proj_mask_or_ops", "0"))
                        row["_inv_rid"] = str(ppq_kv.get("proj_rid_iters", "0"))
                        if row["status"] == 1 and (
                            row["_inv_sig"] not in ("0", "0.000", "")
                            or row["_inv_mask"] not in ("0", "0.000", "")
                            or row["_inv_rid"] not in ("0", "0.000", "")
                        ):
                            row["status"] = 0
                            row["error_type"] = "invariant"
                            row["error_msg"] = (
                                f"proj_sig_count={row['_inv_sig']} proj_mask_or_ops={row['_inv_mask']} "
                                f"proj_rid_iters={row['_inv_rid']}"
                            )

                    if row["status"] == 1:
                        cnt, hh, cerr = run_count_hash(
                            db,
                            adapter.role,
                            qid,
                            sql_to_run,
                            statement_timeout_ms,
                            session_setup=_session_setup,
                        )
                        if cnt is None:
                            row["status"] = 0
                            row["error_type"] = "count_hash"
                            row["error_msg"] = cerr
                        else:
                            row["_count"] = int(cnt)
                            row["_hash"] = str(hh)

                    key = (db, policy_set_name, qid)
                    if baseline == "rls_index":
                        if row["status"] == 1 and row["_count"] is not None:
                            gt[key] = (int(row["_count"]), str(row["_hash"]), 1)
                        else:
                            gt[key] = (0, "", 0)

                    if baseline == "no_policy" and row["status"] == 1:
                        mem_base[key] = int(row["_hot_peak_rss_kb"])

                    rows.append(row)

                    print(
                        f"[run_test] db={db} baseline={baseline} policy_set={policy_set_name} q{qid} "
                        f"status={row['status']} cold={row['cold_ms']} hot={row['hot_ms']} err={row['error_type'] or '-'}"
                    )

                try:
                    if setup_done:
                        adapter.teardown(db, setup_state)
                except Exception as exc:  # noqa: BLE001
                    print(f"[warn] teardown failed baseline={baseline} db={db} policy_set={policy_set_name}: {exc}")

    # Finalize correctness + memory deltas.
    for row in rows:
        key = (str(row["db"]), str(row["policy_set_name"]), str(row["query_id"]))
        if row["status"] != 1:
            row["correctness"] = "UNKNOWN"
        elif row["baseline"] == "rls_index":
            row["correctness"] = "TRUE"
        else:
            gt_entry = gt.get(key)
            if not gt_entry or gt_entry[2] != 1:
                row["correctness"] = "UNKNOWN"
            else:
                if row["_count"] == gt_entry[0] and str(row["_hash"]) == str(gt_entry[1]):
                    row["correctness"] = "TRUE"
                else:
                    row["correctness"] = "FALSE"
                    if not row["error_type"]:
                        row["error_type"] = "mismatch"
                    if not row["error_msg"]:
                        row["error_msg"] = "rows/hash mismatch vs rls_index"

        base = mem_base.get(key)
        if base is None or row["status"] != 1:
            row["mem_overhead_kb"] = ""
        else:
            row["mem_overhead_kb"] = str(int(row["_hot_peak_rss_kb"]) - int(base))

    # Write CSV with required columns.
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        w.writeheader()
        for r in rows:
            out_row = {k: r.get(k, "") for k in RESULT_COLUMNS}
            out_row["error_msg"] = str(out_row.get("error_msg", "")).replace("\n", " ").replace("\r", " ")
            w.writerow(out_row)

    # Summary markdown.
    total = len(rows)
    ok = sum(1 for r in rows if int(r.get("status", 0)) == 1)
    fail = total - ok

    ours_rows = [r for r in rows if r["baseline"] == "ours" and int(r.get("status", 0)) == 1]
    rls_rows = {
        (r["db"], r["policy_set_name"], r["query_id"]): float(r["hot_ms"])
        for r in rows
        if r["baseline"] == "rls_index" and int(r.get("status", 0)) == 1 and r.get("hot_ms")
    }
    ratios = []
    for r in ours_rows:
        k = (r["db"], r["policy_set_name"], r["query_id"])
        if k in rls_rows and r.get("hot_ms"):
            try:
                ratios.append(float(r["hot_ms"]) / float(rls_rows[k]))
            except Exception:
                pass

    lines = [
        "# Sweep Results",
        "",
        f"- out_csv: `{OUT_CSV}`",
        f"- total_cases: {total}",
        f"- status_ok: {ok}",
        f"- status_error_or_timeout: {fail}",
    ]
    if ratios:
        lines.append(f"- median ours/rls_index hot_ms ratio: {statistics.median(ratios):.3f}")

    # quick baseline pass matrix
    lines.append("")
    lines.append("## Baseline Status")
    for b in BASELINES:
        br = [r for r in rows if r["baseline"] == b]
        b_ok = sum(1 for r in br if int(r.get("status", 0)) == 1)
        b_true = sum(1 for r in br if r.get("correctness") == "TRUE")
        lines.append(f"- {b}: ok={b_ok}/{len(br)} correctness_true={b_true}/{len(br)}")

    lines.append("")
    lines.append("## Notes")
    lines.append("- correctness compares each baseline against `rls_index` row-count+hash for the same (db, policy_set, query).")
    lines.append("- if `rls_index` fails for a case, correctness is marked `UNKNOWN` for that case.")

    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[done] wrote {OUT_CSV}")
    print(f"[done] wrote {OUT_MD}")


if __name__ == "__main__":
    main()
