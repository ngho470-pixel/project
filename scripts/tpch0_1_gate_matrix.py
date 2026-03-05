#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

from psycopg2 import sql

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import fast_sweep_profile_60s as h
from baselines import no_policy, ours, rls, rls_index, sieve, sieve_index, view_based
from baselines.common import BaselineAdapter, BaselineSetup
from utils.pg import run_count_only, run_hygiene, run_query_trials


DB = "tpch0_1"
POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"

QUERY_IDS: List[str] = ["1", "3", "6", "10", "11"]
POLICY_SETS: List[Tuple[str, List[int]]] = [
    ("S_A", list(range(1, 6))),
    ("S_B", list(range(1, 11))),
    ("S_C", list(range(11, 16))),
    ("S_D", list(range(11, 21))),
    ("S_E", list(range(21, 26))),
    ("S_F", list(range(21, 31))),
    ("S_G", list(range(5, 16)) + list(range(25, 31))),
]
BASELINES: List[str] = ["no_policy", "view_based", "rls", "rls_index", "sieve", "sieve_index", "ours"]

STATEMENT_TIMEOUT = "30min"
HOT_RUNS = 1

OUT_CORR = REPO_ROOT / "logs" / "tpch0_1_gate_correctness.csv"
OUT_PERF = REPO_ROOT / "logs" / "tpch0_1_gate_perf.csv"
OUT_BUILD = REPO_ROOT / "logs" / "tpch0_1_gate_build_disk.csv"
OUT_MD = REPO_ROOT / "logs" / "tpch0_1_gate_summary.md"


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


def _index_breakdown(db: str) -> Tuple[int, int]:
    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(pg_total_relation_size(c.oid)), 0) "
                "FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname='public' AND c.relkind='i' AND c.relname LIKE 'cf_rls_k%';"
            )
            row = cur.fetchone() or (0, 0)
            return int(row[0] or 0), int(row[1] or 0)
    finally:
        conn.close()


def _ours_artifact_breakdown(db: str, enabled_path: Path) -> Dict[str, int]:
    run_id = h.artifact_run_id_for_enabled(enabled_path)
    files_table = h.artifact_table_for_run_id(run_id)
    schema, table = h._split_qualified_ident(files_table)
    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL(
                    "SELECT "
                    "COALESCE(SUM(octet_length(file)),0), "
                    "COALESCE(SUM(CASE WHEN name LIKE 'bin/%%' THEN octet_length(file) ELSE 0 END),0), "
                    "COALESCE(SUM(CASE WHEN name LIKE 'meta/%%' THEN octet_length(file) ELSE 0 END),0), "
                    "COALESCE(SUM(CASE WHEN name LIKE 'dict/%%' THEN octet_length(file) ELSE 0 END),0), "
                    "COALESCE(SUM(CASE WHEN name LIKE 'rank/%%' THEN octet_length(file) ELSE 0 END),0) "
                    "FROM {}.{} WHERE COALESCE(run_id,'')=%s;"
                ).format(sql.Identifier(schema), sql.Identifier(table)),
                [run_id],
            )
            row = cur.fetchone() or (0, 0, 0, 0, 0)
            return {
                "artifacts_bytes": int(row[0] or 0),
                "bin_bytes": int(row[1] or 0),
                "meta_bytes": int(row[2] or 0),
                "dict_bytes": int(row[3] or 0),
                "rank_bytes": int(row[4] or 0),
            }
    finally:
        conn.close()


def _safe_err(msg: object) -> str:
    return str(msg or "").replace("\n", " ").replace("\r", " ").strip()[:500]


def main() -> None:
    OUT_CORR.parent.mkdir(parents=True, exist_ok=True)

    statement_timeout_ms = h.parse_timeout_ms(STATEMENT_TIMEOUT)
    adapters = make_adapters()
    policy_lines_all = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}

    run_hyg_ok, run_hyg_msg = run_hygiene(REPO_ROOT, DB)
    if not run_hyg_ok:
        raise RuntimeError(f"db hygiene failed before run: {_safe_err(run_hyg_msg)}")

    cases: List[Dict[str, object]] = []
    build_rows: List[Dict[str, object]] = []
    gt: Dict[Tuple[str, str], int] = {}

    for policy_set_name, policy_ids in POLICY_SETS:
        active_policy_lines = parse_policy_ids(policy_lines_all, policy_ids)
        enabled_path = Path("/tmp") / f"tpch0_1_gate_{policy_set_name}.txt"
        h.write_enabled_policy_file(active_policy_lines, enabled_path)

        for baseline in BASELINES:
            adapter = adapters[baseline]
            setup_state = BaselineSetup()
            setup_error = ""
            setup_done = False

            ok_h, hmsg = run_hygiene(REPO_ROOT, DB)
            if not ok_h:
                setup_error = f"db_hygiene_failed: {_safe_err(hmsg)}"

            t_setup0 = time.perf_counter()
            if not setup_error:
                try:
                    setup_state = adapter.setup(DB, active_policy_lines, enabled_path, statement_timeout_ms)
                    setup_done = True
                except Exception as exc:  # noqa: BLE001
                    setup_error = _safe_err(getattr(exc, "pgerror", None) or exc)
            t_setup_ms = (time.perf_counter() - t_setup0) * 1000.0

            if baseline in ("rls_index", "sieve_index", "ours"):
                breakdown: Dict[str, object]
                disk_bytes_total = int(setup_state.disk_overhead_bytes or 0)
                if baseline == "rls_index":
                    idx_count, idx_bytes = _index_breakdown(DB)
                    disk_bytes_total = idx_bytes
                    breakdown = {
                        "indexes_bytes": idx_bytes,
                        "policies_count": len(policy_ids),
                        "indexes_count": idx_count,
                    }
                elif baseline == "sieve_index":
                    idx_count, idx_bytes = _index_breakdown(DB)
                    disk_bytes_total = idx_bytes
                    breakdown = {
                        "sieve_bytes": 0,
                        "indexes_bytes": idx_bytes,
                        "indexes_count": idx_count,
                        "views_count": len((setup_state.state or {}).get("views", [])),
                        "mode": str((setup_state.state or {}).get("mode", "")),
                    }
                else:
                    ours_b = _ours_artifact_breakdown(DB, enabled_path)
                    disk_bytes_total = int(ours_b.get("artifacts_bytes", disk_bytes_total))
                    breakdown = ours_b

                build_rows.append(
                    {
                        "db": DB,
                        "baseline": baseline,
                        "policy_set_name": policy_set_name,
                        "policy_ids": policy_ids_csv(policy_ids),
                        "build_ms": f"{(setup_state.pre_run_memory_building_ms or t_setup_ms):.3f}",
                        "disk_bytes_total": str(int(disk_bytes_total)),
                        "disk_bytes_breakdown_json": json.dumps(breakdown, sort_keys=True),
                    }
                )

            for qid in QUERY_IDS:
                if qid not in qmap:
                    continue

                base = {
                    "db": DB,
                    "baseline": baseline,
                    "policy_set_name": policy_set_name,
                    "policy_ids": policy_ids_csv(policy_ids),
                    "query_id": qid,
                    "status_int": 0,
                    "rows": "",
                    "_rows_int": None,
                    "hot_ms": "",
                    "peak_rss_kb": "",
                    "error_msg": "",
                    "error_type": "",
                }

                if setup_error:
                    base["error_type"] = "setup_error"
                    base["error_msg"] = setup_error
                    cases.append(base)
                    continue

                qsql = qmap[qid]
                try:
                    if baseline.startswith("sieve"):
                        sql_to_run, prep_err = adapter.prepare_query(qid, qsql, setup_state, DB, h.PG_HOST, h.PG_PORT)
                    else:
                        sql_to_run, prep_err = adapter.prepare_query(qid, qsql, setup_state)
                except Exception as exc:  # noqa: BLE001
                    sql_to_run, prep_err = "", _safe_err(getattr(exc, "pgerror", None) or exc)

                if prep_err:
                    base["error_type"] = "prepare_error"
                    base["error_msg"] = prep_err
                    cases.append(base)
                    continue

                def _session_setup(cur):
                    return adapter.session_setup(cur, enabled_path, statement_timeout_ms, setup_state)

                run = run_query_trials(
                    DB,
                    adapter.role,
                    sql_to_run,
                    statement_timeout_ms,
                    HOT_RUNS,
                    session_setup=_session_setup,
                    capture_notices_cold=adapter.captures_notices,
                )
                base["hot_ms"] = f"{run.hot_ms:.3f}" if run.status == 1 else ""
                base["peak_rss_kb"] = str(int(run.hot_peak_rss_kb)) if run.status == 1 else ""
                base["status_int"] = int(run.status)
                base["error_type"] = run.error_type
                base["error_msg"] = run.error_msg

                if baseline == "ours" and run.notices:
                    _payload, ppq_kv, _cnt = h.extract_policy_profile_query(run.notices)
                    inv_sig = str(ppq_kv.get("proj_sig_count", "0"))
                    inv_mask = str(ppq_kv.get("proj_mask_or_ops", "0"))
                    inv_rid = str(ppq_kv.get("proj_rid_iters", "0"))
                    if base["status_int"] == 1 and (
                        inv_sig not in ("0", "0.000", "")
                        or inv_mask not in ("0", "0.000", "")
                        or inv_rid not in ("0", "0.000", "")
                    ):
                        base["status_int"] = 0
                        base["error_type"] = "invariant"
                        base["error_msg"] = f"proj_sig_count={inv_sig} proj_mask_or_ops={inv_mask} proj_rid_iters={inv_rid}"

                if base["status_int"] == 1:
                    cnt, cerr = run_count_only(
                        DB,
                        adapter.role,
                        qid,
                        sql_to_run,
                        statement_timeout_ms,
                        session_setup=_session_setup,
                    )
                    if cnt is None:
                        base["status_int"] = 0
                        base["error_type"] = "count"
                        base["error_msg"] = cerr
                    else:
                        base["_rows_int"] = int(cnt)
                        base["rows"] = str(int(cnt))
                        if baseline == "rls_index":
                            gt[(policy_set_name, qid)] = int(cnt)

                cases.append(base)
                print(
                    f"[gate] set={policy_set_name} baseline={baseline} q{qid} "
                    f"status={base['status_int']} hot_ms={base['hot_ms'] or '-'} err={base['error_type'] or '-'}"
                )

            try:
                if setup_done:
                    adapter.teardown(DB, setup_state)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] teardown failed baseline={baseline} set={policy_set_name}: {_safe_err(exc)}")

    # correctness + perf tables
    corr_rows: List[Dict[str, str]] = []
    perf_rows: List[Dict[str, str]] = []
    mismatch_rows: List[Dict[str, str]] = []
    error_rows: List[Dict[str, str]] = []

    for c in cases:
        key = (str(c["policy_set_name"]), str(c["query_id"]))
        gt_entry = gt.get(key)
        gt_rows = str(gt_entry) if gt_entry is not None else ""

        if c["baseline"] == "no_policy":
            match_gt = "NA"
        elif c["status_int"] != 1:
            match_gt = "FALSE" if gt_entry else "UNKNOWN"
        elif not gt_entry:
            match_gt = "UNKNOWN"
        elif str(c["rows"]) == str(gt_entry):
            match_gt = "TRUE"
        else:
            match_gt = "FALSE"

        if c["status_int"] != 1:
            status_txt = "error"
        elif c["baseline"] != "no_policy" and match_gt == "FALSE":
            status_txt = "fail"
        else:
            status_txt = "ok"

        corr_row = {
            "db": str(c["db"]),
            "baseline": str(c["baseline"]),
            "policy_set_name": str(c["policy_set_name"]),
            "policy_ids": str(c["policy_ids"]),
            "query_id": str(c["query_id"]),
            "status": status_txt,
                "rows": str(c["rows"]),
                "gt_rows": gt_rows,
                "match_gt": match_gt,
            "error_msg": _safe_err(c["error_msg"]),
        }
        corr_rows.append(corr_row)

        perf_rows.append(
            {
                "db": str(c["db"]),
                "baseline": str(c["baseline"]),
                "policy_set_name": str(c["policy_set_name"]),
                "policy_ids": str(c["policy_ids"]),
                "query_id": str(c["query_id"]),
                "hot_ms": str(c["hot_ms"]),
                "peak_rss_kb": str(c["peak_rss_kb"]),
                "rows": str(c["rows"]),
                "status": "ok" if c["status_int"] == 1 else "error",
                "error_msg": _safe_err(c["error_msg"]),
            }
        )

        if status_txt == "error":
            error_rows.append(corr_row)
        elif status_txt == "fail":
            mismatch_rows.append(corr_row)

    with OUT_CORR.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "db",
                "baseline",
                "policy_set_name",
                "policy_ids",
                "query_id",
                "status",
                "rows",
                "gt_rows",
                "match_gt",
                "error_msg",
            ],
        )
        w.writeheader()
        for r in corr_rows:
            w.writerow(r)

    with OUT_PERF.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "db",
                "baseline",
                "policy_set_name",
                "policy_ids",
                "query_id",
                "hot_ms",
                "peak_rss_kb",
                "rows",
                "status",
                "error_msg",
            ],
        )
        w.writeheader()
        for r in perf_rows:
            w.writerow(r)

    with OUT_BUILD.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "db",
                "baseline",
                "policy_set_name",
                "policy_ids",
                "build_ms",
                "disk_bytes_total",
                "disk_bytes_breakdown_json",
            ],
        )
        w.writeheader()
        for r in build_rows:
            w.writerow(r)

    # Summary
    ratio_by_baseline: Dict[str, List[float]] = {}
    rls_hot: Dict[Tuple[str, str], float] = {}
    for r in perf_rows:
        if r["baseline"] == "rls_index" and r["status"] == "ok" and r["hot_ms"]:
            rls_hot[(r["policy_set_name"], r["query_id"])] = float(r["hot_ms"])
    for r in perf_rows:
        if r["baseline"] == "rls_index" or r["status"] != "ok" or not r["hot_ms"]:
            continue
        k = (r["policy_set_name"], r["query_id"])
        if k in rls_hot and rls_hot[k] > 0:
            ratio_by_baseline.setdefault(r["baseline"], []).append(float(r["hot_ms"]) / rls_hot[k])

    med_rss: Dict[str, float] = {}
    for b in BASELINES:
        vals = [int(r["peak_rss_kb"]) for r in perf_rows if r["baseline"] == b and r["status"] == "ok" and r["peak_rss_kb"]]
        if vals:
            med_rss[b] = float(statistics.median(vals))

    lines = [
        "# tpch0_1 Gate Summary",
        "",
        f"- db: `{DB}`",
        f"- queries: `{','.join(QUERY_IDS)}`",
        f"- policy_sets: `{', '.join(name for name, _ in POLICY_SETS)}`",
        f"- baselines: `{', '.join(BASELINES)}`",
        f"- statement_timeout: `{STATEMENT_TIMEOUT}`",
        f"- hot_runs: {HOT_RUNS}",
        "",
        "## Overall",
        f"- total_cases: {len(corr_rows)}",
        f"- ok: {sum(1 for r in corr_rows if r['status'] == 'ok')}",
        f"- fail_mismatch: {sum(1 for r in corr_rows if r['status'] == 'fail')}",
        f"- error: {sum(1 for r in corr_rows if r['status'] == 'error')}",
        "",
        "## Baseline Errors",
    ]
    if not error_rows:
        lines.append("- none")
    else:
        for r in error_rows[:50]:
            lines.append(
                f"- {r['baseline']} {r['policy_set_name']} q{r['query_id']}: {r['error_msg']}"
            )

    lines.append("")
    lines.append("## Mismatches vs rls_index")
    if not mismatch_rows:
        lines.append("- none")
    else:
        for r in mismatch_rows[:50]:
            lines.append(
                f"- {r['baseline']} {r['policy_set_name']} q{r['query_id']}: rows={r['rows']} gt={r['gt_rows']}"
            )

    lines.append("")
    lines.append("## Median Runtime Ratios vs rls_index")
    for b in ["view_based", "rls", "sieve", "sieve_index", "ours"]:
        vals = ratio_by_baseline.get(b, [])
        if vals:
            lines.append(f"- {b}: {statistics.median(vals):.3f}")
        else:
            lines.append(f"- {b}: NA")

    lines.append("")
    lines.append("## Median Peak RSS (kB)")
    for b in BASELINES:
        if b in med_rss:
            lines.append(f"- {b}: {med_rss[b]:.1f}")
        else:
            lines.append(f"- {b}: NA")

    lines.append("")
    lines.append("## Build + Disk (rls_index / sieve_index / ours)")
    for r in build_rows:
        lines.append(
            f"- {r['baseline']} {r['policy_set_name']}: build_ms={r['build_ms']} "
            f"disk_bytes_total={r['disk_bytes_total']} breakdown={r['disk_bytes_breakdown_json']}"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("- Ground truth is `rls_index` for each (policy_set, query).")
    lines.append("- For `no_policy`, `match_gt` is `NA` by design.")
    lines.append("- `hot_ms` is a single run (`hot_runs=1`) for this gate.")

    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[done] wrote {OUT_CORR}")
    print(f"[done] wrote {OUT_PERF}")
    print(f"[done] wrote {OUT_BUILD}")
    print(f"[done] wrote {OUT_MD}")


if __name__ == "__main__":
    main()
