#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / "custom_filter" / "custom_filter.so")
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / "artifact_builder" / "artifact_builder.so")

OUT_CSV = REPO_ROOT / "logs" / "policy_pool_single_policy_smoke.csv"
OUT_MD = REPO_ROOT / "logs" / "policy_pool_single_policy_smoke.md"
DEFAULT_POLICY_FILE = REPO_ROOT / "policy.txt"
DEFAULT_QUERY_FILE = REPO_ROOT / "queries.txt"


@dataclass(frozen=True)
class PolicyEntry:
    policy_id: int
    target: str
    line: str


TARGET_QUERY_CANDIDATES: Dict[str, Tuple[str, ...]] = {
    "lineitem": ("1", "6"),
    "orders": ("3",),
    "customer": ("13", "22"),
    "supplier": ("5", "2"),
    "nation": ("5",),
    "region": ("5",),
    "partsupp": ("11", "9", "2"),
    "part": ("2", "14"),
}


def parse_policy_pool(path: Path, lo: int, hi: int) -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("--"):
            continue
        pid, target, _expr = h.parse_policy_entry_with_id(line)
        if pid is None or not target:
            continue
        if lo <= int(pid) <= hi:
            out.append(PolicyEntry(int(pid), target, line))
    out.sort(key=lambda x: x.policy_id)
    return out


def load_all_queries(path: Path) -> Dict[str, str]:
    return {qid: qsql for qid, qsql in h.load_queries(path)}


@contextmanager
def strict_env():
    old_pgoptions = os.environ.get("PGOPTIONS")
    old_cf_strict = os.environ.get("CF_POLICY_STRICT_MODE")
    os.environ["PGOPTIONS"] = "-c custom_filter.strict_mode=on -c custom_filter.query_driven_mode=off"
    os.environ["CF_POLICY_STRICT_MODE"] = "1"
    try:
        yield
    finally:
        if old_pgoptions is None:
            os.environ.pop("PGOPTIONS", None)
        else:
            os.environ["PGOPTIONS"] = old_pgoptions
        if old_cf_strict is None:
            os.environ.pop("CF_POLICY_STRICT_MODE", None)
        else:
            os.environ["CF_POLICY_STRICT_MODE"] = old_cf_strict


def run_hygiene(db: str) -> Tuple[bool, str]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "pg_hygiene.py"),
        "--db",
        db,
        "--kill-nonidle",
        "--fail-loud",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
        txt = ((out.stdout or "") + "\n" + (out.stderr or "")).strip()
        return True, txt
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if hasattr(exc, "stdout") or hasattr(exc, "stderr"):
            msg = (
                ((getattr(exc, "stdout", "") or "") + "\n" + (getattr(exc, "stderr", "") or "")).strip()
                or msg
            )
        return False, msg.replace("\n", " ")[:600]


def run_count_hash(db: str, baseline: str, query_id: str, query_sql: str, enabled_path: Path, timeout_ms: int):
    conn = None
    try:
        conn = h.connect(db, h.role_for_baseline(baseline))
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, timeout_ms)
            if baseline in ("rls", "rls_with_index"):
                cur.execute("SET row_security = on;")
            cnt, hh = h.result_count_and_hash_in_session(cur, query_id, query_sql)
            return int(cnt), str(hh or ""), ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, None, msg[:600]
    finally:
        if conn is not None:
            conn.close()


def parse_routes(notices: List[str]) -> Tuple[str, str, str]:
    route_counts: Dict[str, int] = {}
    reject_reasons: List[str] = []
    for line in notices:
        if "class_route_term:" not in line:
            continue
        m_route = re.search(r"\broute=([A-Za-z0-9_]+)", line)
        if not m_route:
            continue
        route = m_route.group(1)
        route_counts[route] = route_counts.get(route, 0) + 1
        if route == "reject":
            m_reason = re.search(r"\breason=([A-Za-z0-9_./:-]+)", line)
            if m_reason:
                reject_reasons.append(m_reason.group(1))
    if not route_counts:
        return "", "", ""
    ordered = sorted(route_counts.items(), key=lambda kv: kv[0])
    route_summary = ",".join(f"{k}:{v}" for k, v in ordered)
    main_route = sorted(ordered, key=lambda kv: (-kv[1], kv[0]))[0][0]
    reject_summary = ",".join(sorted(set(reject_reasons))) if reject_reasons else ""
    return main_route, route_summary, reject_summary


def run_ours_count_hash_with_profile(
    db: str,
    query_id: str,
    query_sql: str,
    enabled_path: Path,
    timeout_ms: int,
    profile_k: int,
):
    conn = None
    try:
        conn = h.connect(db, "postgres")
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, "ours", enabled_path, timeout_ms, ours_debug_mode="trace")
            cur.execute("SET client_min_messages = notice;")
            cur.execute("SET custom_filter.profile_k = %s;", [int(profile_k)])
            cur.execute("SET custom_filter.profile_query = %s;", [str(query_id)])

            base_sql: Optional[str] = query_sql if h.is_single_select(query_sql) else h.timing_fallback_sql(query_id)
            wrapped = h.count_and_hash_wrapper(base_sql) if base_sql is not None else None
            if wrapped is None:
                return None, None, {}, "", "", "", f"unsupported query for count+hash wrapper: q{query_id}"

            del conn.notices[:]
            metrics, result_rows = h.execute_with_rss_fetchall(cur, wrapped)
            notices = [n.replace("\n", " ").strip() for n in conn.notices]
            del conn.notices[:]

            _pp_payload, _pp_kv, _pp_cnt = h.extract_policy_profile(notices)
            _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
            route_main, route_summary, route_reject_reason = parse_routes(notices)

            if metrics.status != "ok":
                return None, None, ppq_kv, route_main, route_summary, route_reject_reason, metrics.error_msg or "profile capture failed"
            if not result_rows or len(result_rows[0]) < 2:
                return None, None, ppq_kv, route_main, route_summary, route_reject_reason, "count+hash wrapper returned no rows"
            cnt = int(result_rows[0][0])
            hh = str(result_rows[0][1] or "")
            return cnt, hh, ppq_kv, route_main, route_summary, route_reject_reason, ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, None, {}, "", "", "", msg[:600]
    finally:
        if conn is not None:
            conn.close()


def qid_for_target(target: str, all_qmap: Dict[str, str]) -> str:
    for cand in TARGET_QUERY_CANDIDATES.get(target, ("1",)):
        if cand in all_qmap:
            return cand
    return "1"


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Single-policy strict smoke over policy pool 1..30")
    ap.add_argument("--db", default="tpch1")
    ap.add_argument("--policy-file", default=str(DEFAULT_POLICY_FILE))
    ap.add_argument("--query-file", default=str(DEFAULT_QUERY_FILE))
    ap.add_argument("--policy-min", type=int, default=1)
    ap.add_argument("--policy-max", type=int, default=30)
    ap.add_argument("--statement-timeout", default="0")
    ap.add_argument("--out-csv", default=str(OUT_CSV))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    all_qmap = load_all_queries(Path(args.query_file))
    policies = parse_policy_pool(Path(args.policy_file), int(args.policy_min), int(args.policy_max))

    cols = [
        "db",
        "policy_id",
        "target",
        "query_id",
        "status",
        "correctness",
        "reason",
        "route_main",
        "route_summary",
        "route_reject_reason",
        "ours_rows",
        "ours_hash",
        "gt_rows",
        "gt_hash",
        "policy_total_ms",
        "class_terms_ok",
        "class_terms_reject",
        "class_route_single_hub",
        "class_route_two_hop",
        "class_route_tree",
        "class_route_cycle_rect",
        "class_route_td_cycle",
        "class_route_reject",
        "pf2_cmp_key_arity_max",
        "pf2_hub_key_arity",
        "proj_sig_count",
        "proj_mask_or_ops",
        "proj_rid_iters",
        "hygiene_ok",
    ]
    rows: List[Dict[str, str]] = []
    case_idx = 0

    for p in policies:
        enabled = Path("/tmp") / f"policy_pool_single_{p.policy_id}.txt"
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)
        qid = qid_for_target(p.target, all_qmap)
        qsql = all_qmap[qid]

        row = {k: "" for k in cols}
        row.update({"db": db, "policy_id": str(p.policy_id), "target": p.target, "query_id": qid, "hygiene_ok": "0"})

        ok_h, diag = run_hygiene(db)
        if not ok_h:
            row["status"] = "ERROR"
            row["correctness"] = "ERROR"
            row["reason"] = f"db_hygiene_failed: {diag[:300]}"
            rows.append(row)
            print(f"[single_smoke] policy={p.policy_id} q={qid} status=ERROR reason=db_hygiene_failed")
            continue
        row["hygiene_ok"] = "1"

        ours_rows = None
        ours_hash = None
        ours_err = ""
        gt_rows = None
        gt_hash = None
        gt_err = ""
        ppq: Dict[str, str] = {}
        route_main = ""
        route_summary = ""
        route_reject_reason = ""

        try:
            case_idx += 1
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, case_idx, enabled, timeout_ms)
            case_idx += 1
            ours_rows, ours_hash, ppq, route_main, route_summary, route_reject_reason, ours_err = run_ours_count_hash_with_profile(
                db, qid, qsql, enabled, timeout_ms, case_idx
            )

            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [p.line])
            h.create_rls_indexes_for_k(db, case_idx, [p.line], timeout_ms)
            gt_rows, gt_hash, gt_err = run_count_hash(db, "rls_with_index", qid, qsql, enabled, timeout_ms)
        except Exception as exc:  # noqa: BLE001
            ours_err = ours_err or (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:600]
        finally:
            try:
                h.clear_rls_indexes_and_policies(db)
            except Exception:
                pass
            try:
                h.clear_artifacts(db)
            except Exception:
                pass

        row["route_main"] = route_main
        row["route_summary"] = route_summary
        row["route_reject_reason"] = route_reject_reason
        row["ours_rows"] = "" if ours_rows is None else str(ours_rows)
        row["ours_hash"] = "" if ours_hash is None else str(ours_hash)
        row["gt_rows"] = "" if gt_rows is None else str(gt_rows)
        row["gt_hash"] = "" if gt_hash is None else str(gt_hash)
        for k in [
            "policy_total_ms",
            "class_terms_ok",
            "class_terms_reject",
            "class_route_single_hub",
            "class_route_two_hop",
            "class_route_tree",
            "class_route_cycle_rect",
            "class_route_td_cycle",
            "class_route_reject",
            "pf2_cmp_key_arity_max",
            "pf2_hub_key_arity",
            "proj_sig_count",
            "proj_mask_or_ops",
            "proj_rid_iters",
        ]:
            row[k] = str(ppq.get(k, ""))

        reason_parts: List[str] = []
        if ours_err:
            reason_parts.append(f"ours:{ours_err}")
        if gt_err:
            reason_parts.append(f"gt:{gt_err}")
        row["reason"] = " | ".join(reason_parts)

        if ours_rows is None or gt_rows is None or ours_hash is None or gt_hash is None:
            row["status"] = "ERROR"
            row["correctness"] = "ERROR"
        else:
            row["status"] = "ok"
            row["correctness"] = "PASS" if (int(ours_rows) == int(gt_rows) and str(ours_hash) == str(gt_hash)) else "FAIL"
            if row["correctness"] == "FAIL" and not row["reason"]:
                row["reason"] = "rows/hash mismatch"

        rows.append(row)
        print(
            f"[single_smoke] policy={p.policy_id} target={p.target} q={qid} "
            f"status={row['status']} correctness={row['correctness']} route={route_main or '-'} reason={row['reason'] or '-'}"
        )

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    ok_rows = sum(1 for r in rows if r["status"] == "ok")
    pass_rows = sum(1 for r in rows if r["correctness"] == "PASS")
    fail_rows = sum(1 for r in rows if r["correctness"] == "FAIL")
    err_rows = sum(1 for r in rows if r["status"] == "ERROR")
    lines = [
        "# Policy Pool Single Policy Smoke",
        "",
        f"- db: `{db}`",
        f"- policies: `{args.policy_min}..{args.policy_max}`",
        f"- rows: {len(rows)}",
        f"- ok_rows: {ok_rows}",
        f"- pass_rows: {pass_rows}",
        f"- fail_rows: {fail_rows}",
        f"- error_rows: {err_rows}",
        "",
        "## Rows",
    ]
    for r in rows:
        lines.append(
            f"- policy={r['policy_id']} target={r['target']} q{r['query_id']}: status={r['status']} "
            f"correctness={r['correctness']} route={r['route_main'] or '-'} "
            f"invariants(sig/mask/rid)={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"reason={r['reason'] or '-'}"
        )
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] csv={out_csv} md={out_md}")


if __name__ == "__main__":
    main()
