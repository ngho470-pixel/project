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
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / "custom_filter" / "custom_filter.so")
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / "artifact_builder" / "artifact_builder.so")

OUT_CSV = REPO_ROOT / "logs" / "policy_pool_Q1_Q22_matrix.csv"
OUT_MD = REPO_ROOT / "logs" / "policy_pool_Q1_Q22_matrix.md"
DEFAULT_POLICY_FILE = REPO_ROOT / "policy.txt"
DEFAULT_QUERY_FILE = REPO_ROOT / "queries.txt"


@dataclass(frozen=True)
class PolicyEntry:
    policy_id: int
    target: str
    line: str


def parse_policy_pool(path: Path) -> Dict[int, PolicyEntry]:
    out: Dict[int, PolicyEntry] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("--"):
            continue
        pid, target, _expr = h.parse_policy_entry_with_id(line)
        if pid is None or not target:
            continue
        out[int(pid)] = PolicyEntry(int(pid), target, line)
    return out


def load_query_map(path: Path, ids: Sequence[str]) -> Dict[str, str]:
    qmap = {qid: qsql for qid, qsql in h.load_queries(path)}
    out: Dict[str, str] = {}
    for qid in ids:
        if qid not in qmap:
            raise RuntimeError(f"query_id={qid} not found in {path}")
        out[qid] = qmap[qid]
    return out


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


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Full policy-set matrix over Q1..Q22")
    ap.add_argument("--db", default="tpch1")
    ap.add_argument("--policy-file", default=str(DEFAULT_POLICY_FILE))
    ap.add_argument("--query-file", default=str(DEFAULT_QUERY_FILE))
    ap.add_argument("--queries", default=",".join(str(i) for i in range(1, 23)))
    ap.add_argument("--statement-timeout", default="0")
    ap.add_argument("--out-csv", default=str(OUT_CSV))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    query_ids = tuple(x.strip() for x in str(args.queries).split(",") if x.strip())
    qmap = load_query_map(Path(args.query_file), query_ids)
    pool = parse_policy_pool(Path(args.policy_file))

    policy_sets: List[Tuple[str, List[int]]] = [
        ("S1", list(range(1, 6))),
        ("S2", list(range(6, 11))),
        ("S3", list(range(11, 15))),
        ("S4", list(range(15, 20))),
        ("S5", [20]),
        ("S6", list(range(21, 26))),
        ("S7", list(range(26, 31))),
        ("S8", list(range(11, 21))),
        ("S9", list(range(1, 31))),
    ]

    cols = [
        "db",
        "policy_set",
        "policy_ids",
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

    for set_name, pids in policy_sets:
        missing = [pid for pid in pids if pid not in pool]
        if missing:
            raise RuntimeError(f"missing policy ids for {set_name}: {missing}")
        entries = [pool[pid] for pid in pids]
        enabled = Path("/tmp") / f"policy_pool_q1q22_{set_name}.txt"
        h.write_enabled_policy_file([e.line for e in entries], enabled)
        os.chmod(enabled, 0o644)

        ok_h, diag = run_hygiene(db)
        if not ok_h:
            for qid in query_ids:
                row = {k: "" for k in cols}
                row.update(
                    {
                        "db": db,
                        "policy_set": set_name,
                        "policy_ids": ",".join(str(x) for x in pids),
                        "query_id": qid,
                        "status": "ERROR",
                        "correctness": "ERROR",
                        "reason": f"db_hygiene_failed: {diag[:300]}",
                        "hygiene_ok": "0",
                    }
                )
                rows.append(row)
            continue

        ours_case: Dict[str, Tuple[Optional[int], Optional[str], str, Dict[str, str], str, str, str]] = {}
        gt_case: Dict[str, Tuple[Optional[int], Optional[str], str]] = {}
        setup_ours_err = ""
        setup_gt_err = ""

        try:
            case_idx += 1
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, case_idx, enabled, timeout_ms)
            for qid in query_ids:
                case_idx += 1
                ours_rows, ours_hash, ppq, route_main, route_summary, route_reject_reason, err = run_ours_count_hash_with_profile(
                    db, qid, qmap[qid], enabled, timeout_ms, case_idx
                )
                ours_case[qid] = (ours_rows, ours_hash, err, ppq, route_main, route_summary, route_reject_reason)
        except Exception as exc:  # noqa: BLE001
            setup_ours_err = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:600]

        try:
            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [e.line for e in entries])
            h.create_rls_indexes_for_k(db, case_idx if case_idx > 0 else 1, [e.line for e in entries], timeout_ms)
            for qid in query_ids:
                gt_rows, gt_hash, gt_err = run_count_hash(db, "rls_with_index", qid, qmap[qid], enabled, timeout_ms)
                gt_case[qid] = (gt_rows, gt_hash, gt_err)
        except Exception as exc:  # noqa: BLE001
            setup_gt_err = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:600]
        finally:
            try:
                h.clear_rls_indexes_and_policies(db)
            except Exception:
                pass
            try:
                h.clear_artifacts(db)
            except Exception:
                pass

        for qid in query_ids:
            row = {k: "" for k in cols}
            row.update({"db": db, "policy_set": set_name, "policy_ids": ",".join(str(x) for x in pids), "query_id": qid, "hygiene_ok": "1"})

            ours_rows, ours_hash, ours_err, ppq, route_main, route_summary, route_reject_reason = ours_case.get(
                qid, (None, None, "", {}, "", "", "")
            )
            gt_rows, gt_hash, gt_err = gt_case.get(qid, (None, None, ""))

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
            if setup_ours_err:
                reason_parts.append(f"setup_ours:{setup_ours_err}")
            if setup_gt_err:
                reason_parts.append(f"setup_gt:{setup_gt_err}")
            if ours_err:
                reason_parts.append(f"ours:{ours_err}")
            if gt_err:
                reason_parts.append(f"gt:{gt_err}")
            row["reason"] = " | ".join(reason_parts)

            if ours_rows is None or ours_hash is None or gt_rows is None or gt_hash is None:
                row["status"] = "ERROR"
                row["correctness"] = "ERROR"
            else:
                row["status"] = "ok"
                row["correctness"] = "PASS" if (int(ours_rows) == int(gt_rows) and str(ours_hash) == str(gt_hash)) else "FAIL"
                if row["correctness"] == "FAIL" and not row["reason"]:
                    row["reason"] = "rows/hash mismatch"

            rows.append(row)
            print(
                f"[matrix] set={set_name} q{qid} status={row['status']} correctness={row['correctness']} "
                f"route={row['route_main'] or '-'} reason={row['reason'] or '-'}"
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
        "# Policy Pool Q1..Q22 Matrix",
        "",
        f"- db: `{db}`",
        f"- query_ids: `{','.join(query_ids)}`",
        f"- sets: `{','.join(s for s, _ in policy_sets)}`",
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
            f"- {r['policy_set']} q{r['query_id']}: status={r['status']} correctness={r['correctness']} "
            f"route={r['route_main'] or '-'} "
            f"invariants(sig/mask/rid)={r.get('proj_sig_count','')}/{r.get('proj_mask_or_ops','')}/{r.get('proj_rid_iters','')} "
            f"reason={r['reason'] or '-'}"
        )
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] csv={out_csv} md={out_md}")


if __name__ == "__main__":
    main()
