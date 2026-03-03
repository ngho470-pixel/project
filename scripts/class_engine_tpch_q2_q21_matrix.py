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

OUT_CSV = REPO_ROOT / "logs" / "class_engine_tpch_q2_q21_matrix.csv"
OUT_MD = REPO_ROOT / "logs" / "class_engine_tpch_q2_q21_matrix.md"
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


def run_profile_probe(db: str, query_id: str, query_sql: str, enabled_path: Path, timeout_ms: int, profile_k: int):
    try:
        with strict_env():
            metrics, _payload, _kv, _cnt, notices = h.run_ours_profile_capture(
                db,
                query_sql,
                enabled_path,
                timeout_ms,
                ours_profile_rescan=False,
                ours_debug_mode="trace",
                query_id=query_id,
                profile_k=profile_k,
                profile_query=query_id,
            )
        _pp_payload, pp_kv, _pp_cnt = h.extract_policy_profile(notices)
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        route_main, route_summary, route_reject_reason = parse_routes(notices)
        err = "" if metrics.status == "ok" else (metrics.error_msg or "profile capture failed")
        return metrics, ppq_kv, pp_kv, route_main, route_summary, route_reject_reason, err
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, {}, {}, "", "", "", msg[:600]


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

    ap = argparse.ArgumentParser(description="Targeted class-engine matrix for Q2/Q21 + baselines")
    ap.add_argument("--db", default="tpch1")
    ap.add_argument("--policy-file", default=str(DEFAULT_POLICY_FILE))
    ap.add_argument("--query-file", default=str(DEFAULT_QUERY_FILE))
    ap.add_argument("--queries", default="2,21,1,6")
    ap.add_argument("--statement-timeout", default="30min")
    ap.add_argument("--sets", default="A,B,C,D,E,F")
    ap.add_argument("--stop-on-first-error", action="store_true")
    ap.add_argument("--out-csv", default=str(OUT_CSV))
    ap.add_argument("--out-md", default=str(OUT_MD))
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    query_ids = tuple(x.strip() for x in str(args.queries).split(",") if x.strip())
    qmap = load_query_map(Path(args.query_file), query_ids)
    pool = parse_policy_pool(Path(args.policy_file))

    all_sets: Dict[str, List[int]] = {
        "A": [1],
        "B": [15],
        "C": [16],
        "D": [17],
        "E": [20],
        "F": [29],
        "G": list(range(11, 21)),
    }
    wanted_sets = [s.strip() for s in str(args.sets).split(",") if s.strip()]
    sets: List[Tuple[str, List[int]]] = []
    for s in wanted_sets:
        if s not in all_sets:
            raise RuntimeError(f"unknown set '{s}', choose from {sorted(all_sets.keys())}")
        sets.append((s, all_sets[s]))

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
        "pf2_terms_supported",
        "pf2_terms_failed_shape",
        "class_terms_ok",
        "class_terms_reject",
        "class_route_single_hub",
        "class_route_two_hop",
        "class_route_tree",
        "class_route_cycle_rect",
        "class_route_td_cycle",
        "class_route_reject",
        "pf2_cmp_total",
        "pf2_cmp_supported",
        "pf2_cmp_key_arity_max",
        "proj_sig_count",
        "proj_mask_or_ops",
        "proj_rid_iters",
        "hygiene_ok",
        "hygiene_diag",
    ]
    rows: List[Dict[str, str]] = []
    case_idx = 0
    any_error = False

    for set_name, pids in sets:
        if any_error and args.stop_on_first_error:
            break
        missing = [pid for pid in pids if pid not in pool]
        if missing:
            raise RuntimeError(f"missing policy ids in pool: {missing}")
        entries = [pool[pid] for pid in pids]
        enabled = Path("/tmp") / f"class_engine_matrix_{set_name}.txt"
        h.write_enabled_policy_file([e.line for e in entries], enabled)
        os.chmod(enabled, 0o644)

        ok_hygiene, hygiene_diag = run_hygiene(db)
        if not ok_hygiene:
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
                        "reason": "db_hygiene_failed",
                        "hygiene_ok": "0",
                        "hygiene_diag": hygiene_diag[:500],
                    }
                )
                rows.append(row)
            continue

        ours_case: Dict[str, Tuple[Optional[int], Optional[str], str, Dict[str, str], str, str, str, str]] = {}
        gt_case: Dict[str, Tuple[Optional[int], Optional[str], str]] = {}
        setup_ours_err = ""
        setup_rls_err = ""

        try:
            case_idx += 1
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, case_idx, enabled, timeout_ms)
            for qid in query_ids:
                query_sql = qmap[qid]
                case_idx += 1
                ours_rows, ours_hash, ppq, route_main, route_summary, route_reject_reason, probe_err = run_ours_count_hash_with_profile(
                    db, qid, query_sql, enabled, timeout_ms, case_idx
                )
                ours_case[qid] = (ours_rows, ours_hash, probe_err, ppq, route_main, route_summary, route_reject_reason, probe_err)
        except Exception as exc:  # noqa: BLE001
            setup_ours_err = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:600]

        try:
            h.clear_artifacts(db)
            h.apply_rls_policies_for_k(db, [e.line for e in entries])
            h.create_rls_indexes_for_k(db, case_idx if case_idx > 0 else 1, [e.line for e in entries], timeout_ms)
            for qid in query_ids:
                query_sql = qmap[qid]
                gt_rows, gt_hash, gt_err = run_count_hash(db, "rls_with_index", qid, query_sql, enabled, timeout_ms)
                gt_case[qid] = (gt_rows, gt_hash, gt_err)
        except Exception as exc:  # noqa: BLE001
            setup_rls_err = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()[:600]
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
            row.update(
                {
                    "db": db,
                    "policy_set": set_name,
                    "policy_ids": ",".join(str(x) for x in pids),
                    "query_id": qid,
                    "status": "ERROR",
                    "correctness": "ERROR",
                    "hygiene_ok": "1",
                    "hygiene_diag": hygiene_diag[:500],
                }
            )
            ours_rows, ours_hash, ours_err, ppq, route_main, route_summary, route_reject_reason, probe_err = ours_case.get(
                qid, (None, None, "", {}, "", "", "", "")
            )
            gt_rows, gt_hash, gt_err = gt_case.get(qid, (None, None, ""))

            row["route_main"] = route_main
            row["route_summary"] = route_summary
            row["route_reject_reason"] = route_reject_reason
            row["ours_rows"] = "" if ours_rows is None else str(ours_rows)
            row["ours_hash"] = "" if ours_hash is None else str(ours_hash)
            row["gt_rows"] = "" if gt_rows is None else str(gt_rows)
            row["gt_hash"] = "" if gt_hash is None else str(gt_hash)

            if setup_ours_err or setup_rls_err:
                row["status"] = "ERROR"
                row["correctness"] = "ERROR"
                row["reason"] = "; ".join(x for x in [setup_ours_err, setup_rls_err] if x)[:600]
            elif ours_rows is None or gt_rows is None:
                row["status"] = "ERROR"
                row["correctness"] = "ERROR"
                row["reason"] = "; ".join(x for x in [ours_err, gt_err, probe_err] if x)[:600]
            elif int(ours_rows) != int(gt_rows) or str(ours_hash) != str(gt_hash):
                row["status"] = "FAIL"
                row["correctness"] = "FAIL"
                row["reason"] = "rows/hash mismatch"
            elif probe_err:
                row["status"] = "ERROR"
                row["correctness"] = "ERROR"
                row["reason"] = probe_err[:600]
            else:
                row["status"] = "ok"
                row["correctness"] = "PASS"
                row["reason"] = ""
                for invk in ("proj_sig_count", "proj_mask_or_ops", "proj_rid_iters"):
                    iv = str(ppq.get(invk, "0"))
                    if iv not in ("", "0", "0.000"):
                        row["status"] = "FAIL"
                        row["correctness"] = "FAIL"
                        row["reason"] = f"strict invariant broken: {invk}={iv}"
                        break

            for k in (
                "policy_total_ms",
                "pf2_terms_supported",
                "pf2_terms_failed_shape",
                "class_terms_ok",
                "class_terms_reject",
                "class_route_single_hub",
                "class_route_two_hop",
                "class_route_tree",
                "class_route_cycle_rect",
                "class_route_td_cycle",
                "class_route_reject",
                "pf2_cmp_total",
                "pf2_cmp_supported",
                "pf2_cmp_key_arity_max",
                "proj_sig_count",
                "proj_mask_or_ops",
                "proj_rid_iters",
            ):
                row[k] = ppq.get(k, row.get(k, ""))

            rows.append(row)
            print(
                f"[matrix] set={set_name} pids={row['policy_ids']} q{qid} "
                f"status={row['status']} corr={row['correctness']} route={row['route_main'] or '-'} reason={row['reason'] or '-'}"
            )
            if row["status"] != "ok":
                any_error = True
                if args.stop_on_first_error:
                    break

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    ok = sum(1 for r in rows if r["status"] == "ok")
    fail = sum(1 for r in rows if r["status"] == "FAIL")
    err = sum(1 for r in rows if r["status"] == "ERROR")
    lines = [
        "# Class Engine tpch1 Q2/Q21 Matrix",
        "",
        f"- db: `{db}`",
        f"- queries: `{','.join(query_ids)}`",
        "- mode: `strict_mode=on`, `query_driven_mode=off`",
        f"- cases: {len(rows)}",
        f"- status: ok={ok} fail={fail} error={err}",
        "",
        "## Cases",
    ]
    for r in rows:
        lines.append(
            f"- set={r['policy_set']} pids={r['policy_ids']} q{r['query_id']}: "
            f"status={r['status']} correctness={r['correctness']} "
            f"route={r['route_main'] or '-'} route_summary={r['route_summary'] or '-'} "
            f"ours={r['ours_rows']}/{r['ours_hash']} gt={r['gt_rows']}/{r['gt_hash']} "
            f"cmp_total/supported/key_arity={r.get('pf2_cmp_total','')}/{r.get('pf2_cmp_supported','')}/{r.get('pf2_cmp_key_arity_max','')} "
            f"invariants(sig/mask/rid)={r.get('proj_sig_count','-')}/{r.get('proj_mask_or_ops','-')}/{r.get('proj_rid_iters','-')} "
            f"reason={r['reason'] or '-'}"
        )
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] csv={out_csv} md={out_md}")


if __name__ == "__main__":
    main()
