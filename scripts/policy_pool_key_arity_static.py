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
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / "custom_filter" / "custom_filter.so")
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / "artifact_builder" / "artifact_builder.so")

OUT_CSV = REPO_ROOT / "logs" / "policy_pool_key_arity_static.csv"
OUT_MD = REPO_ROOT / "logs" / "policy_pool_key_arity_static.md"
DEFAULT_POLICY_FILE = REPO_ROOT / "policy.txt"
DEFAULT_QUERY_FILE = REPO_ROOT / "queries.txt"


@dataclass(frozen=True)
class PolicyEntry:
    policy_id: int
    target: str
    line: str


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


def parse_routes(notices: List[str]) -> str:
    route_counts: Dict[str, int] = {}
    for line in notices:
        if "class_route_term:" not in line:
            continue
        m_route = re.search(r"\broute=([A-Za-z0-9_]+)", line)
        if not m_route:
            continue
        route = m_route.group(1)
        route_counts[route] = route_counts.get(route, 0) + 1
    if not route_counts:
        return ""
    ordered = sorted(route_counts.items(), key=lambda kv: kv[0])
    return ",".join(f"{k}:{v}" for k, v in ordered)


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
        _pp_payload, _pp_kv, _pp_cnt = h.extract_policy_profile(notices)
        _ppq_payload, ppq_kv, _ppq_cnt = h.extract_policy_profile_query(notices)
        route_summary = parse_routes(notices)
        err = "" if metrics.status == "ok" else (metrics.error_msg or "profile capture failed")
        return ppq_kv, route_summary, err
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return {}, "", msg[:600]


def to_int(v: str) -> int:
    try:
        return int(str(v or "0"))
    except Exception:
        try:
            return int(float(str(v)))
        except Exception:
            return 0


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Static key-arity report over policy pool via compiled strict term plans")
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

    target_query_candidates = {
        "lineitem": ("1", "6"),
        "orders": ("3",),
        "customer": ("13", "22"),
        "supplier": ("5", "2"),
        "nation": ("5",),
        "region": ("5",),
        "partsupp": ("11", "9", "2"),
        "part": ("2", "14"),
    }

    cols = ["policy_id", "target", "max_cmp_key_arity", "max_hub_key_arity", "td_width", "notes"]
    rows: List[Dict[str, str]] = []
    case_idx = 0

    for p in policies:
        enabled = Path("/tmp") / f"policy_pool_keyarity_{p.policy_id}.txt"
        h.write_enabled_policy_file([p.line], enabled)
        os.chmod(enabled, 0o644)

        qid = None
        for cand in target_query_candidates.get(p.target, ("1",)):
            if cand in all_qmap:
                qid = cand
                break
        if qid is None:
            qid = "1"

        row = {k: "" for k in cols}
        row["policy_id"] = str(p.policy_id)
        row["target"] = p.target
        row["max_cmp_key_arity"] = "0"
        row["max_hub_key_arity"] = "0"
        row["td_width"] = "0"

        ok_h, diag = run_hygiene(db)
        if not ok_h:
            row["notes"] = f"hygiene_failed:{diag[:180]}"
            rows.append(row)
            continue

        try:
            case_idx += 1
            h.clear_artifacts(db)
            h.clear_rls_indexes_and_policies(db)
            with strict_env():
                h.setup_ours_for_k(db, case_idx, enabled, timeout_ms)
            case_idx += 1
            sql_text = all_qmap[qid]
            ppq, route_summary, err = run_profile_probe(db, qid, sql_text, enabled, timeout_ms, case_idx)
            row["max_cmp_key_arity"] = str(to_int(ppq.get("pf2_cmp_key_arity_max", "0")))
            row["max_hub_key_arity"] = str(to_int(ppq.get("pf2_hub_key_arity", "0")))
            row["td_width"] = str(to_int(ppq.get("class_td_width_max", "0")))
            notes = [f"q={qid}"]
            if route_summary:
                notes.append(f"route={route_summary}")
            if err:
                notes.append(f"err={err}")
            row["notes"] = "; ".join(notes)
        except Exception as exc:  # noqa: BLE001
            row["notes"] = f"error:{(getattr(exc,'pgerror',None) or str(exc)).replace(chr(10), ' ')[:180]}"
        finally:
            try:
                h.clear_rls_indexes_and_policies(db)
            except Exception:
                pass
            try:
                h.clear_artifacts(db)
            except Exception:
                pass

        rows.append(row)
        print(f"[keyarity_static] policy={p.policy_id} target={p.target} cmp={row['max_cmp_key_arity']} hub={row['max_hub_key_arity']} td={row['td_width']} notes={row['notes']}")

    out_csv = Path(args.out_csv)
    out_md = Path(args.out_md)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    max_cmp = max((to_int(r["max_cmp_key_arity"]) for r in rows), default=0)
    max_hub = max((to_int(r["max_hub_key_arity"]) for r in rows), default=0)
    max_td = max((to_int(r["td_width"]) for r in rows), default=0)

    lines = [
        "# Policy Pool Key Arity Static",
        "",
        f"- db: `{db}`",
        f"- policies: `{args.policy_min}..{args.policy_max}`",
        f"- max_cmp_key_arity: {max_cmp}",
        f"- max_hub_key_arity: {max_hub}",
        f"- max_td_width: {max_td}",
        "",
        "## Rows",
    ]
    for r in rows:
        lines.append(
            f"- policy={r['policy_id']} target={r['target']} cmp_key={r['max_cmp_key_arity']} "
            f"hub_key={r['max_hub_key_arity']} td_width={r['td_width']} notes={r['notes']}"
        )
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[done] csv={out_csv} md={out_md}")


if __name__ == "__main__":
    main()
