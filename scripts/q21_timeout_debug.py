#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402

h.CUSTOM_FILTER_SO = str(REPO_ROOT / "custom_filter" / "custom_filter.so")
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / "artifact_builder" / "artifact_builder.so")

DEFAULT_POLICY_FILE = REPO_ROOT / "policy.txt"
DEFAULT_QUERY_FILE = REPO_ROOT / "queries.txt"
OUT_PLAIN = REPO_ROOT / "logs" / "q21_plain_explain.md"
OUT_RLS = REPO_ROOT / "logs" / "q21_rls_explain.md"
OUT_OURS = REPO_ROOT / "logs" / "q21_ours_explain.md"
OUT_AUDIT = REPO_ROOT / "logs" / "q21_wrapper_audit.txt"
OUT_ROOTCAUSE = REPO_ROOT / "logs" / "q21_timeout_rootcause.md"


def parse_policy_line(path: Path, policy_id: int) -> str:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("--"):
            continue
        pid, _target, _expr = h.parse_policy_entry_with_id(line)
        if pid is not None and int(pid) == int(policy_id):
            return line
    raise RuntimeError(f"policy {policy_id} not found in {path}")


def load_q21(path: Path) -> str:
    for qid, qsql in h.load_queries(path):
        if str(qid) == "21":
            return qsql
    raise RuntimeError(f"query 21 not found in {path}")


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
        return False, msg.replace("\n", " ")[:1000]


def run_explain_with_session(
    db: str,
    role: str,
    setup_sql: List[str],
    query_sql: str,
) -> Tuple[str, float, List[str], str]:
    conn = None
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            for s in setup_sql:
                cur.execute(s)
            explain_sql = "EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) " + query_sql
            del conn.notices[:]
            t0 = time.perf_counter()
            cur.execute(explain_sql)
            rows = cur.fetchall()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            notices = [n.replace("\n", " ").strip() for n in conn.notices]
            txt = "\n".join(str(r[0]) for r in rows)
            return txt, elapsed_ms, notices, ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return "", 0.0, [], msg
    finally:
        if conn is not None:
            conn.close()


def write_md(path: Path, title: str, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {title}\n\n{body}\n", encoding="utf-8")


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Q21 timeout debug pack (plain/rls/ours + wrapper audit)")
    ap.add_argument("--db", default="tpch1")
    ap.add_argument("--policy-file", default=str(DEFAULT_POLICY_FILE))
    ap.add_argument("--query-file", default=str(DEFAULT_QUERY_FILE))
    ap.add_argument("--policy-id", type=int, default=1)
    ap.add_argument("--statement-timeout", default="0")
    args = ap.parse_args()

    db = str(args.db)
    timeout_ms = h.parse_timeout_ms(args.statement_timeout)
    st_guc = str(int(timeout_ms))
    qsql = load_q21(Path(args.query_file))
    policy_line = parse_policy_line(Path(args.policy_file), int(args.policy_id))

    enabled = Path("/tmp") / "q21_debug_policy_set.txt"
    h.write_enabled_policy_file([policy_line], enabled)
    os.chmod(enabled, 0o644)

    ok_h, diag = run_hygiene(db)
    if not ok_h:
        raise RuntimeError(f"db hygiene failed: {diag}")

    # 1) plain postgres, no RLS, no custom_filter
    plain_setup = [
        f"SET statement_timeout = {st_guc};",
        "SET row_security = off;",
        "SET custom_filter.enabled = off;",
        "SET custom_filter.strict_mode = off;",
    ]
    plain_txt, plain_ms, _plain_notices, plain_err = run_explain_with_session(db, "postgres", plain_setup, qsql)
    plain_body = f"- elapsed_ms: {plain_ms:.3f}\n- error: {plain_err or '-'}\n\n```sql\n{plain_txt or ''}\n```"
    write_md(OUT_PLAIN, "Q21 Plain Explain", plain_body)

    # 2) rls_with_index baseline
    try:
        h.clear_artifacts(db)
        h.clear_rls_indexes_and_policies(db)
        h.apply_rls_policies_for_k(db, [policy_line])
        h.create_rls_indexes_for_k(db, 1, [policy_line], timeout_ms)
        rls_setup = [
            f"SET statement_timeout = {st_guc};",
            "SET row_security = on;",
            "SET custom_filter.enabled = off;",
            "SET custom_filter.strict_mode = off;",
        ]
        rls_txt, rls_ms, _rls_notices, rls_err = run_explain_with_session(db, h.role_for_baseline("rls_with_index"), rls_setup, qsql)
    finally:
        try:
            h.clear_rls_indexes_and_policies(db)
        except Exception:
            pass
        try:
            h.clear_artifacts(db)
        except Exception:
            pass
    rls_body = f"- elapsed_ms: {rls_ms:.3f}\n- error: {rls_err or '-'}\n\n```sql\n{rls_txt or ''}\n```"
    write_md(OUT_RLS, "Q21 RLS+Index Explain", rls_body)

    # 3) ours strict class engine with wrapper audit enabled
    audit_lines: List[str] = []
    try:
        h.clear_artifacts(db)
        h.clear_rls_indexes_and_policies(db)
        with strict_env():
            h.setup_ours_for_k(db, 1, enabled, timeout_ms)
        ours_setup = [
            f"SET statement_timeout = {st_guc};",
            "SET row_security = off;",
            "SET custom_filter.enabled = on;",
            "SET custom_filter.strict_mode = on;",
            "SET custom_filter.query_driven_mode = off;",
            "SET custom_filter.debug_ids = on;",
            "SET client_min_messages = notice;",
        ]
        ours_txt, ours_ms, ours_notices, ours_err = run_explain_with_session(db, "postgres", ours_setup, qsql)
        for n in ours_notices:
            if "wrapper_audit" in n or "CF_SUBPLAN" in n or "CF_ID " in n:
                audit_lines.append(n)
    finally:
        try:
            h.clear_rls_indexes_and_policies(db)
        except Exception:
            pass
        try:
            h.clear_artifacts(db)
        except Exception:
            pass

    ours_body = f"- elapsed_ms: {ours_ms:.3f}\n- error: {ours_err or '-'}\n\n```sql\n{ours_txt or ''}\n```"
    write_md(OUT_OURS, "Q21 Ours Strict Explain", ours_body)
    OUT_AUDIT.parent.mkdir(parents=True, exist_ok=True)
    OUT_AUDIT.write_text("\n".join(audit_lines) + ("\n" if audit_lines else ""), encoding="utf-8")

    def node_summary(explain_txt: str) -> str:
        lines = []
        for ln in explain_txt.splitlines():
            if re.search(r"(Nested Loop|Hash Join|Merge Join|Seq Scan|Custom Scan|SubPlan)", ln):
                lines.append(ln.strip())
            if len(lines) >= 12:
                break
        return "\n".join(lines) if lines else "(no node summary parsed)"

    root = [
        "# Q21 Timeout Root Cause",
        "",
        f"- db: `{db}`",
        f"- policy_set: `{{{args.policy_id}}}`",
        f"- hygiene: `{diag}`",
        f"- plain_elapsed_ms: {plain_ms:.3f}",
        f"- rls_elapsed_ms: {rls_ms:.3f}",
        f"- ours_elapsed_ms: {ours_ms:.3f}",
        f"- plain_error: `{plain_err or '-'}`",
        f"- rls_error: `{rls_err or '-'}`",
        f"- ours_error: `{ours_err or '-'}`",
        "",
        "## Plan Node Snapshot (Plain)",
        "```",
        node_summary(plain_txt),
        "```",
        "## Plan Node Snapshot (RLS+Index)",
        "```",
        node_summary(rls_txt),
        "```",
        "## Plan Node Snapshot (Ours Strict)",
        "```",
        node_summary(ours_txt),
        "```",
        "## Wrapper Audit",
        f"- audit_lines: {len(audit_lines)}",
        f"- audit_file: `{OUT_AUDIT}`",
    ]
    OUT_ROOTCAUSE.write_text("\n".join(root) + "\n", encoding="utf-8")
    print(f"[done] {OUT_PLAIN} {OUT_RLS} {OUT_OURS} {OUT_AUDIT} {OUT_ROOTCAUSE}")


if __name__ == "__main__":
    main()
