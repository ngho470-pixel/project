from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup


_ALIAS_RESERVED = {
    "where",
    "group",
    "order",
    "limit",
    "offset",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "cross",
    "on",
    "having",
    "union",
}


def _safe_alias(alias: str) -> str:
    a = (alias or "").strip()
    if not a:
        return ""
    if a.lower() in _ALIAS_RESERVED:
        return ""
    return a


def _compile_view_predicates(policy_lines: List[str]) -> Dict[str, str]:
    by_target: Dict[str, Dict[str, List[str]]] = {}
    for raw in policy_lines:
        pid, target, expr = h.parse_policy_entry_with_id(raw)
        target = target.lower()
        pred = h.rewrite_policy_expr_for_rls(target, expr)
        entry = by_target.setdefault(target, {"perm": [], "rest": []})
        if pid is None:
            entry["perm"].append(f"({pred})")
        elif int(pid) % 2 == 1:
            entry["perm"].append(f"({pred})")
        else:
            entry["rest"].append(f"({pred})")

    out: Dict[str, str] = {}
    for t, grp in by_target.items():
        perm = grp["perm"]
        rest = grp["rest"]
        if not perm:
            out[t] = "FALSE"
            continue
        expr = "(" + " OR ".join(perm) + ")"
        if rest:
            expr += " AND (" + " AND ".join(rest) + ")"
        out[t] = expr
    return out


def _rewrite_query_with_views(query_sql: str, view_map: Dict[str, str]) -> str:
    sql = query_sql
    for table, view_name in view_map.items():
        # FROM/JOIN table [AS alias]
        p1 = re.compile(
            rf"(?i)\b(from|join)\s+({re.escape(table)})\b(\s+(?:as\s+)?([a-z_][a-z0-9_]*))?"
        )

        def r1(m):
            kw = m.group(1)
            alias_chunk = m.group(3) or ""
            alias_name = _safe_alias(m.group(4) or "")
            if alias_name:
                return f"{kw} {view_name}{alias_chunk}"
            if alias_chunk:
                # Alias-like token was reserved (e.g., WHERE/GROUP); preserve it.
                return f"{kw} {view_name} {table}{alias_chunk}"
            return f"{kw} {view_name} {table}"

        sql = p1.sub(r1, sql)

        # Comma-separated table references.
        p2 = re.compile(
            rf"(?i)(,)\s*({re.escape(table)})\b(\s+(?:as\s+)?([a-z_][a-z0-9_]*))?"
        )

        def r2(m):
            comma = m.group(1)
            alias_chunk = m.group(3) or ""
            alias_name = _safe_alias(m.group(4) or "")
            if alias_name:
                return f"{comma} {view_name}{alias_chunk}"
            if alias_chunk:
                # Alias-like token was reserved (e.g., WHERE/GROUP); preserve it.
                return f"{comma} {view_name} {table}{alias_chunk}"
            return f"{comma} {view_name} {table}"

        sql = p2.sub(r2, sql)

    return sql


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int) -> BaselineSetup:
    _ = enabled_path
    _ = statement_timeout_ms
    h.clear_rls_indexes_and_policies(db)

    view_preds = _compile_view_predicates(list(policy_lines))
    created: List[str] = []

    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            import time

            t0 = time.perf_counter()
            for table in sorted(view_preds.keys()):
                view_name = f"cf_v_{table}"
                pred = view_preds[table]
                cur.execute(
                    f"CREATE OR REPLACE VIEW {view_name} WITH (security_barrier = true) AS "
                    f"SELECT * FROM {table} WHERE ({pred});"
                )
                created.append(view_name)
            build_ms = (time.perf_counter() - t0) * 1000.0
    finally:
        conn.close()

    view_map = {t: f"cf_v_{t}" for t in view_preds.keys()}
    return BaselineSetup(
        pre_run_memory_building_ms=float(build_ms),
        disk_overhead_bytes=0,
        state={"views": created, "view_map": view_map},
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    views = list((setup_state.state or {}).get("views", []))
    if not views:
        return
    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            for v in views:
                cur.execute(f"DROP VIEW IF EXISTS {v};")
    finally:
        conn.close()


def session_setup(cur, enabled_path: Path, statement_timeout_ms: int, setup_state: BaselineSetup) -> None:
    _ = enabled_path
    _ = statement_timeout_ms
    _ = setup_state
    cur.execute("SET custom_filter.enabled = off;")
    cur.execute("SET row_security = off;")


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup):
    _ = query_id
    view_map = dict((setup_state.state or {}).get("view_map", {}))
    rewritten = _rewrite_query_with_views(query_sql, view_map)
    sql = h.timing_sql_for_query(query_id, rewritten)
    return sql, ""
