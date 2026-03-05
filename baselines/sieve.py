from __future__ import annotations

import os
from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup
from baselines.sieve_wrapper import ensure_sieve_artifact, java_available, rewrite_sql_with_sieve
from baselines.view_based import _rewrite_query_with_views


def _compile_view_predicates(policy_lines):
    by_target = {}
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

    out = {}
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


def _build_policy_views(db: str, view_preds, statement_timeout_ms: int):
    created = []
    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            import time

            t0 = time.perf_counter()
            # Pass 1: create identity views so cross-view references resolve.
            for table in sorted(view_preds.keys()):
                view_name = f"cf_sv_{table}"
                cur.execute(f"CREATE OR REPLACE VIEW {view_name} WITH (security_barrier = true) AS SELECT * FROM {table};")
                created.append(view_name)

            # Pass 2: replace with filtered definitions where witness references also go through cf_sv_* views.
            view_map = {t: f"cf_sv_{t}" for t in view_preds.keys()}
            for table in sorted(view_preds.keys()):
                view_name = view_map[table]
                pred = view_preds[table]
                pred = _rewrite_query_with_views(pred, view_map)
                cur.execute(
                    f"CREATE OR REPLACE VIEW {view_name} WITH (security_barrier = true) AS "
                    f"SELECT * FROM {table} WHERE ({pred});"
                )
            build_ms = (time.perf_counter() - t0) * 1000.0
    finally:
        conn.close()

    return created, build_ms


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int, repo_root: Path) -> BaselineSetup:
    _ = db
    _ = statement_timeout_ms
    h.clear_rls_indexes_and_policies(db)

    # Default path: policy-aware SQL rewrite via security-barrier views.
    # Java Sieve wrapper in this repo is a narrow demo rewriter and not policy-general.
    use_java = os.getenv("CF_SIEVE_USE_JAVA", "0") == "1"
    if use_java and java_available():
        try:
            jar = ensure_sieve_artifact(repo_root)
            return BaselineSetup(
                pre_run_memory_building_ms=0.0,
                disk_overhead_bytes=0,
                state={"mode": "java", "jar": str(jar), "enabled_path": str(enabled_path)},
            )
        except Exception as exc:  # noqa: BLE001
            return BaselineSetup(
                pre_run_memory_building_ms=0.0,
                disk_overhead_bytes=0,
                state={"mode": "error", "enabled_path": str(enabled_path), "fallback_reason": str(exc)[:200]},
            )

    view_preds = _compile_view_predicates(list(policy_lines))
    created, build_ms = _build_policy_views(db, view_preds, statement_timeout_ms)

    view_map = {t: f"cf_sv_{t}" for t in view_preds.keys()}
    return BaselineSetup(
        pre_run_memory_building_ms=float(build_ms),
        disk_overhead_bytes=0,
        state={"mode": "view_rewrite", "views": created, "view_map": view_map, "enabled_path": str(enabled_path)},
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


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup, db: str, pg_host: str, pg_port: int):
    mode = str((setup_state.state or {}).get("mode", "view_rewrite"))
    if mode == "java":
        jar = Path((setup_state.state or {}).get("jar", ""))
        policy_file = Path((setup_state.state or {}).get("enabled_path", ""))
        rewritten, _rewrite_ms, err = rewrite_sql_with_sieve(
            jar,
            db,
            pg_host,
            pg_port,
            user=h.ROLE_CONFIG["postgres"]["user"],
            password=h.ROLE_CONFIG["postgres"]["password"],
            policy_file=policy_file,
            query_sql=query_sql,
        )
        if err:
            return "", err
        sql = h.timing_sql_for_query(query_id, rewritten)
        return sql, ""
    if mode == "view_rewrite":
        view_map = dict((setup_state.state or {}).get("view_map", {}))
        rewritten = _rewrite_query_with_views(query_sql, view_map)
        sql = h.timing_sql_for_query(query_id, rewritten)
        return sql, ""
    if mode == "error":
        return "", str((setup_state.state or {}).get("fallback_reason", "sieve setup failed"))
    sql = h.timing_sql_for_query(query_id, query_sql)
    return sql, ""
