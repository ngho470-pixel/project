from __future__ import annotations

import os
from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup
from baselines.sieve_wrapper import ensure_sieve_artifact, java_available, rewrite_sql_with_sieve
from baselines.view_based import _rewrite_query_with_views
from baselines.sieve import _build_policy_views, _compile_view_predicates


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int, repo_root: Path) -> BaselineSetup:
    h.clear_rls_indexes_and_policies(db)
    use_java = os.getenv("CF_SIEVE_USE_JAVA", "0") == "1"
    mode = "view_rewrite"
    jar = Path("")
    fallback_reason = ""
    if use_java and java_available():
        try:
            jar = ensure_sieve_artifact(repo_root)
            mode = "java"
        except Exception as exc:  # noqa: BLE001
            mode = "error"
            fallback_reason = str(exc)[:200]

    created = []
    build_ms = 0.0
    view_map = {}
    if mode == "view_rewrite":
        view_preds = _compile_view_predicates(list(policy_lines))
        view_map = {t: f"cf_sv_{t}" for t in view_preds.keys()}
        created, build_ms = _build_policy_views(db, view_preds, statement_timeout_ms)

    # Reuse policy-derived index inference strategy.
    idx_ms, idx_bytes, _idx_names = h.create_rls_indexes_for_k(
        db,
        max(1, len(policy_lines)),
        policy_lines,
        statement_timeout_ms,
    )
    return BaselineSetup(
        pre_run_memory_building_ms=float(build_ms + idx_ms),
        disk_overhead_bytes=int(idx_bytes),
        state={
            "mode": mode,
            "jar": str(jar),
            "enabled_path": str(enabled_path),
            "fallback_reason": fallback_reason,
            "views": created,
            "view_map": view_map,
        },
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    views = list((setup_state.state or {}).get("views", []))
    if views:
        conn = h.connect(db, "postgres")
        try:
            with conn.cursor() as cur:
                for v in views:
                    cur.execute(f"DROP VIEW IF EXISTS {v};")
        finally:
            conn.close()
    h.clear_rls_indexes_and_policies(db)


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
        return "", str((setup_state.state or {}).get("fallback_reason", "sieve_index setup failed"))
    sql = h.timing_sql_for_query(query_id, query_sql)
    return sql, ""
