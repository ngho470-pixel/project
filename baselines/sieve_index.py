from __future__ import annotations

from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup
from baselines.sieve_wrapper import ensure_sieve_artifact, java_available, rewrite_sql_with_sieve


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int, repo_root: Path) -> BaselineSetup:
    h.clear_rls_indexes_and_policies(db)
    mode = "error"
    jar = Path("")
    fallback_reason = ""
    if not java_available():
        fallback_reason = "java runtime not found"
    else:
        try:
            jar = ensure_sieve_artifact(repo_root)
            mode = "java"
        except Exception as exc:  # noqa: BLE001
            fallback_reason = str(exc)[:200]

    idx_ms, idx_bytes, _idx_names = h.create_rls_indexes_for_k(
        db,
        max(1, len(policy_lines)),
        policy_lines,
        statement_timeout_ms,
    )
    return BaselineSetup(
        pre_run_memory_building_ms=float(idx_ms),
        disk_overhead_bytes=int(idx_bytes),
        state={
            "mode": mode,
            "jar": str(jar),
            "enabled_path": str(enabled_path),
            "fallback_reason": fallback_reason,
        },
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    _ = setup_state
    h.clear_rls_indexes_and_policies(db)


def session_setup(cur, enabled_path: Path, statement_timeout_ms: int, setup_state: BaselineSetup) -> None:
    _ = enabled_path
    _ = statement_timeout_ms
    _ = setup_state
    cur.execute("SET row_security = off;")


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup, db: str, pg_host: str, pg_port: int):
    mode = str((setup_state.state or {}).get("mode", "error"))
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
    return "", str((setup_state.state or {}).get("fallback_reason", "sieve_index setup failed"))
