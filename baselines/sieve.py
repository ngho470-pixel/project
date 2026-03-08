from __future__ import annotations

from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup
from baselines.sieve_wrapper import ensure_sieve_artifact, java_available, rewrite_sql_with_sieve


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int, repo_root: Path) -> BaselineSetup:
    _ = policy_lines
    _ = statement_timeout_ms
    h.clear_rls_indexes_and_policies(db)
    if not java_available():
        return BaselineSetup(
            pre_run_memory_building_ms=0.0,
            disk_overhead_bytes=0,
            state={"mode": "error", "enabled_path": str(enabled_path), "fallback_reason": "java runtime not found"},
        )
    try:
        jar = ensure_sieve_artifact(repo_root)
    except Exception as exc:  # noqa: BLE001
        return BaselineSetup(
            pre_run_memory_building_ms=0.0,
            disk_overhead_bytes=0,
            state={"mode": "error", "enabled_path": str(enabled_path), "fallback_reason": str(exc)[:200]},
        )
    return BaselineSetup(
        pre_run_memory_building_ms=0.0,
        disk_overhead_bytes=0,
        state={"mode": "java", "jar": str(jar), "enabled_path": str(enabled_path)},
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    _ = db
    _ = setup_state


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
    return "", str((setup_state.state or {}).get("fallback_reason", "sieve setup failed"))
