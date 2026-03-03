from __future__ import annotations

from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int) -> BaselineSetup:
    _ = policy_lines
    h.clear_rls_indexes_and_policies(db)
    setup_ms, disk_bytes = h.setup_ours_for_k(
        db,
        max(1, len(policy_lines)),
        enabled_path,
        statement_timeout_ms,
    )
    return BaselineSetup(
        pre_run_memory_building_ms=float(setup_ms),
        disk_overhead_bytes=int(disk_bytes),
        state={},
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    _ = setup_state
    # Keep run-scoped artifacts for reproducibility until the next setup refreshes run_id table.
    h.clear_rls_indexes_and_policies(db)


def session_setup(cur, enabled_path: Path, statement_timeout_ms: int, setup_state: BaselineSetup) -> None:
    _ = setup_state
    h.set_session_for_baseline(cur, "ours", enabled_path, statement_timeout_ms)


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup):
    _ = setup_state
    sql = h.timing_sql_for_query(query_id, query_sql)
    return sql, ""
