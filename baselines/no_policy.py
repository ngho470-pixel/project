from __future__ import annotations

from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int) -> BaselineSetup:
    _ = policy_lines
    _ = enabled_path
    _ = statement_timeout_ms
    h.clear_rls_indexes_and_policies(db)
    return BaselineSetup(pre_run_memory_building_ms=0.0, disk_overhead_bytes=0, state={})


def teardown(db: str, setup_state: BaselineSetup) -> None:
    _ = setup_state
    h.clear_rls_indexes_and_policies(db)


def session_setup(cur, enabled_path: Path, statement_timeout_ms: int, setup_state: BaselineSetup) -> None:
    _ = enabled_path
    _ = statement_timeout_ms
    _ = setup_state
    cur.execute("SET custom_filter.enabled = off;")
    cur.execute("SET row_security = off;")


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup):
    _ = setup_state
    sql = h.timing_sql_for_query(query_id, query_sql)
    return sql, ""
