from __future__ import annotations

from pathlib import Path

import fast_sweep_profile_60s as h
from baselines.common import BaselineSetup


def setup(db: str, policy_lines, enabled_path: Path, statement_timeout_ms: int) -> BaselineSetup:
    _ = enabled_path
    h.clear_rls_indexes_and_policies(db)
    h.apply_rls_policies_for_k(db, policy_lines)
    index_ms, index_disk, _idx_names = h.create_rls_indexes_for_k(
        db,
        max(1, len(policy_lines)),
        policy_lines,
        statement_timeout_ms,
    )
    return BaselineSetup(
        pre_run_memory_building_ms=float(index_ms),
        disk_overhead_bytes=int(index_disk),
        state={},
    )


def teardown(db: str, setup_state: BaselineSetup) -> None:
    _ = setup_state
    h.clear_rls_indexes_and_policies(db)


def session_setup(cur, enabled_path: Path, statement_timeout_ms: int, setup_state: BaselineSetup) -> None:
    _ = enabled_path
    _ = statement_timeout_ms
    _ = setup_state
    cur.execute("SET custom_filter.enabled = off;")
    cur.execute("SET row_security = on;")
    cur.execute("SET enable_indexonlyscan = off;")


def prepare_query(query_id: str, query_sql: str, setup_state: BaselineSetup):
    _ = setup_state
    sql = h.timing_sql_for_query(query_id, query_sql)
    return sql, ""
