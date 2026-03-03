from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import fast_sweep_profile_60s as h


@dataclass
class QueryRun:
    cold_ms: float
    hot_ms: float
    hot_peak_rss_kb: int
    status: int
    error_type: str
    error_msg: str
    notices: List[str]


def run_hygiene(repo_root: Path, db: str) -> Tuple[bool, str]:
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "pg_hygiene.py"),
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
            msg = ((getattr(exc, "stdout", "") or "") + "\n" + (getattr(exc, "stderr", "") or "")).strip() or msg
        return False, msg[:500]


def run_query_trials(
    db: str,
    role: str,
    query_sql: str,
    statement_timeout_ms: int,
    hot_runs: int,
    session_setup: Optional[Callable] = None,
    capture_notices_cold: bool = False,
) -> QueryRun:
    conn = None
    notices: List[str] = []
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)

            if capture_notices_cold:
                cold_metrics, notices = h.execute_with_rss_and_notices(cur, query_sql)
            else:
                cold_metrics = h.execute_with_rss(cur, query_sql)

            hot_metrics = [h.execute_with_rss(cur, query_sql) for _ in range(hot_runs)]

            if cold_metrics.status != "ok":
                return QueryRun(
                    cold_ms=float(cold_metrics.elapsed_ms),
                    hot_ms=0.0,
                    hot_peak_rss_kb=0,
                    status=0,
                    error_type=cold_metrics.error_type or "db_error",
                    error_msg=cold_metrics.error_msg or "cold run failed",
                    notices=notices,
                )

            for hm in hot_metrics:
                if hm.status != "ok":
                    return QueryRun(
                        cold_ms=float(cold_metrics.elapsed_ms),
                        hot_ms=0.0,
                        hot_peak_rss_kb=0,
                        status=0,
                        error_type=hm.error_type or "db_error",
                        error_msg=hm.error_msg or "hot run failed",
                        notices=notices,
                    )

            hot_ms = sum(float(hm.elapsed_ms) for hm in hot_metrics) / float(hot_runs)
            hot_peak = int(sum(int(hm.peak_rss_kb) for hm in hot_metrics) / float(hot_runs))
            return QueryRun(
                cold_ms=float(cold_metrics.elapsed_ms),
                hot_ms=float(hot_ms),
                hot_peak_rss_kb=hot_peak,
                status=1,
                error_type="",
                error_msg="",
                notices=notices,
            )
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        etype = "timeout" if "statement timeout" in msg.lower() else "db_error"
        return QueryRun(
            cold_ms=0.0,
            hot_ms=0.0,
            hot_peak_rss_kb=0,
            status=0,
            error_type=etype,
            error_msg=msg[:500],
            notices=notices,
        )
    finally:
        if conn is not None:
            conn.close()


def run_count_hash(
    db: str,
    role: str,
    query_id: str,
    query_sql: str,
    statement_timeout_ms: int,
    session_setup: Optional[Callable] = None,
) -> Tuple[Optional[int], Optional[str], str]:
    conn = None
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)
            cnt, hh = h.result_count_and_hash_in_session(cur, query_id, query_sql)
            return int(cnt), str(hh or ""), ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, None, msg[:500]
    finally:
        if conn is not None:
            conn.close()
