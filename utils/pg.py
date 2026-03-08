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
    cold_notices: List[str]
    hot_notices: List[str]
    no_parallel_show_ok: bool
    no_parallel_show: dict


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
    capture_notices_hot: bool = False,
) -> QueryRun:
    conn = None
    notices: List[str] = []
    cold_notices: List[str] = []
    hot_notices: List[str] = []
    no_parallel_ok = False
    no_parallel_vals = {}
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)
                # Enforce baseline-agnostic no-parallel contract after any baseline-specific SETs.
                h.apply_no_parallel_settings(cur)
                cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])

            no_parallel_ok, no_parallel_vals = verify_no_parallel_settings(cur)

            if capture_notices_cold:
                cold_metrics, cold_notices = h.execute_with_rss_and_notices(cur, query_sql)
                notices = list(cold_notices)
            else:
                cold_metrics = h.execute_with_rss(cur, query_sql)

            hot_metrics = []
            for _ in range(hot_runs):
                if capture_notices_hot:
                    hm, hn = h.execute_with_rss_and_notices(cur, query_sql)
                    hot_metrics.append(hm)
                    hot_notices = list(hn)
                else:
                    hot_metrics.append(h.execute_with_rss(cur, query_sql))

            if cold_metrics.status != "ok":
                return QueryRun(
                    cold_ms=float(cold_metrics.elapsed_ms),
                    hot_ms=0.0,
                    hot_peak_rss_kb=0,
                    status=0,
                    error_type=cold_metrics.error_type or "db_error",
                    error_msg=cold_metrics.error_msg or "cold run failed",
                    notices=notices,
                    cold_notices=cold_notices,
                    hot_notices=hot_notices,
                    no_parallel_show_ok=no_parallel_ok,
                    no_parallel_show=no_parallel_vals,
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
                    cold_notices=cold_notices,
                    hot_notices=hot_notices,
                    no_parallel_show_ok=no_parallel_ok,
                    no_parallel_show=no_parallel_vals,
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
                cold_notices=cold_notices,
                hot_notices=hot_notices,
                no_parallel_show_ok=no_parallel_ok,
                no_parallel_show=no_parallel_vals,
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
            cold_notices=cold_notices,
            hot_notices=hot_notices,
            no_parallel_show_ok=no_parallel_ok,
            no_parallel_show=no_parallel_vals,
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
                h.apply_no_parallel_settings(cur)
                cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])
            cnt, hh = h.result_count_and_hash_in_session(cur, query_id, query_sql)
            return int(cnt), str(hh or ""), ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, None, msg[:500]
    finally:
        if conn is not None:
            conn.close()


def run_canonical_rows(
    db: str,
    role: str,
    query_id: str,
    query_sql: str,
    statement_timeout_ms: int,
    session_setup: Optional[Callable] = None,
) -> Tuple[Optional[int], Optional[List[str]], str]:
    _ = query_id
    conn = None
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)
                h.apply_no_parallel_settings(cur)
                cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])

            base_sql = h.final_select_statement(query_sql)
            if base_sql is None:
                return None, None, "cannot canonicalize non-SELECT query"

            wrapped = (
                "WITH __q AS ("
                + base_sql
                + ") SELECT row_to_json(__q)::text FROM __q ORDER BY 1"
            )
            cur.execute(wrapped)
            rows = cur.fetchall()
            out_rows = [str(r[0]) for r in rows]
            return int(len(out_rows)), out_rows, ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, None, msg[:500]
    finally:
        if conn is not None:
            conn.close()


def run_count_only(
    db: str,
    role: str,
    query_id: str,
    query_sql: str,
    statement_timeout_ms: int,
    session_setup: Optional[Callable] = None,
) -> Tuple[Optional[int], str]:
    conn = None
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)
                h.apply_no_parallel_settings(cur)
                cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])
            try:
                cnt, _hh = h.result_count_and_hash_in_session(cur, query_id, query_sql)
                return int(cnt), ""
            except Exception:
                cnt = h.result_count_in_session(cur, query_id, query_sql)
                return int(cnt), ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return None, msg[:500]
    finally:
        if conn is not None:
            conn.close()


def explain_text(
    db: str,
    role: str,
    query_sql: str,
    statement_timeout_ms: int,
    session_setup: Optional[Callable] = None,
    analyze: bool = True,
) -> Tuple[str, str]:
    """
    Return full EXPLAIN text and error string (empty on success).
    """
    conn = None
    try:
        conn = h.connect(db, role)
        with conn.cursor() as cur:
            h.apply_timing_session_settings(cur, statement_timeout_ms)
            if session_setup is not None:
                session_setup(cur)
            h.apply_no_parallel_settings(cur)
            cur.execute("SET statement_timeout = %s;", [int(statement_timeout_ms)])
            prefix = "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS) " if analyze else "EXPLAIN (VERBOSE, SETTINGS) "
            q = query_sql.strip()
            if q.endswith(";"):
                q = q[:-1]
            cur.execute(prefix + q)
            rows = cur.fetchall()
            plan_text = "\n".join(str(r[0]) for r in rows)
            return plan_text, ""
    except Exception as exc:  # noqa: BLE001
        msg = (getattr(exc, "pgerror", None) or str(exc)).replace("\n", " ").strip()
        return "", msg[:500]
    finally:
        if conn is not None:
            conn.close()


def parallelism_off_verified(explain_output: str) -> bool:
    t = (explain_output or "")
    bad_needles = (
        "Workers Planned",
        "Workers Launched",
        "Parallel Seq Scan",
        "Parallel Hash",
        "Parallel Append",
        "Gather ",
        "Gather Merge",
    )
    return not any(x in t for x in bad_needles)


def verify_no_parallel_settings(cur) -> Tuple[bool, dict]:
    expected = {
        "max_parallel_workers_per_gather": "0",
        "max_parallel_maintenance_workers": "0",
        "max_parallel_workers": "0",
        "min_parallel_table_scan_size": "1tb",
        "min_parallel_index_scan_size": "1tb",
        "parallel_leader_participation": "off",
        "enable_parallel_append": "off",
        "enable_parallel_hash": "off",
        "jit": "off",
    }
    seen = {}
    ok = True
    for k, want in expected.items():
        cur.execute(f"SHOW {k};")
        got = str(cur.fetchone()[0]).strip().lower()
        seen[k] = got
        if got != str(want).strip().lower():
            ok = False
    return ok, seen
