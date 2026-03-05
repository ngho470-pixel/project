#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
import fast_sweep_profile_60s as h  # noqa: E402


def _managed_tables() -> List[str]:
    tbls = getattr(h, "TABLES", None)
    if isinstance(tbls, (list, tuple)) and tbls:
        return [str(x) for x in tbls]
    # Fallback for trimmed harness modules where TABLES is not exported.
    return [
        "lineitem",
        "orders",
        "customer",
        "supplier",
        "part",
        "partsupp",
        "nation",
        "region",
    ]


def _connect_once(db: str):
    """Fail-fast connect for hygiene preflight (don't inherit long harness retries)."""
    import psycopg2

    cfg = h.ROLE_CONFIG["postgres"]
    conn = psycopg2.connect(
        host=str(h.PG_HOST),
        port=int(h.PG_PORT),
        dbname=str(db),
        user=cfg["user"],
        password=cfg["password"],
        connect_timeout=3,
    )
    conn.autocommit = True
    # Hygiene queries must not inherit statement timeouts from the caller/session defaults.
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = 0;")
        cur.execute("SET lock_timeout = 0;")
    return conn


def _rows(cur) -> List[Tuple]:
    cur.execute(
        """
        SELECT pid, state, wait_event_type, wait_event, backend_type, left(query, 240)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND state <> 'idle'
        ORDER BY pid;
        """
    )
    return list(cur.fetchall())


def _managed_lock_rows(cur) -> List[Tuple]:
    managed = _managed_tables()
    table_list = ", ".join("'" + t.replace("'", "''") + "'" for t in managed)
    cur.execute(
        f"""
        SELECT a.pid,
               a.state,
               a.wait_event_type,
               a.wait_event,
               c.relname,
               l.mode,
               l.granted,
               left(a.query, 200)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        LEFT JOIN pg_class c ON c.oid = l.relation
        LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE a.datname = current_database()
          AND a.pid <> pg_backend_pid()
          AND a.state <> 'idle'
          AND n.nspname = 'public'
          AND (c.relname LIKE 'files%' OR c.relname IN ({table_list}))
        ORDER BY a.pid, c.relname, l.mode;
        """
    )
    return list(cur.fetchall())


def _print_diag(cur, label: str) -> None:
    try:
        rows = _rows(cur)
    except Exception as exc:  # noqa: BLE001
        print(f"[pg_hygiene] {label} diag_rows_error={type(exc).__name__}: {exc}")
        rows = []
    try:
        lock_rows = _managed_lock_rows(cur)
    except Exception as exc:  # noqa: BLE001
        print(f"[pg_hygiene] {label} diag_locks_error={type(exc).__name__}: {exc}")
        lock_rows = []
    print(f"[pg_hygiene] {label} active_sessions={len(rows)} managed_locks={len(lock_rows)}")
    for r in rows:
        print(
            "[pg_hygiene] activity "
            f"pid={r[0]} state={r[1]} wait_type={r[2] or ''} wait={r[3] or ''} "
            f"backend_type={r[4] or ''} query={r[5] or ''}"
        )
    for r in lock_rows:
        print(
            "[pg_hygiene] managed_lock "
            f"pid={r[0]} state={r[1]} wait_type={r[2] or ''} wait={r[3] or ''} "
            f"rel={r[4] or ''} mode={r[5] or ''} granted={r[6]} query={r[7] or ''}"
        )


def _has_hard_blockers(lock_rows: List[Tuple]) -> bool:
    """Allow nonblocking readers on public.files*; treat managed TPCH table locks as blockers."""
    managed = set(_managed_tables())
    for r in lock_rows:
        rel = str(r[4] or "")
        mode = (r[5] or "")
        granted = bool(r[6])
        if not granted:
            return True
        if rel.startswith("files"):
            if mode not in ("AccessShareLock",):
                return True
            continue
        # Harness performs DDL on managed TPCH tables (RLS/index setup/teardown), so any live lock
        # on those tables can block progress and should fail preflight.
        if rel in managed:
            return True
    return False


def _cancel_all(cur) -> None:
    cur.execute(
        """
        SELECT pg_cancel_backend(pid)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND state <> 'idle';
        """
    )


def _terminate_all(cur) -> None:
    cur.execute(
        """
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid()
          AND state <> 'idle';
        """
    )


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Preflight DB hygiene for harness runs")
    ap.add_argument("--db", default="postgres")
    ap.add_argument("--timeout-seconds", type=float, default=10.0)
    ap.add_argument("--kill-nonidle", action="store_true", help="Attempt cancel/terminate of non-idle backends (default behavior).")
    ap.add_argument("--no-kill-nonidle", dest="kill_nonidle", action="store_false", help="Diagnostics only; do not cancel/terminate.")
    ap.set_defaults(kill_nonidle=True)
    ap.add_argument("--fail-loud", action="store_true", help="Fail with diagnostics if blockers remain (default behavior).")
    ap.add_argument("--no-fail-loud", dest="fail_loud", action="store_false", help="Return success even if blockers remain.")
    ap.set_defaults(fail_loud=True)
    args = ap.parse_args()

    print(f"[pg_hygiene] connecting db={args.db}")
    try:
        conn = _connect_once(str(args.db))
    except Exception as exc:  # noqa: BLE001
        print(f"[pg_hygiene] FAIL connect db={args.db} err={exc}")
        raise SystemExit(2)
    try:
        with conn.cursor() as cur:
            _print_diag(cur, "before")
            rows = _rows(cur)
            if not rows:
                print("[pg_hygiene] clean")
                print("[pg_hygiene] no non-idle backends remaining")
                return

            if not args.kill_nonidle:
                print("[pg_hygiene] kill_nonidle=off")
                if args.fail_loud:
                    print("[pg_hygiene] FAIL remaining_non_idle_sessions=1 recommendation=restart postgres cluster")
                    raise SystemExit(2)
                return

            _cancel_all(cur)
            time.sleep(1.0)
            _terminate_all(cur)

            deadline = time.time() + float(args.timeout_seconds)
            while time.time() < deadline:
                rows = _rows(cur)
                lock_rows = _managed_lock_rows(cur)
                if not rows:
                    print("[pg_hygiene] cleaned")
                    print("[pg_hygiene] no non-idle backends remaining")
                    return
                if not _has_hard_blockers(lock_rows):
                    print("[pg_hygiene] nonblocking_sessions_remain=1 proceeding")
                    _print_diag(cur, "remaining_nonblocking")
                    return
                time.sleep(0.5)

            _print_diag(cur, "after_failed_cleanup")
            msg = "[pg_hygiene] FAIL remaining_non_idle_sessions=1 recommendation=restart postgres cluster"
            print(msg)
            if args.fail_loud:
                raise SystemExit(2)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
