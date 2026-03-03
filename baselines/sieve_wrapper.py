from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple


def java_available() -> bool:
    return shutil.which("java") is not None


def ensure_sieve_artifact(repo_root: Path) -> Path:
    jar = repo_root / "Sieve-master" / "target" / "sieve-rewriter.jar"
    if jar.exists():
        return jar
    if not java_available():
        raise RuntimeError("java runtime not found")
    cmd = ["mvn", "-q", "-DskipTests", "package"]
    proc = subprocess.run(cmd, cwd=str(repo_root / "Sieve-master"), capture_output=True, text=True)
    if proc.returncode != 0 or not jar.exists():
        raise RuntimeError(f"failed to build sieve-rewriter.jar: {proc.stderr or proc.stdout}")
    return jar


def rewrite_sql_with_sieve(
    jar_path: Path,
    db: str,
    pg_host: str,
    pg_port: int,
    user: str,
    password: str,
    policy_file: Path,
    query_sql: str,
) -> Tuple[str, float, str]:
    if not java_available():
        return "", 0.0, "java runtime not found"
    cmd: List[str] = [
        "java",
        "-jar",
        str(jar_path),
        "--jdbc",
        f"jdbc:postgresql://{pg_host}:{pg_port}/{db}",
        "--user",
        user,
        "--password",
        password,
        "--policy",
        str(policy_file),
        "--query",
        query_sql,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return "", 0.0, (proc.stderr or proc.stdout or "sieve wrapper failed")[:500]
    try:
        payload = json.loads((proc.stdout or "").strip())
    except Exception as exc:  # noqa: BLE001
        return "", 0.0, f"invalid sieve json: {exc}"[:500]

    err = str(payload.get("error") or "").strip()
    rewritten = str(payload.get("rewritten_sql") or "").strip()
    rewrite_ms = float(payload.get("rewrite_ms") or 0.0)
    if err:
        return "", rewrite_ms, err[:500]
    if not rewritten:
        return "", rewrite_ms, "missing rewritten_sql"
    return rewritten, rewrite_ms, ""


def shell_quote_cmd(cmd: List[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)
