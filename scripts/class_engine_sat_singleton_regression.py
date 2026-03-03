#!/usr/bin/env python3
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT_CSV = REPO / "logs" / "_class_engine_sat_singleton_regression.csv"
OUT_MD = REPO / "logs" / "_class_engine_sat_singleton_regression.md"


def main() -> None:
    cmd = [
        sys.executable,
        str(REPO / "scripts" / "class_engine_full_language_correctness.py"),
        "--db",
        "tpch1",
        "--policy-min",
        "1",
        "--policy-max",
        "1",
        "--queries",
        "1,3,6",
        "--statement-timeout",
        "20min",
        "--out-csv",
        str(OUT_CSV),
        "--out-md",
        str(OUT_MD),
    ]
    subprocess.run(cmd, check=True)

    rows = list(csv.DictReader(OUT_CSV.open("r", encoding="utf-8")))
    bad = []
    for r in rows:
        reason = (r.get("reason") or "").lower()
        if r.get("status") != "ok":
            bad.append(f"q{r.get('query_id')}: status={r.get('status')} reason={r.get('reason')}")
        if "cnf init failed" in reason:
            bad.append(f"q{r.get('query_id')}: still has CNF init failure")
    if bad:
        raise SystemExit("singleton SAT regression FAILED:\n" + "\n".join(bad))
    print("singleton SAT regression PASS")


if __name__ == "__main__":
    main()
