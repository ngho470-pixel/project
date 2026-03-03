#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def read_rows(csv_path: Path):
    with csv_path.open() as f:
        return list(csv.DictReader(f))


def to_float(v: str, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: smoke_analysis.py <results.csv>", file=sys.stderr)
        return 2
    csv_path = Path(sys.argv[1]).resolve()
    rows = read_rows(csv_path)
    if not rows:
        print("empty csv", file=sys.stderr)
        return 2

    out_dir = csv_path.parent
    plot_dir = out_dir / "smoke_plots"
    plot_dir.mkdir(parents=True, exist_ok=True)

    hot_by_baseline = defaultdict(list)
    ok_count = defaultdict(int)
    total_count = defaultdict(int)
    corr_true = defaultdict(int)

    for r in rows:
        b = r["baseline"]
        total_count[b] += 1
        if str(r.get("status", "0")) == "1":
            ok_count[b] += 1
        if str(r.get("correctness", "")).upper() == "TRUE":
            corr_true[b] += 1
        if r.get("hot_ms"):
            hot_by_baseline[b].append(to_float(r["hot_ms"]))

    baselines = sorted(total_count.keys())
    hot_medians = [statistics.median(hot_by_baseline[b]) if hot_by_baseline[b] else 0.0 for b in baselines]
    corr_rates = [corr_true[b] / total_count[b] if total_count[b] else 0.0 for b in baselines]

    plt.figure(figsize=(10, 5))
    plt.bar(baselines, hot_medians)
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("median hot_ms")
    plt.title("Smoke: median hot time by baseline")
    plt.tight_layout()
    p1 = plot_dir / "hot_ms_by_baseline.png"
    plt.savefig(p1)
    plt.close()

    plt.figure(figsize=(10, 5))
    plt.bar(baselines, corr_rates)
    plt.ylim(0, 1.0)
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("correctness rate")
    plt.title("Smoke: correctness rate by baseline")
    plt.tight_layout()
    p2 = plot_dir / "correctness_rate.png"
    plt.savefig(p2)
    plt.close()

    md = out_dir / "smoke_analysis.md"
    with md.open("w") as f:
        f.write("# Smoke Analysis\n\n")
        f.write(f"- source_csv: `{csv_path}`\n")
        f.write(f"- total_rows: {len(rows)}\n")
        f.write(f"- plot_hot: `{p1}`\n")
        f.write(f"- plot_correctness: `{p2}`\n\n")
        f.write("## Baseline Summary\n")
        for b in baselines:
            med = statistics.median(hot_by_baseline[b]) if hot_by_baseline[b] else 0.0
            f.write(
                f"- {b}: cases={total_count[b]} ok={ok_count[b]} correctness_true={corr_true[b]} "
                f"median_hot_ms={med:.3f}\n"
            )

    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
