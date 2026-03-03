# Class Engine Experiment Harness

This repo is sanitized to run baseline sweeps for the class-engine policy system.

## What is included
- `custom_filter/`: extension runtime (`custom_filter.so`) and policy engine.
- `artifact_builder/`: artifact builder runtime.
- `Sieve-master/`: Sieve baseline source/jar build.
- `run_test.py`: one-command sweep runner.
- `baselines/`: baseline adapters (`no_policy`, `view_based`, `rls`, `rls_index`, `sieve`, `sieve_index`, `ours`).
- `utils/`: runner utilities.
- `fast_sweep_profile_60s.py`: shared DB/session/policy helper layer.
- `policy.txt`, `queries.txt`: policy pool and TPCH query text.
- `scripts/`: `drona_run.sh`, `pg_hygiene.py`, `setup_drona_env.sh`, `smoke_analysis.py`.
- `wheels/`: offline Python wheelhouse for drona venv installs.

## Run sweep

```bash
python3 run_test.py
```

`run_test.py` has all configuration at top-level constants.

## Smoke mode
Set in `run_test.py`:
- `SMOKE_ONLY = True`

Smoke covers `tpch1`, policy sets `{1-5, 11-20, 21-30}`, queries `{1,3,6,10,11}`, baselines `{no_policy, view_based, rls, rls_index, ours, sieve, sieve_index}`.

## Drona deployment
Sync and run on drona (`/home/nghosh/setu`):

```bash
scripts/drona_run.sh --remote-root /home/nghosh/setu -- "python3 run_test.py"
```

## Offline analysis environment on drona
Create venv and install analytics packages from local wheelhouse:

```bash
bash scripts/setup_drona_env.sh /home/nghosh/setu
```

This installs packages with `pip --no-index --find-links wheels`.

## Smoke analysis plots
Generate summary markdown and plots from a sweep CSV:

```bash
python3 scripts/smoke_analysis.py logs/sweep_YYYYMMDD_HHMMSS/results.csv
```

Outputs:
- `logs/smoke_analysis.md`
- `logs/smoke_plots/hot_ms_by_baseline.png`
- `logs/smoke_plots/correctness_rate.png`
