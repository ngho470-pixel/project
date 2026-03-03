# Harness Profile-Capture Hang (`run_ours_profile_capture`) 

## Symptom
- `fast_sweep_profile_60s.py` could appear to hang during OURS profile capture (`run_ours_profile_capture`), typically in drona runs.
- Process state showed Python blocked in socket poll, with little/no harness output for long intervals.
- In some cases no active `pg_stat_activity` query was visible, making the stall opaque.

## Root Cause (Control-Plane)
The harness used synchronous psycopg/libpq calls (`cur.execute`, `fetchall`) with:
- no client-side wait timeout around libpq socket polling, and
- no milestone logging for the capture sub-steps.

So any control-plane stall in the client wait path (network/socket/protocol wait, or simply long silent execution with buffered stdout) looked like an indefinite hang.

This was a harness diagnosability + timeout bug, not a policy-engine semantics bug.

## Fix
Added a capture watchdog and structured milestone tracing around `run_ours_profile_capture`:

1. Milestones (timestamped)
- `CAPTURE_START`
- `CONNECT_START` / `CONNECT_OK`
- `QUERY_SUBMIT_START` / `QUERY_SUBMIT_OK`
- `WAIT_RESULT_START` / `WAIT_RESULT_RETURNED`
- `READ_PROFILE_START` / `READ_PROFILE_OK`
- `CAPTURE_END`

2. Fail-loud client-side timeout for psycopg/libpq wait
- Implemented a temporary psycopg wait callback (`psycopg2.extensions.set_wait_callback`) with `select()` timeout.
- On timeout, the harness now dumps:
  - last milestone(s)
  - Python PID / socket fd / SQL text
  - `ps -ef` relevant lines
  - `pg_stat_activity` non-idle rows for the target DB
- Then raises `CaptureTimeoutError` (non-zero exit), instead of hanging silently.

3. Structured logging controls
- `CF_CAPTURE_TRACE=1` enables milestone logs to stderr.
- `CF_CAPTURE_WATCHDOG_SECONDS=<N>` controls the capture control-plane timeout (default `60`).

## Reproduction / Verification

### Minimal capture-only probe (fast, <10s on drona)
This exercises the exact `run_ours_profile_capture` path via `--layer-probe`.

```bash
./scripts/drona_run.sh -- "export PGOPTIONS='-c custom_filter.strict_mode=on' CF_POLICY_STRICT_MODE=1 CF_CAPTURE_TRACE=1 CF_CAPTURE_WATCHDOG_SECONDS=60; python3 fast_sweep_profile_60s.py --layer-probe --db tpch1 --ks 10 --policy-pool 11-20 --query-ids 13 --statement-timeout 30min --run-dir logs/drona/capture_probe_q13"
```

### Heavier capture probe (same path, q1)
This is the previously problematic path shape; it is expected to take much longer than 10s on `tpch1`.

```bash
./scripts/drona_run.sh -- "export PGOPTIONS='-c custom_filter.strict_mode=on' CF_POLICY_STRICT_MODE=1 CF_CAPTURE_TRACE=1 CF_CAPTURE_WATCHDOG_SECONDS=90; python3 fast_sweep_profile_60s.py --layer-probe --db tpch1 --ks 10 --policy-pool 11-20 --query-ids 1 --statement-timeout 30min --run-dir logs/drona/capture_probe_q1"
```

## Notes
- The new watchdog does **not** change DB semantics or engine behavior; it only hardens the harness control plane.
- Strict mode remains ON in the reproduction commands.
