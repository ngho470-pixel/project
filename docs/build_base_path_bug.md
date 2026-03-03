# build_base Path Bug (fast_sweep Remote Runs)

## Symptom
`fast_sweep_profile_60s.py --run` could fail on `drona` with:

- `psycopg2.errors.InternalError_: failed to parse policies at logs/.../enabled_policies_*.txt`

This was initially misdiagnosed as a "long path" issue because using `--server-policy-dir /tmp` made the error disappear.

## Actual Root Cause
The failure was caused by passing a **relative path** (for the enabled policy file) into `public.build_base(text)`.

`build_base()` runs inside the PostgreSQL backend and calls `fopen(policy_path, ...)` in the extension (`artifact_builder`). Relative paths are resolved against the **server/backend process working directory**, not the harness process working directory.

So a path like:

- `logs/drona/.../enabled_policies_tpch1_k10.txt`

exists relative to the harness run directory, but not necessarily relative to the Postgres backend CWD. The backend then fails to open the file, and `build_base()` reports the generic error `failed to parse policies ...`.

`--server-policy-dir /tmp` worked because it produced an **absolute path**, which the backend could open reliably.

## Fix
Make the enabled policy file path passed to `build_base()` absolute in `fast_sweep_profile_60s.py`:

- `enabled_policy_path_for_k(...)` now canonicalizes to an absolute path
- `server_enabled_policy_path(...)` now canonicalizes relative `server_policy_dir` to an absolute path before constructing the server-side filename

This removes the need for the `/tmp` workaround.

## Code Changes
- `fast_sweep_profile_60s.py`
  - `enabled_policy_path_for_k(...)`
  - `server_enabled_policy_path(...)`

## Validation
- `scripts/stage9_correctness_verify.py` on `drona` runs successfully with normal paths.
- `fast_sweep_profile_60s.py --run` (tidscan ON/OFF sweep for `tpch1`, policies `11..20`, queries `1,3,6,13,22`) now starts and proceeds without `--server-policy-dir /tmp`.

## Notes
- The error text from `build_base()` is currently ambiguous (`failed to parse policies` also covers file-open failures). If needed later, the extension can be improved to distinguish `fopen` failure from parse failure explicitly.
