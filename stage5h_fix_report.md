# Stage-5H Fix Report

## Scope
- Objective: eliminate backend crash for `K=5, Q6` (`lineitem JOIN orders JOIN customer`) and guarantee fail-closed ERRORs instead of segfaults.
- Code change scope: `custom_filter/custom_filter.c` only.

## 1) Crash Repro Evidence (before patch)

### Repro command block used
```bash
# policy/artifacts
head -n 5 /home/ng_lab/z3/policy_supported.txt > /home/ng_lab/z3/tmp_policy_k5.txt
psql -d tpch0_1 -v ON_ERROR_STOP=1 <<'SQL'
TRUNCATE public.files;
LOAD '/home/ng_lab/z3/artifact_builder/artifact_builder.so';
SELECT build_base('/home/ng_lab/z3/tmp_policy_k5.txt');
SQL

# query
psql -d tpch0_1 -v ON_ERROR_STOP=1 <<'SQL'
SET max_parallel_workers_per_gather=0;
SET statement_timeout='30min';
SET custom_filter.policy_path='/home/ng_lab/z3/tmp_policy_k5.txt';
LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SELECT COUNT(*)
FROM lineitem l
JOIN orders o ON l.l_orderkey = o.o_orderkey
JOIN customer c ON o.o_custkey = c.c_custkey;
SQL
```

### PostgreSQL log evidence
- From `/var/log/postgresql/postgresql-16-main.log`:
  - `2026-02-09 03:50:06.388 ... server process (PID 2770455) was terminated by signal 11`
  - Failed statement:
    - `SELECT COUNT(*) FROM lineitem l JOIN orders o ON l.l_orderkey=o.o_orderkey JOIN customer c ON o.o_custkey=c.c_custkey;`
  - Immediate recovery-mode FATAL followed.

### Core/backtrace evidence
- `coredumpctl info 2770455 --no-pager` stack excerpt:
  - `custom_filter.so + 0xbf898`
  - `custom_filter.so + 0xc6517`
  - then postgres executor frames.
- Previous symbol mapping (from `addr2line`) mapped these into `custom_filter/custom_filter.c` hot scan path.

## 2) Patch Applied

### File changed
- `custom_filter/custom_filter.c`

### Safety changes implemented
- Added strict RID/bitmap bounds checks in tuple filter hot path (fail-closed `ERROR`).
- Added CTID/index invariants in `cf_ctid_to_rid` before any lookup math.
- Added `allow_nbytes` tracking and byte-bound validation before bit access.
- Added query-lifetime memory context assertions in contract mode for retained chunks (`allow_bits`, ctid arrays/index/hash, blobs).
- Added consistency checks:
  - `_ctid` payload shape,
  - `n_rows` vs ctid pair count,
  - allow bitmap size vs rows,
  - non-null retained structures when required.
- Kept fail-closed behavior (`ereport(ERROR, ...)`) instead of allowing undefined behavior.

## 3) Post-patch Crash Regression

### 50 fresh-session strict loop
- Command output log: `/home/ng_lab/z3/stage5h_after_patch_loop50_strict.log`
- Result:
  - `runs_ok=50`
  - `runs_nonzero=0`
- No new segfault line was appended to postgres log during this loop.

### Crash-marker check
- Last `signal 11` entry in postgres log remains:
  - `2026-02-09 03:50:06.388 ... PID 2770455`
- No later `terminated by signal 11` line after patch regression runs.

## 4) Sweep Re-run After Patch

### Command
```bash
python3 /home/ng_lab/z3/stage_policy_scaling_correctness.py > /home/ng_lab/z3/stage5h_sweep_after_patch2.out 2>&1
```

### Result
- Output files:
  - `/home/ng_lab/z3/policy_scale_correctness.csv`
  - `/home/ng_lab/z3/policy_scale_correctness.md`
- Summary:
  - `rows=15`
  - status counts: `PASS=12, SKIP=2, ERROR=1`
  - stop reason: `error` (not crash)

### Minimal failing repro (new blocker)
- Stop case:
  - `K=15`, `query_id=1`, query: `SELECT COUNT(*) FROM customer;`
  - policy file: `/home/ng_lab/z3/tmp_policy_k15.txt`
- Repro log:
  - `/home/ng_lab/z3/logs/K15_Q1_contract.log`
- Error:
  - `policy_contract: const atom y13 missing in meta/join_classes (col=customer.c_nationkey)`

### Suspected component
- **Primary suspect**: evaluator/contract-mapping metadata consistency for const atoms on join-key columns.
  - Evidence: const atom appears with join-class metadata (`jc=1`) and contract validation expects join-class mapping consistency where const-atoms should remain const-only.
- **Likely area**:
  - contract validator path in `custom_filter/custom_filter.c` and/or atom classification in evaluator output consumed by that path.

## 5) Current Status
- Backend crash path for `K=5, Q6` is eliminated in strict 50-session regression (no new segfaults).
- Stage is still blocked by a non-crash engine/contract consistency error at `K=15, Q1`; this is now the minimal repro to fix next.
