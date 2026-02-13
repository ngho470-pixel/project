# Remote-First Workflow (`drona`)

This repo can run experiments on `drona` and automatically sync outputs back locally.

## Helper Script

Use:

```bash
scripts/drona_run.sh -- <remote command>
```

Defaults:
- host: `nghosh@drona.cse.iitd.ac.in`
- remote root: `/tmp/z3_lab/project`
- sync local -> remote before running
- sync remote -> local after running (even if command fails)

`cvc/` and `cvc5/` are excluded by default for speed. Use `--full-tree` to include them.

## Examples

Smoke run:

```bash
scripts/drona_run.sh -- "python3 fast_sweep_profile_60s.py --run --smoke-check --smoke-only --db tpch0_1 --policy policy.txt --queries queries.txt --policies-enabled policies_enabled.txt --statement-timeout 600s"
```

Single correctness sweep:

```bash
scripts/drona_run.sh -- "python3 correctness_tpch0_1_k1_10_20.py --db tpch0_1 --ks 1 10 20 --policy /tmp/z3_lab/policy.txt --queries /tmp/z3_lab/queries.txt --enabled-path /tmp/z3_lab/policies_enabled.txt --custom-filter-so /tmp/z3_lab/custom_filter.so --artifact-builder-so /tmp/z3_lab/artifact_builder.so"
```

Only sync (no run):

```bash
scripts/drona_run.sh
```
