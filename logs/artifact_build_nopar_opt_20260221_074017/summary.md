# Artifact Build Optimization (No Parallelism)

## Environment
- Host: drona.cse.iitd.ac.in
- DB: `tpch1`
- Policy set: `/tmp/z3_cf/policies/enabled_tpch1_k15_1_5_11_20.txt`
- Command:
  - `LOAD '/tmp/z3_cf/artifact_builder.so'; SELECT build_base('/tmp/z3_cf/policies/enabled_tpch1_k15_1_5_11_20.txt');`

## Before (previous optimized baseline)
- `artifact_builder: total_ms=38368.934`
- `/usr/bin/time elapsed_s=38.49`
- Hot tables:
  - `lineitem table_tokenize_ms=30367.198`
  - `orders table_tokenize_ms=3849.371`

## After (this change)
- Run 1:
  - `artifact_builder: total_ms=34756.498`
  - `/usr/bin/time elapsed_s=34.88`
- Run 2:
  - `artifact_builder: total_ms=34708.925`
  - `/usr/bin/time elapsed_s=34.84`
- Hot tables (run 2):
  - `lineitem table_tokenize_ms=27061.786`
  - `orders table_tokenize_ms=3484.894`

## Delta vs previous baseline
- Build wall-time: `38.49s -> 34.84s` (~9.5% faster)
- Builder total_ms: `38368.934 -> 34708.925` (~9.5% faster)
- lineitem tokenize_ms: `30367.198 -> 27061.786` (~10.9% faster)

## What changed
- Added typed token-map fast paths in `artifact_builder/artifact_builder.c`:
  - int/date keys avoid per-row text conversion
  - varlena keys (including numeric/text/bpchar) avoid per-row output-function conversion
- Kept execution single-threaded (no parallel workers).
