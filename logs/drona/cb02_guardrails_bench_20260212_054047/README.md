# CB02 Guardrails Benchmark

- db: tpch0_1
- ks: 1,15,20
- old builder: /tmp/z3_lab/bench/old/artifact_builder.so
- new builder: /tmp/z3_lab/bench/new/artifact_builder.so

## Build Wall/RSS
- note: `maxrss_kb` is from `/usr/bin/time -v` on the `psql` client command.
- K=1 old_elapsed=0:01.88 old_maxrss_kb=10044 new_elapsed=0:01.71 new_maxrss_kb=9904
- K=15 old_elapsed=0:14.30 old_maxrss_kb=9980 new_elapsed=0:14.17 new_maxrss_kb=9920
- K=20 old_elapsed=0:18.99 old_maxrss_kb=9940 new_elapsed=0:18.86 new_maxrss_kb=10044

## Artifact Payload Bytes (before vacuum)
- K=1 old_code_ctid_total_bytes=12011440 new_code_ctid_total_bytes=10810308
- K=15 old_code_ctid_total_bytes=33568156 new_code_ctid_total_bytes=32037012
- K=20 old_code_ctid_total_bytes=41392732 new_code_ctid_total_bytes=39659624

## SPI Profile (log_statement=all)
- top-level log_statement output did not include nested SPI INSERT text in this environment
- build output shows 89 artifact rows in public.files (one per artifact name), not per-table-row inserts
- inspect spi_profile_build.out for full statement trace

## CB02 Regression
- cb02_roundtrip=ok
- corrupt_cb02_error=ok
- v1_fallback=ok
- restored_cb02=ok
