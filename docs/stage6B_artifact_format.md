# Stage 6B Compact Code Artifact Format

## Scope
Stage 6B changes code artifact encoding only. Semantics are unchanged.

Unchanged:
- dictionaries/domains/ranks logical meaning,
- token ids and comparator semantics,
- `*_ctid` format,
- SAT/hybrid logic.

## New format

### Manifest (`*_code_base`)
- Old row-wise manifest: `CB03`
- New compact manifest: `CB04`

`CB04` layout:
- magic: 4 bytes (`CB04`)
- `int32 total_rows`
- `int32 chunk_rows`
- `int32 ntoks`
- `int32 chunk_count`

### Column chunks
For each table token column `c` and chunk `i`, builder emits:
- `<table>_code_col_<c>_chunk_<i>`

Chunk payload format `CC04`:
- magic: 4 bytes (`CC04`)
- `int32 nrows`
- `uint16 bitwidth`
- `uint16 reserved=0`
- `int32 payload_len`
- bitpacked token stream

Encoding:
- stored value = `tok + 1` (so `-1`/NULL sentinel maps to `0`)
- bitwidth per chunk/column chosen from observed max encoded value

This is columnar + bitpacked, so code bytes drop significantly vs row-wise `CB02`.

## Loader compatibility

`custom_filter/policy.cpp` now supports:
- `CB04` manifests + `CC04` column chunks (preferred path),
- legacy `CB03` + `CB02` (fallback compatibility),
- legacy raw path.

Key decode additions:
- `parse_cb04_manifest(...)`
- `decode_cc04_column_append(...)`
- `decode_table_needed_columns(...)` branch for `CB04_MANIFEST`.

## Size report

Generated report:
- `logs/stage6B_size_report.csv`

Columns include:
- new actual code bytes (`new_code_total_bytes`)
- old row-wise estimate (`old_code_total_bytes_est`)
- ratio (`code_size_ratio_new_over_old_est`)
- dataset-level artifact bytes and load/parse measurements.

Notes:
- `artifact_load_ms_new` / `artifact_parse_ms_new` are measured.
- Old load/parse values in the report are size-based estimates (`*_old_est`) derived from old-vs-new code byte totals for same dataset/policy.

