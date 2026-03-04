# SigBin Engine

## Target Pipeline
1. Build target-row signatures in token space.
2. Bin rows by signature assignment.
3. Solve policy Boolean structure in SAT over signature variables.
4. Materialize allow bitmap as union of allowed signature bins.
5. Execute page-local hit-only scan from bitmap.

## Implemented in `fd34951`
- `custom_filter/policy.cpp` single-table formula fast path now evaluates in **signature space**:
  - atom evaluation on signature tokens (not RID unions)
  - AST `AND/OR` over `TokenBitset` signatures
  - projection to `SparseBlockWords` via prebuilt `sig_mask_offsets/sig_mask_blocks/sig_mask_word_vals`
- `SignatureCacheEntry` now stores `rid_to_sid` for O(#setbits) RID->signature projection.
- `class_set_target_sig_bits_from_rids()` now iterates set RID bits only and uses cached `rid_to_sid`.

## Smoke Evidence
- `logs/gate_tpch0_1_sigbin_smoke.csv`
- `logs/gate_tpch0_1_sigbin_smoke.md`

Observed for `tpch0_1 / S_A / q1 / ours`:
- `single_table_bin_fastpath_used=5`
- `class_route_single_hub=5`
- `bin_rids_scanned_total=0` (policy-side RID scan eliminated for this path)

## Remaining Work For Full Replacement
- Cross-table join/comparator term routes still produce row-oriented feasibility and must be rewritten to signature/bin payloads.
- SAT output still combines term-level results from legacy route evaluators for non-single-table terms.
- Artifact builder still persists CSR token->RID bins; full sigbin path needs bin-bitmaps as primary artifact.
- Executor still supports multiple scan modes; page-local hit-only mode should be made default for sigbin allow bitmaps.
