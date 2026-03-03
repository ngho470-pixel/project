# Class Engine `!=` Support

## Scope
This stage extends strict class-engine comparator support to include `!=` for:
- same-table `col != const`
- same-table `col != col`
- cross-table `U.x != V.y` on supported class routes (`tree`, `cycle_rect`) with key arity `1..2`

Unsupported in strict mode (fail-loud):
- cross-table `!=` with separator key arity `> 2`
- any term shape already unsupported by class routes

## Semantics
For comparisons, NULL token (`tok < 0`) is treated as UNKNOWN -> false.

`x != y` is true iff both tokens are non-NULL and different.

## Summary structure for cross-table `!=`
For each comparator summary key `k` (arity 1 or 2), witness-side summary stores:
- `neq_cnt[k] in {0,1,2}`: capped number of distinct witness comparator tokens
- `neq_one[k]`: the unique token when `neq_cnt[k] == 1`

Target acceptance for `(key=k, xtok=x)`:
- accept if `neq_cnt[k] >= 2`
- accept if `neq_cnt[k] == 1` and `neq_one[k] != x`
- else reject

This is exact existential semantics:
`exists witness y with y != x` under key `k`.

## Implementation mapping
- Comparator planning no longer rejects `ConstOp::NE` in:
  - `pf2_tree_detect_pattern(...)`
  - `pf2_cycle_rect_detect_pattern(...)`
- Key1 summary builder:
  - `pf2_tree_build_cmp_summary_key1(...)`
  - adds `need_neq`, `neq_cnt`, `neq_one`
- Key2 summary builders:
  - `pf2_tree_build_cmp_summary_key2(...)`
  - `pf2_cycle_build_cmp_summary_key2_direct(...)`
  - add `need_neq`, key2 `(cnt,one)` aggregation (sparse and dense)
- Target row comparator check:
  - `pf2_cmp_summary_accept_target_row(...)`
  - exact `!=` acceptance using `(cnt,one)`
- Same-table `!=` remains row-local token check through:
  - `token_compare(...)`
  - `pf2_row_matches_table_local_atoms(...)`

## Complexity
- Summary build: one witness-side scan over relevant bin-driven rows.
- Check: O(1) per candidate target row.
- No signature projection path introduced; strict invariants remain:
  - `proj_sig_count=0`
  - `proj_mask_or_ops=0`
  - `proj_rid_iters=0`
