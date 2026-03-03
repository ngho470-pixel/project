# Class Engine TD-Cycle Route

## Scope
- Strict-mode class engine route: `td_cycle`.
- Triggered for conjunction terms whose target-connected join incidence graph is cyclic and not matched by specialized `cycle_rect`.
- Width bound: `W=2` by default (`CF_CLASS_TD_WIDTH_LIMIT` overrides for validation).
- If computed TD width exceeds `W`, strict mode errors with:
  - `policy: class_engine unsupported term shape on target=... (td_width=... > W=...)`.

## Core Algorithm
1. Build table-variable incidence from cross-table equality join atoms.
2. Detect target-connected cyclic component.
3. Build primal graph over class variables in that component.
4. Run deterministic min-fill elimination (target vars eliminated last).
5. Enforce width cap (`td_width <= W`).
6. Build sparse factor relations per table from CSR bins + row-local checks:
   - driver domain selected by smallest token universe.
   - scan bin slices `Bin(table, domain, token)`.
   - keep rows passing unary + same-table comparators.
   - emit unique token tuples over table scope variables.
7. Run elimination DP over relations (natural join + existential projection).
8. Project final feasible relation to target vars and stamp CTIDs:
   - arity 1: token bins
   - arity 2: bin intersection (two-pointer)
   - arity >2: target row scan membership

## Strict Invariants
- `proj_sig_count=0`
- `proj_mask_or_ops=0`
- `proj_rid_iters=0`

## Route / Counters
- Per-term notice:
  - `class_route_term: ... route=td_cycle width=<w> bags=<n> ...`
- Per-query counters in `policy_profile_query`:
  - `class_td_terms_total`
  - `class_td_terms_supported`
  - `class_td_width_max`
  - `class_td_bags`
  - `class_td_build_ms`
  - `class_td_dp_ms`
  - `class_td_msg_entries_total`
  - `class_td_fail_width`
  - `class_route_td_cycle`

## Validation Scripts
- `scripts/class_td_cycle_correctness_verify.py`
- `scripts/class_td_cycle_shape_fail.py`
- `scripts/class_td_cycle_perf.py`
