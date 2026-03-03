# NO, not complete

Under the full language definition in your Section A, the current strict-mode class engine is **not complete**.

The decisive blockers are implementation caps that are stricter than the language:

1. comparator separator key arity is capped at `<= 2` in tree/cycle-rect planning (`custom_filter/policy.cpp:5591`, `custom_filter/policy.cpp:5618`).
2. cyclic general route is capped by TD width limit `W` (default `2`) and fail-louds above that (`custom_filter/policy.cpp:8025`, `custom_filter/policy.cpp:8928`, `custom_filter/policy.cpp:9322`).
3. exhaustive empirical sweep requested for `(policy 1..30) x (q1,q3,q6,q13,q22)` could not execute here because DB hygiene failed for every case (PostgreSQL unavailable), see `logs/class_engine_full_language_correctness.csv`.

## B1) Completeness Matrix

| Language Feature | Supported? | Exact? | Route | Limits | Code Pointer(s) | Evidence |
|---|---|---|---|---|---|---|
| AND/OR composition (permissive OR, restrictive AND) | Yes | Yes | all class routes | none observed in code path | `custom_filter/policy.cpp:10719`, `custom_filter/policy.cpp:10741`, `custom_filter/policy.cpp:10768`, `custom_filter/policy.cpp:10798`, `custom_filter/policy.cpp:10804` | existing strict correctness logs plus composition code |
| Same-table `T.col θ Const` for `θ={=,!=,<,<=,>,>=}` | Yes | Yes | single_hub/two_hop/tree/cycle_rect/td_cycle | none in operator set | parse op: `custom_filter/policy.cpp:2269`; unary token-set build incl `!=`: `custom_filter/policy.cpp:2819`, `custom_filter/policy.cpp:2838`; row evaluation with NULL->false: `custom_filter/policy.cpp:4413` | `logs/class_neq_correctness.md` (N1 etc) |
| Same-table `T.col θ T.col` for `θ={=,!=,<,<=,>,>=}` | Yes | Yes | local checks inside class routes | comparable-domain assumptions from compiler | local comparator row check: `custom_filter/policy.cpp:4499`, `custom_filter/policy.cpp:4522`; comparator semantics incl `!=`: `custom_filter/policy.cpp:3970` | `logs/stage9_correctness.md`, `logs/class_neq_correctness.md` |
| Cross-table `T1.col θ T2.col` target↔witness (`θ` includes `!=`) | Yes (for supported shapes) | Yes | tree/cycle_rect/td_cycle | tree/cycle-rect key arity cap `<=2`; shape caps | tree planning and cap: `custom_filter/policy.cpp:5487`, `custom_filter/policy.cpp:5591`, `custom_filter/policy.cpp:5618`; key summaries (k1/k2 incl `!=`): `custom_filter/policy.cpp:6315`, `custom_filter/policy.cpp:6502` | `logs/pf_v2_7_correctness.md`, `logs/class_neq_correctness.md` |
| Witness–witness comparators (adjacent) | Yes | Yes | tree | same route/shape caps | witness comparator context + row filter: `custom_filter/policy.cpp:7455`, `custom_filter/policy.cpp:7514`; counters: `custom_filter/policy.cpp:7729` | `logs/class_ww_cmp_correctness.md` |
| Witness–witness comparators (non-adjacent chain) | Yes (tree path) | Yes | tree | still key arity `<=2`; tree-connectable path only | chain summary build and compose counters: `custom_filter/policy.cpp:7197`, `custom_filter/policy.cpp:7208`; filter checks: `custom_filter/policy.cpp:7536` | `logs/class_ww_chain_correctness.md`, `logs/class_ww_chain_perf.md` |
| Cycles (rectangle comparator cycle) | Yes | Yes | cycle_rect | route-specific detector constraints | cycle-rect detect and comparator handling: `custom_filter/policy.cpp:5950` (pattern region), direct key2 summary: `custom_filter/policy.cpp:6167` | `logs/pf_v2_7_correctness.md`, `logs/pf_v2_7_perf.md` |
| Cycles (non-rectangle cyclic join graphs) | Yes (bounded) | Yes (within cap) | td_cycle | TD width cap `W` | td detect: `custom_filter/policy.cpp:8667`, width: `custom_filter/policy.cpp:8927`, fail: `custom_filter/policy.cpp:9322` | `logs/class_td_cycle_fast_correctness.md` |
| Cycles with comparators (non-rectangle comparator factors) | Yes (bounded) | Yes (within cap) | td_cycle | TD width cap `W`; if width exceeded -> reject | comparator edges in TD detect: `custom_filter/policy.cpp:8667`, `custom_filter/policy.cpp:8692`; comparator prune for `=,!=,<,<=,>,>=`: `custom_filter/policy.cpp:8996`, `custom_filter/policy.cpp:9016` | `logs/class_td_cycle_fast_correctness.md` (TDC3) |
| Key arity 1 | Yes | Yes | tree/cycle_rect | none | planner assigns `key_arity`: `custom_filter/policy.cpp:5588`, `custom_filter/policy.cpp:5617` | `logs/class_neq_correctness.md`, `logs/pf_v2_7_perf.md` |
| Key arity 2 | Yes | Yes | tree/cycle_rect | none beyond shape caps | key2 summaries + stats: `custom_filter/policy.cpp:6502`, `custom_filter/policy.cpp:6230` | `logs/pf_v2_7_perf.md`, `logs/class_neq_correctness.md` (N5) |
| Key arity 3+ | **No** | N/A | reject | hard fail-loud | `custom_filter/policy.cpp:5591`, `custom_filter/policy.cpp:5618`; error site `custom_filter/policy.cpp:10365` | `logs/class_neq_shape_fail.md` |
| Multiple occurrences of same base table in plan (aliases / duplicate scans) | **Unproven / partial** | Unknown | executor filter is relid-based | no dedicated alias-completeness tests in strict harness | relid-based filter bind: `custom_filter/custom_filter.c:650`, `custom_filter/custom_filter.c:2899`; table-name based policy compilation in planner | no dedicated alias evidence in current logs |
| Multiple targets in one query + cross-target interactions | Yes (with dependency DAG) | Yes for acyclic target dependencies | all class routes per target | fail-loud on dependency cycle | target dependency ordering and cycle reject: `custom_filter/policy.cpp:10995`, `custom_filter/policy.cpp:11035`, `custom_filter/policy.cpp:11061` | code-level proof; no new exhaustive run in this task |

### Completeness conclusion from matrix

The matrix has at least two **hard NO rows** under your full-language definition:

- key arity `3+` unsupported.
- unbounded cyclic complexity unsupported because td width is bounded (`td_width > W` rejects).

That is sufficient to conclude **NOT complete**.

## B2) Strict-Mode Routing Guarantee

### Dispatch and strict-path proof

Strict/constrained class dispatch is centralized in `eval_term_conjunction_words(...)`:

- route attempts: `single_hub -> two_hop -> cycle_rect -> td_cycle -> tree` at `custom_filter/policy.cpp:10243`, `custom_filter/policy.cpp:10265`, `custom_filter/policy.cpp:10287`, `custom_filter/policy.cpp:10309`, `custom_filter/policy.cpp:10338`.
- unsupported term fail-loud: `custom_filter/policy.cpp:10365`.
- per-term route marker notice: `class_route_term` at `custom_filter/policy.cpp:9633`.
- per-query route counters in `policy_profile_query`: `custom_filter/policy.cpp:9645`.

Strict-mode flag parser:

- policy engine strict check: `custom_filter/policy.cpp:172`.
- executor strict check: `custom_filter/custom_filter.c:3170`.

### Legacy-route reachability check (grep evidence)

Searched strict runtime code for legacy entrypoints and PFV3/query-driven switches:

- `pfv3`: no matches in `custom_filter/policy.cpp` and `custom_filter/custom_filter.c`.
- `propagate_clause(`, `refine_witness_active_sigs`, `project_active_signatures_to_block_words`: no matches.
- `query_driven_mode`: no matches.

This indicates strict runtime currently has no alternate PFV3/query-driven dispatch path in these files.

## B3) Empirical Evidence on drona target workload

### Requested exhaustive sweep artifact

Runner added:

- `scripts/class_engine_full_language_correctness.py`

Output produced (local runner attempt):

- `logs/class_engine_full_language_correctness.csv`
- `logs/class_engine_full_language_correctness.md`

Result on this host:

- all 150 cases (`policy 1..30` x `q1,q3,q6,q13,q22`) failed at hygiene/connect stage.
- root cause in CSV `hygiene_diag`: PostgreSQL connection refused on `localhost:5432`.

On drona, runner smoke evidence is available:

- `logs/class_engine_full_language_drona_smoke.csv`
- `logs/class_engine_full_language_drona_smoke.md`

This drona smoke (`policy 1`, queries `1,3,6,13,22`) shows a runtime blocker in strict path for some queries:

- `ERROR: policy: cvc5 CNF init failed: Invalid kind 'AND' ... has 1 child`

So full exhaustive drona sweep is currently blocked by an engine bug in CNF/Tseitin construction for unary-AND forms, not by routing configuration.

### Additional strict empirical evidence available in repo

These pre-existing strict logs show route/counter behavior for major feature families:

- `logs/pf_v2_7_correctness.md` / `logs/pf_v2_7_perf.md` (cycle_rect comparator path, invariants zero).
- `logs/class_neq_correctness.md` and `logs/class_neq_shape_fail.md` (`!=` support + arity>2 fail-loud).
- `logs/class_ww_cmp_correctness.md` (witness-witness adjacent).
- `logs/class_ww_chain_correctness.md` and `logs/class_ww_chain_perf.md` (witness-witness non-adjacent chain).
- `logs/class_td_cycle_fast_correctness.md` and `logs/class_td_cycle_fast_perf.md` (td_cycle incl non-rectangle comparator case).

## B4) Final Answer (hard)

**NO, not complete.**

### Exact missing constructs under full-language definition

1. **Comparator separator key arity `>2`** is not supported (reject/fail-loud).
2. **Unbounded cyclic terms** are not supported due strict TD width cap (`td_width > W` reject).
3. **Alias/duplicate-scan completeness** is not yet proven by dedicated strict tests.
4. Full exhaustive drona sweep is currently blocked by the `cvc5 CNF init failed (AND arity=1)` runtime bug on a subset of policy/query cases.

### Minimal roadmap to become complete while staying class/bin-based

1. Lift tree/cycle-rect key arity cap from `<=2` to general `k` with sparse keyed summaries.
2. Lift strict TD width cap (or add exact decomposition fallback with bounded resource policy) for all cyclic terms.
3. Add alias/duplicate-table strict tests and route evidence rows in harness.
4. Fix unary-AND CNF construction, then re-run exhaustive `tpch1` sweep to populate per-(policy,query) route and invariant evidence.
