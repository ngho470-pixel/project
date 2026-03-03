# Class Engine Strict Contract

## Strict Runtime Contract
In strict experimental mode (`custom_filter.strict_mode=on`), policy evaluation routes only through the class engine:

- `single_hub`
- `two_hop`
- `tree`
- `cycle_rect`

For any unsupported term shape, strict mode fails loud:

- error: `policy: class_engine unsupported term shape on target=<table>`

No fallback to legacy signature/ActiveSig or PFV3 is allowed in strict mode.

Operator surface in runtime/parser is hard-limited to:
- `=`
- `!=`
- `<`
- `<=`
- `>`
- `>=`

Legacy `IN`/`LIKE` operator paths were removed from runtime parser/evaluator code.

## SAT Role
SAT remains the Boolean control plane only:

- Tseitin CNF over policy AST
- selector-model enumeration for OR choices
- term extraction

SAT is not used as the witness/join engine.

## Enforcement Invariants
For strict class-engine runs, per-query invariants must hold:

- `proj_sig_count=0`
- `proj_mask_or_ops=0`
- `proj_rid_iters=0`

## Route Evidence
Per-term route marker (NOTICE):

- `class_route_term: target=<t> route=<single_hub|two_hop|tree|cycle_rect|reject> term_atoms=<...> reason=<...>`

Per-query summary counters (`policy_profile_query`):

- `class_terms_ok`
- `class_terms_reject`
- `class_route_single_hub`
- `class_route_two_hop`
- `class_route_tree`
- `class_route_cycle_rect`
- `class_route_reject`

## GUC Surface
Legacy experimental toggles were removed from runtime source:

- removed/not recognized: `custom_filter.pfv3*`
- removed/not recognized: `custom_filter.query_driven_mode`
- removed/not recognized: `custom_filter.policy_first_v2*`

Strict mode route is class-engine-only.
