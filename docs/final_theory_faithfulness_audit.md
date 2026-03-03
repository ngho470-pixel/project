# Final Theory Faithfulness Audit

## Verdict
`faithful-with-caveats`.

Current runtime matches the core mandatory semantics in Part A:
- policy-agnostic artifact model with domain dictionaries/ranks + code/ctid artifacts,
- SAT-guided model enumeration over Tseitin CNF with explicit OR selectors,
- theory propagation on token domains with conflict-driven SAT blocking,
- exact OR-union of per-model allow sets,
- scan-time CTID bitmap enforcement without query rewriting.

Remaining deviations are mostly architectural/performance (not result-correctness on supported semantics), plus one scope deviation (`IN`/`LIKE` still accepted).

## Scope Audited
- `artifact_builder/artifact_builder.c`
- `custom_filter/policy_evaluator.cpp`
- `custom_filter/policy.cpp`
- `custom_filter/custom_filter.c`

## B1) Theory -> Code Mapping

### Artifacts
| Theory item | Status | Evidence |
|---|---|---|
| Policy-scoped column discovery | Implemented | `artifact_builder/artifact_builder.c:960`, `artifact_builder/artifact_builder.c:973`, `artifact_builder/artifact_builder.c:990`, `artifact_builder/artifact_builder.c:1001` |
| Domain assignment via equijoin connectivity | Implemented (union-find + canonical class ids) | `artifact_builder/artifact_builder.c:1022`, `artifact_builder/artifact_builder.c:1036`, `artifact_builder/artifact_builder.c:1100` |
| `meta/join_classes` write | Implemented | `artifact_builder/artifact_builder.c:1182`, `artifact_builder/artifact_builder.c:1209` |
| `meta/col_domain` write | Implemented | `artifact_builder/artifact_builder.c:1212`, `artifact_builder/artifact_builder.c:1225` |
| `meta/cols/<table>` write | Implemented | `artifact_builder/artifact_builder.c:1298`, `artifact_builder/artifact_builder.c:1311` |
| `dict/domain/<id>` write | Implemented | `artifact_builder/artifact_builder.c:1527`, `artifact_builder/artifact_builder.c:1528` |
| `rank/domain/<id>` + `meta/dict_rank/domain/<id>` write | Implemented for ordered domains | `artifact_builder/artifact_builder.c:1540`, `artifact_builder/artifact_builder.c:1542`, `artifact_builder/artifact_builder.c:1547` |
| `T_code_base` write | Implemented (CB04 manifest + column chunks) | `artifact_builder/artifact_builder.c:1486`, `artifact_builder/artifact_builder.c:1494`, `artifact_builder/artifact_builder.c:1506` |
| `T_ctid` write (RID->CTID) | Implemented | `artifact_builder/artifact_builder.c:1399`, `artifact_builder/artifact_builder.c:1502` |
| `meta/join_classes`/`meta/col_domain` load | Implemented | `custom_filter/policy.cpp:2242`, `custom_filter/policy.cpp:2263` |
| `dict/domain/<id>` load | Implemented | `custom_filter/policy.cpp:2321` |
| `rank/domain/<id>` + rank-meta load | Implemented | `custom_filter/policy.cpp:2397`, `custom_filter/policy.cpp:2413` |
| `T_code_base` read/decode | Implemented | `custom_filter/policy.cpp:2424`, `custom_filter/policy.cpp:3426`, `custom_filter/policy.cpp:3480` |
| `T_ctid` read | Implemented | `custom_filter/policy.cpp:2379`, `custom_filter/policy.cpp:2387` |

### Binning / signatures / co-occurrence
| Theory item | Status | Evidence |
|---|---|---|
| Bin/presence representation | Implemented via `TokenBitset` domain supports + row masks | `custom_filter/policy.cpp:4574`, `custom_filter/policy.cpp:5110`, `custom_filter/policy.cpp:4725` |
| Signature classes (`sid`, class rowlists) | Implemented explicitly | `custom_filter/policy.cpp:3906`, `custom_filter/policy.cpp:3994`, `custom_filter/policy.cpp:3999` |
| Active signature set | Implemented (target table) | `custom_filter/policy.cpp:5921`, `custom_filter/policy.cpp:5924` |
| Co-occurrence enforcement | Implemented (same-row checks on multi-col groups + comparator checks) | `custom_filter/policy.cpp:4149`, `custom_filter/policy.cpp:4153`, `custom_filter/policy.cpp:4505` |

### SAT/hybrid (mandatory)
| Theory item | Status | Evidence |
|---|---|---|
| Tseitin CNF build path | Implemented | `custom_filter/policy.cpp:606`, `custom_filter/policy.cpp:700`, `custom_filter/policy.cpp:725` |
| Explicit OR-choice selectors | Implemented | `custom_filter/policy.cpp:636`, `custom_filter/policy.cpp:639`, `custom_filter/policy.cpp:642` |
| SAT solver call site | Implemented (cvc5 incremental CNF solver) | `custom_filter/policy.cpp:755`, `custom_filter/policy.cpp:775`, `custom_filter/policy.cpp:5996` |
| Model->term extraction driven by selectors | Implemented | `custom_filter/policy.cpp:5624`, `custom_filter/policy.cpp:5660`, `custom_filter/policy.cpp:6041` |
| Theory conflict lemma hook | Implemented (coarse clause over selector decisions) | `custom_filter/policy.cpp:6085`, `custom_filter/policy.cpp:6088` |
| Model blocking + enumeration until UNSAT | Implemented | `custom_filter/policy.cpp:6020`, `custom_filter/policy.cpp:6112` |
| Union-of-models computed | Implemented (`OR` into final allow structure) | `custom_filter/policy.cpp:6093`, `custom_filter/policy.cpp:6095` |

### Propagation
| Theory item | Status | Evidence |
|---|---|---|
| Operator-specific pruning `=`/`!=`/`<`/`<=`/`>`/`>=` | Implemented | `custom_filter/policy.cpp:4777`, `custom_filter/policy.cpp:4795`, `custom_filter/policy.cpp:4804` |
| Ordered compare uses rank | Implemented (`token_rank_of`, rank-required checks) | `custom_filter/policy.cpp:3750`, `custom_filter/policy.cpp:4761`, `custom_filter/policy.cpp:3192` |
| Comparable-domain enforcement for col-col | Implemented (compile-time errors) | `custom_filter/policy_evaluator.cpp:918`, `custom_filter/policy_evaluator.cpp:925`, `custom_filter/policy.cpp:3037` |
| Acyclic schedule + cyclic fixpoint fallback | Implemented | `custom_filter/policy.cpp:4856`, `custom_filter/policy.cpp:5199`, `custom_filter/policy.cpp:5277` |
| Bounded-iteration cap that may truncate | Not present in current path | `custom_filter/policy.cpp:5277`, `custom_filter/policy.cpp:5314` (terminates by fixpoint/empty only) |

### Projection and enforcement
| Theory item | Status | Evidence |
|---|---|---|
| `Allow(T|M)` from theory state | Implemented via active signatures + projection | `custom_filter/policy.cpp:5934`, `custom_filter/policy.cpp:5935` |
| RID/CTID model union at target | Implemented | `custom_filter/policy.cpp:6093`, `custom_filter/policy.cpp:6270` |
| RID->CTID->block_words | Implemented | `custom_filter/policy.cpp:4309`, `custom_filter/policy.cpp:6270`, `custom_filter/policy.cpp:6292` |
| Tuple-time CTID membership check | Implemented | `custom_filter/custom_filter.c:3656`, `custom_filter/custom_filter.c:3679` |
| Scan-node interception coverage | Implemented for Seq/Index/Bitmap/Tid/Foreign/etc scan nodes | `custom_filter/custom_filter.c:924`, `custom_filter/custom_filter.c:2862`, `custom_filter/custom_filter.c:3933` |

## B2) Deviations Table

| Deviation | File/line | Why it exists | Risk type | Minimal corrective path |
|---|---|---|---|---|
| `ActiveSig[U]` is explicit only for target projection; non-target tables use row-scan support propagation | `custom_filter/policy.cpp:5921`, `custom_filter/policy.cpp:4577`, `custom_filter/policy.cpp:5281` | Simpler/more memory-stable propagation on witness tables | Performance-only (co-occurrence still exact via row-level checks) | Add signature caches for witness tables too; derive supports from `ActiveSig[U]` instead of row loops |
| Theory lemmas are coarse (negated selector decision set), not minimized reason cores | `custom_filter/policy.cpp:6085`, `custom_filter/policy.cpp:6088`, `custom_filter/policy.cpp:5674` | Stage5 implemented sound but coarse CDCL(T)-style learning | Performance-only | Track per-conflict responsible selector subset (or atom-lits) and learn smaller clauses |
| Runtime still accepts `IN`/`LIKE` const ops though authoritative scope says only `{=,!=,<,<=,>,>=}` | `custom_filter/policy.cpp:2139`, `custom_filter/policy.cpp:2140`, `custom_filter/policy_evaluator.cpp:1098`, `custom_filter/policy_evaluator.cpp:1099` | Backward compatibility with earlier stages | Scope deviation (can hide out-of-theory usage) | Add strict-mode guard in evaluator/parser to reject out-of-scope ops |
| Conjunction evaluation path still goes through `append_clause_plans_from_dnf` helper | `custom_filter/policy.cpp:5812` | Reuses existing clause planner for extracted term atoms | Performance-only | Add direct conjunction->ClausePlan compiler (skip DNF wrapper entirely) |

## B3) “Foulplay” Checklist

| Check | Yes/No | Evidence |
|---|---|---|
| Any brute OR enumeration without CNF/Tseitin SAT? | **NO** | Runtime builds Tseitin CNF then solves it: `custom_filter/policy.cpp:5989`, `custom_filter/policy.cpp:6022` |
| Any heuristic truncation of witness domains (top-K/sampling) without complete fallback? | **NO** | No top-k/sampling path found; domain supports built by exact scans/bitsets (`custom_filter/policy.cpp:4555`, `custom_filter/policy.cpp:5289`) |
| Any propagation cap that can stop before fixpoint without proof? | **NO** | Cyclic loop ends only on `empty || !any_change`: `custom_filter/policy.cpp:5277`, `custom_filter/policy.cpp:5314` |
| Any ordered compare using token-id order when rank exists/required? | **NO** | Ordered col-col requires rank artifacts and errors if missing: `custom_filter/policy.cpp:3192`, `custom_filter/policy.cpp:4761` |
| Any cross-domain col θ col silently allowed? | **NO** | Compile-time rejection in evaluator and planner: `custom_filter/policy_evaluator.cpp:918`, `custom_filter/policy_evaluator.cpp:925`, `custom_filter/policy.cpp:3037` |
| Any runtime base-table scans/SPI queries/joins by policy engine? | **NO** for protected base-table policy evaluation; **YES** for artifact-table fetch (`public.files`) | Artifact fetch only: `custom_filter/policy.cpp:140`, `custom_filter/custom_filter.c:1846` |
| Any early termination of SAT model enumeration that could miss allowed rows? | **NO** | Enumeration loop continues until UNSAT (`custom_filter/policy.cpp:6020`, `custom_filter/policy.cpp:6022`, `custom_filter/policy.cpp:6112`) |

## Practical Bottom Line
The previous “not faithful” verdict is outdated. Current code now implements the required SAT/hybrid control structure with selector-based model enumeration and theory-conflict learning, and preserves exact union semantics. The remaining gaps are mainly architectural/performance refinements and scope tightening, not core semantic unsoundness for the supported Stage semantics.
