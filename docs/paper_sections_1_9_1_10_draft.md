## 1.9 The Class-Based (SigBin) Approach

We now formalize the class-based approach used by our engine. The key idea is to avoid per-row policy evaluation by grouping target rows that are indistinguishable with respect to policy-relevant Boolean features.

Let $T$ be a target table and let
$$
\mathcal{A}_T = \langle a_1, a_2, \dots, a_k \rangle
$$
be the ordered list of policy feature-atoms used for $T$ (after normalization/deduplication and constant folding).

For each target row $r \in \mathrm{Rows}(T)$, define its signature:
$$
\mathrm{sig}_T(r) = \langle b_1, \dots, b_k \rangle \in \{0,1\}^k,
\quad
b_i = 1 \iff a_i\text{ is true for }r.
$$

Each distinct signature value induces one class (bin). For a signature $s \in \{0,1\}^k$:
$$
B_s = \{r \in \mathrm{Rows}(T) \mid \mathrm{sig}_T(r)=s\}.
$$
Let $\Sigma_T = \{\mathrm{sig}_T(r) : r \in \mathrm{Rows}(T)\}$ be the set of observed signatures. We assign each $s \in \Sigma_T$ a class id $\mathrm{sid}(s)$.

Thus policy evaluation is lifted from rows to classes:
1. Build one signature per row,
2. Group rows into bins $\{B_s\}_{s\in\Sigma_T}$,
3. Evaluate policy formula only once per signature,
4. Return union of bins whose signature is allowed.

### Running policy example

For lineitem policy $P_L$ in Section 1.6, define feature atoms:
- $y_1(l):\; l\_discount \le 0.07$
- $y_2(l):\; \exists o\;[o\_orderkey=l\_orderkey \wedge o\_orderstatus='F' \wedge l\_extendedprice \le o\_totalprice]$

So the policy formula is
$$
\Phi_L(y_1,y_2)= y_1 \wedge y_2.
$$
Each lineitem row has a 2-bit signature $(y_1,y_2)$, giving four possible bins:
$B_{00},B_{01},B_{10},B_{11}$. Only $B_{11}$ satisfies $\Phi_L$.
Hence
$$
\mathrm{Allow}(\mathrm{lineitem}) = B_{11}.
$$

For orders policy $P_O$, one useful atomization is
$$
\Phi_O=(y_G \vee y_F) \wedge y_{\neq},
$$
where $y_G,y_F$ correspond to witness paths via nation = GERMANY/FRANCE and $y_{\neq}$ is the witness condition $o\_totalprice \neq c\_acctbal$.
Again evaluation is once per signature bin, not per row.

## 1.10 Propagation + SAT over Signature Bins

This section formalizes how witness constraints are propagated and how SAT decides allowed signature bins.

### 1.10.1 Propagation model

From join/equality structure, construct a hub graph:
- hubs $h \in H$ represent join token domains,
- each hub has domain $D_h$ (currently feasible tokens),
- each directed arc $e=(h_i\to h_j)$ has adjacency relation
$$
R_e \subseteq D_{h_i}\times D_{h_j}
$$
induced by tuples in witness tables.

For each context (a scoped set of relevant atoms), we perform domain pruning and support propagation.

Propagation algorithm (context-level):

```text
Input:
  Hub graph (H, E), domains {D_h}, arc relations {R_e}
Output:
  Pruned domains {D_h} and empty/non-empty flag

Q <- all arcs E
while Q not empty:
  (u -> v) <- pop(Q)
  removed <- false
  for each token t in D_v:
    if no token s in D_u with (s,t) in R_(u->v):
      remove t from D_v
      removed <- true
  if D_v = empty: return EMPTY
  if removed:
    push all outgoing arcs (v -> w) into Q

for each cyclic SCC C in H:
  run exact-support step on C
  if some D_h becomes empty: return EMPTY

return NON_EMPTY
```

#### Arc-consistency pruning

A token $t\in D_{h_j}$ is removed if no supporting token exists in any required incoming arc relation. Formally, for incoming arcs $\mathrm{In}(h_j)$:
$$
\exists e=(h_i\to h_j)\in \mathrm{In}(h_j):
\neg\exists u\in D_{h_i}\;((u,t)\in R_e)
\;\Rightarrow\; t \text{ is pruned from } D_{h_j}.
$$

This repeats to fixpoint (queue-based). If some $D_h=\varnothing$, the context is unsatisfiable.

#### Cyclic SCC exact step

For SCCs with cycles, local AC may be insufficient. For each cyclic SCC $C$, we compute exact supported tokens by searching assignments
$$
\alpha: C \to \bigcup_{h\in C} D_h
$$
that satisfy all pairwise arc constraints in $C$; unsupported tokens are pruned. This prevents false support in cyclic joins.

#### Witness-to-target support

Given witness predicate rows $S_W$ (rows satisfying local witness-side filters), we seed hub supports and propagate along arcs/SCC order. This yields per-target-hub support sets
$$
\mathrm{Supp}_h \subseteq D_h.
$$
A target row $r$ satisfies the witness atom iff at least one target-incidence hub token of $r$ is in its propagated support:
$$
\exists h\in H_T:\; \tau_h(r) \in \mathrm{Supp}_h.
$$
These truth values become bits in $\mathrm{sig}_T(r)$.

Witness-support propagation algorithm:

```text
Input:
  Witness rows S_W for table W, context domains {D_h}
Output:
  Support sets {Supp_h} on target-connected hubs

Initialize Supp_h <- empty for all hubs
For each hub incident to W:
  seed tokens from S_W into Supp_h, intersect with D_h

Process SCCs in topological order:
  if SCC is cyclic:
    refine supports with exact SCC compatibility
  propagate supports along outgoing arcs using image(R_e, Supp_u)
  intersect propagated tokens with destination domains D_v

Project supports to target incidences to evaluate witness atoms on target rows
```

### 1.10.2 SAT on signatures

Let policy AST for target $T$ be Boolean formula $\Phi_T$ over atom variables $Y=\{y_1,\dots,y_k\}$.
For each observed signature $s=\langle s_1,\dots,s_k\rangle \in \Sigma_T$, define assignment
$$
\alpha_s(y_i)=s_i.
$$
A signature is allowed iff
$$
\Phi_T \land \bigwedge_{i=1}^k (y_i = \alpha_s(y_i))
$$
is SAT.

Then allowed rows are:
$$
\mathrm{Allow}(T) = \bigcup_{s\in\Sigma_T,\;\mathrm{SAT}(s)=1} B_s.
$$

SAT/bin evaluation algorithm:

```text
Input:
  Policy formula Phi_T over atoms Y
  Distinct signatures Sigma_T and bins {B_s}
Output:
  Allow(T)

Allow(T) <- empty
for each signature s in Sigma_T:
  build assignment alpha_s(y_i) = s_i
  if SAT(Phi_T AND assignment(alpha_s)):
    Allow(T) <- Allow(T) union B_s
return Allow(T)
```

### 1.10.3 SAT example using $P_O$

Using
$$
\Phi_O=(y_G \vee y_F) \wedge y_{\neq},
$$
consider three signatures:
- $s_1=(1,0,1)$: SAT (Germany branch true, inequality true) $\Rightarrow$ bin allowed.
- $s_2=(0,0,1)$: UNSAT (no country branch true) $\Rightarrow$ bin denied.
- $s_3=(1,0,0)$: UNSAT (country true but inequality false) $\Rightarrow$ bin denied.

So only bins with SAT signatures contribute rows to $\mathrm{Allow}(\mathrm{orders})$.

### 1.10.4 End-to-end algorithm

1. Extract feature atoms and policy AST for target $T$.
2. Build hub graph (domains + arc adjacencies).
3. Run context propagation (AC + exact SCC on cycles).
4. Derive witness supports and evaluate feature bits for target rows.
5. Build row signatures and bins $B_s$.
6. Run SAT once per distinct signature assignment.
7. Materialize allow set as union of SAT bins.

This is equivalent to row-wise policy semantics, but cost is dominated by number of distinct signatures and propagated token supports, not by per-row existential join evaluation.
