#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import fast_sweep_profile_60s as h

h.CUSTOM_FILTER_SO = str(REPO_ROOT / "custom_filter" / "custom_filter.so")
h.ARTIFACT_BUILDER_SO = str(REPO_ROOT / "artifact_builder" / "artifact_builder.so")

POLICY_FILE = REPO_ROOT / "policy.txt"
QUERY_FILE = REPO_ROOT / "queries.txt"
LOG_CSV = REPO_ROOT / "logs" / "stage9_correctness.csv"
LOG_MD = REPO_ROOT / "logs" / "stage9_correctness.md"
LINT_MD = REPO_ROOT / "logs" / "policy_lint.md"

DEFAULT_DB = os.getenv("STAGE9_DB", "tpch1")
STATEMENT_TIMEOUT_MS = 0
STRICT_GUC = "custom_filter.strict_mode"


@dataclass(frozen=True)
class Stage9Case:
    name: str
    category: str
    policy_ids: Tuple[int, ...]
    query_id: str


CASES: Tuple[Stage9Case, ...] = (
    Stage9Case("same_table_colcol_21_q1", "same_table_ordered_colcol", (21,), "1"),
    Stage9Case("same_table_colcol_22_q1", "same_table_ordered_colcol", (22,), "1"),
    Stage9Case("same_table_colcol_23_q6", "same_table_ordered_colcol", (23,), "6"),
    Stage9Case("cross_table_numeric_colcol_26_q3", "cross_table_numeric_colcol", (26,), "3"),
    Stage9Case("cross_table_numeric_colcol_27_q6", "cross_table_numeric_colcol", (27,), "6"),
    Stage9Case("cross_table_numeric_colcol_28_q11", "cross_table_numeric_colcol", (28,), "11"),
    Stage9Case("cross_table_numeric_colcol_29_q9", "cross_table_numeric_colcol", (29,), "9"),
    Stage9Case("cross_table_numeric_colcol_30_q5", "cross_table_numeric_colcol", (30,), "5"),
)

TYPECLASS_NUMERIC = "NUMERIC"
TYPECLASS_DATE = "DATE"
TYPECLASS_TEXT = "TEXT"
TYPECLASS_UNSUPPORTED = "UNSUPPORTED"


def type_class_from_typname(typname: str) -> str:
    t = (typname or "").lower()
    if t in {"int2", "int4", "int8", "numeric"}:
        return TYPECLASS_NUMERIC
    if t == "date":
        return TYPECLASS_DATE
    if t in {"text", "varchar", "bpchar"}:
        return TYPECLASS_TEXT
    return TYPECLASS_UNSUPPORTED


def normalize_colref(target: str, ref: str) -> str:
    s = ref.strip().lower()
    if "." in s:
        return s
    return f"{target.lower()}.{s}"


def parse_colcol_atoms(target: str, expr: str) -> List[Tuple[str, str, str]]:
    # Capture column-column atoms only. Constants are filtered out by rhs shape.
    pat = re.compile(
        r"([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s*(<=|>=|!=|=|<|>)\s*([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)",
        flags=re.IGNORECASE,
    )
    atoms: List[Tuple[str, str, str]] = []
    for m in pat.finditer(expr):
        lhs_raw, op, rhs_raw = m.group(1), m.group(2), m.group(3)
        lhs = normalize_colref(target, lhs_raw)
        rhs = normalize_colref(target, rhs_raw)
        atoms.append((lhs, op, rhs))
    return atoms


def collect_all_cols_and_atoms(policy_lines: Sequence[str]) -> Tuple[List[str], Dict[int, List[Tuple[str, str, str]]], Dict[int, str]]:
    colset = set()
    per_policy_atoms: Dict[int, List[Tuple[str, str, str]]] = {}
    per_policy_target: Dict[int, str] = {}
    for line in policy_lines:
        pid, target, expr = h.parse_policy_entry_with_id(line)
        if pid is None:
            continue
        atoms = parse_colcol_atoms(target, expr)
        per_policy_atoms[pid] = atoms
        per_policy_target[pid] = target
        for lhs, _, rhs in atoms:
            colset.add(lhs)
            colset.add(rhs)
    cols = sorted(colset)
    return cols, per_policy_atoms, per_policy_target


def fetch_typnames(db: str, cols: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not cols:
        return out
    conn = h.connect(db, "postgres")
    try:
        with conn.cursor() as cur:
            for cref in cols:
                tbl, col = cref.split(".", 1)
                cur.execute(
                    "SELECT t.typname "
                    "FROM pg_attribute a "
                    "JOIN pg_class c ON c.oid=a.attrelid "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "JOIN pg_type t ON t.oid=a.atttypid "
                    "WHERE n.nspname='public' AND c.relname=%s AND a.attname=%s AND a.attnum>0 AND NOT a.attisdropped",
                    [tbl, col],
                )
                row = cur.fetchone()
                out[cref] = row[0] if row else ""
    finally:
        conn.close()
    return out


def union_find_domains(cols: Sequence[str], edges: Sequence[Tuple[str, str]]) -> Dict[str, int]:
    idx = {c: i for i, c in enumerate(cols)}
    parent = list(range(len(cols)))
    rank = [0] * len(cols)

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        if rank[ra] == rank[rb]:
            rank[ra] += 1

    for l, r in edges:
        if l in idx and r in idx:
            union(idx[l], idx[r])

    comps: Dict[int, List[str]] = {}
    for c in cols:
        r = find(idx[c])
        comps.setdefault(r, []).append(c)

    # Deterministic ids by canonical smallest colref.
    comp_keys: List[Tuple[str, int]] = []
    for root, members in comps.items():
        members.sort()
        comp_keys.append((members[0], root))
    comp_keys.sort()
    root_to_did = {root: did for did, (_, root) in enumerate(comp_keys)}

    out: Dict[str, int] = {}
    for c in cols:
        out[c] = root_to_did[find(idx[c])]
    return out


def write_policy_lint(db: str, policy_lines: Sequence[str]) -> None:
    cols, per_policy_atoms, per_policy_target = collect_all_cols_and_atoms(policy_lines)
    typnames = fetch_typnames(db, cols)
    tclass = {c: type_class_from_typname(typnames.get(c, "")) for c in cols}

    # Stage8-like domains (equality-only edges).
    old_edges: List[Tuple[str, str]] = []
    # Stage9 domains (all col-col operators, with type-class compatibility).
    new_edges: List[Tuple[str, str]] = []

    incompatible_policies: Dict[int, str] = {}
    for pid, atoms in per_policy_atoms.items():
        for lhs, op, rhs in atoms:
            if op == "=":
                old_edges.append((lhs, rhs))
            ltc = tclass.get(lhs, TYPECLASS_UNSUPPORTED)
            rtc = tclass.get(rhs, TYPECLASS_UNSUPPORTED)
            if ltc == TYPECLASS_UNSUPPORTED or rtc == TYPECLASS_UNSUPPORTED or ltc != rtc:
                if pid not in incompatible_policies:
                    incompatible_policies[pid] = f"type-class mismatch/unsupported: {lhs}({ltc}) {op} {rhs}({rtc})"
                continue
            new_edges.append((lhs, rhs))

    old_dom = union_find_domains(cols, old_edges) if cols else {}
    new_dom = union_find_domains(cols, new_edges) if cols else {}

    lines: List[str] = []
    lines.append("# Policy Lint (Stage 9)")
    lines.append("")
    lines.append(f"- database: `{db}`")
    lines.append(f"- policy_file: `{POLICY_FILE}`")
    lines.append(f"- strict_mode_ops: `{{=,!=,<,<=,>,>=}}`")
    lines.append("")
    lines.append("| policy_id | target | status | atoms (col-col with domains) | note |")
    lines.append("|---:|---|---|---|---|")

    for line in policy_lines:
        pid, target, expr = h.parse_policy_entry_with_id(line)
        if pid is None:
            continue
        atoms = per_policy_atoms.get(pid, [])

        note = ""
        if pid in incompatible_policies:
            status = "rejected"
            note = incompatible_policies[pid]
        elif not atoms:
            status = "supported_now"
        else:
            old_ok = True
            new_ok = True
            atom_parts: List[str] = []
            for lhs, op, rhs in atoms:
                od_l = old_dom.get(lhs, -1)
                od_r = old_dom.get(rhs, -1)
                nd_l = new_dom.get(lhs, -1)
                nd_r = new_dom.get(rhs, -1)
                atom_parts.append(
                    f"`{lhs}` {op} `{rhs}` old=({od_l},{od_r}) new=({nd_l},{nd_r})"
                )
                if od_l < 0 or od_r < 0 or od_l != od_r:
                    old_ok = False
                if nd_l < 0 or nd_r < 0 or nd_l != nd_r:
                    new_ok = False
            if old_ok:
                status = "supported_now"
            elif new_ok:
                status = "supported_after_stage9"
            else:
                status = "rejected"
                if not note:
                    note = "domain mismatch after stage9 graph build"

            atoms_text = "<br>".join(atom_parts)
            lines.append(f"| {pid} | `{target}` | {status} | {atoms_text} | {note} |")
            continue

        lines.append(f"| {pid} | `{target}` | {status} |  | {note} |")

    LINT_MD.parent.mkdir(parents=True, exist_ok=True)
    LINT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def resolve_enabled_lines(base_policy_lines: List[str], ids: Sequence[int]) -> List[str]:
    ids_set = set(ids)
    out = [line for i, line in enumerate(base_policy_lines, start=1) if i in ids_set]
    if len(out) != len(ids):
        raise RuntimeError(f"failed resolving policy ids {ids}")
    return out


def set_strict_mode(cur) -> None:
    cur.execute("SET custom_filter.strict_mode = 'on';")


def setup_ours(db: str, enabled_path: Path, k: int) -> None:
    h.setup_ours_for_k(db, max(1, int(k)), enabled_path, STATEMENT_TIMEOUT_MS)


def run_count_hash(db: str, baseline: str, query_id: str, query_sql: str, enabled_path: Path) -> Tuple[int, str]:
    role = h.role_for_baseline(baseline)
    conn = h.connect(db, role)
    try:
        with conn.cursor() as cur:
            h.set_session_for_baseline(cur, baseline, enabled_path, STATEMENT_TIMEOUT_MS, ours_debug_mode="off")
            cur.execute("SET max_parallel_workers_per_gather = 0;")
            if baseline in ("ours", "ours_with_index"):
                set_strict_mode(cur)
            return h.result_count_and_hash_in_session(cur, query_id, query_sql)
    finally:
        conn.close()


def run_case(db: str, case: Stage9Case, base_policy_lines: List[str], qmap: Dict[str, str]) -> Dict[str, str]:
    enabled_lines = resolve_enabled_lines(base_policy_lines, case.policy_ids)
    enabled_path = REPO_ROOT / "logs" / f"stage9_enabled_{case.name}.txt"
    enabled_path.write_text("\n".join(enabled_lines) + "\n", encoding="utf-8")

    setup_ours(db, enabled_path, len(enabled_lines))

    ours_rows, ours_hash = run_count_hash(db, "ours", case.query_id, qmap[case.query_id], enabled_path)

    h.clear_rls_indexes_and_policies(db)
    h.apply_rls_policies_for_k(db, enabled_lines)
    h.create_rls_indexes_for_k(db, len(enabled_lines), enabled_lines, STATEMENT_TIMEOUT_MS)
    gt_rows, gt_hash = run_count_hash(db, "rls_with_index", case.query_id, qmap[case.query_id], enabled_path)
    h.clear_rls_indexes_and_policies(db)

    ok = (int(ours_rows) == int(gt_rows) and str(ours_hash or "") == str(gt_hash or ""))

    return {
        "dataset": db,
        "case": case.name,
        "category": case.category,
        "policy_ids": ",".join(str(x) for x in case.policy_ids),
        "query_id": case.query_id,
        "ours_rows": str(ours_rows),
        "ours_hash": str(ours_hash or ""),
        "gt_rows": str(gt_rows),
        "gt_hash": str(gt_hash or ""),
        "status": "PASS" if ok else "FAIL",
        "mismatch_note": "" if ok else "rows/hash mismatch",
    }


def write_md(rows: List[Dict[str, str]]) -> None:
    total = len(rows)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    failed = [r for r in rows if r["status"] != "PASS"]

    lines: List[str] = []
    lines.append("# Stage 9 Correctness Summary")
    lines.append("")
    lines.append(f"- total_cases: {total}")
    lines.append(f"- passed: {passed}")
    lines.append(f"- failed: {len(failed)}")
    lines.append(f"- csv: `{LOG_CSV}`")
    lines.append("")
    lines.append("## Cases")
    for r in rows:
        lines.append(
            f"- {r['case']}: status={r['status']} dataset={r['dataset']} q{r['query_id']} "
            f"policy_ids={r['policy_ids']} ours=({r['ours_rows']},{r['ours_hash']}) "
            f"gt=({r['gt_rows']},{r['gt_hash']})"
        )

    if failed:
        lines.append("")
        lines.append("## FAIL")
        for r in failed:
            lines.append(
                f"- case={r['case']} q{r['query_id']} ours=({r['ours_rows']},{r['ours_hash']}) "
                f"gt=({r['gt_rows']},{r['gt_hash']}) note={r['mismatch_note']}"
            )

    LOG_MD.parent.mkdir(parents=True, exist_ok=True)
    LOG_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    db = DEFAULT_DB
    policy_lines = h.load_policy_lines(POLICY_FILE)
    qmap = {qid: qsql for qid, qsql in h.load_queries(QUERY_FILE)}

    write_policy_lint(db, policy_lines)

    rows: List[Dict[str, str]] = []
    for case in CASES:
        if case.query_id not in qmap:
            raise RuntimeError(f"missing query_id={case.query_id}")
        print(f"[stage9] running {case.name} on {db} q{case.query_id} policies={case.policy_ids}", flush=True)
        row = run_case(db, case, policy_lines, qmap)
        rows.append(row)

    LOG_CSV.parent.mkdir(parents=True, exist_ok=True)
    with LOG_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "dataset",
                "case",
                "category",
                "policy_ids",
                "query_id",
                "ours_rows",
                "ours_hash",
                "gt_rows",
                "gt_hash",
                "status",
                "mismatch_note",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    write_md(rows)
    print(f"[stage9] wrote {LOG_CSV}")
    print(f"[stage9] wrote {LOG_MD}")
    print(f"[stage9] wrote {LINT_MD}")


if __name__ == "__main__":
    main()
