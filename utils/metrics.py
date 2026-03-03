from __future__ import annotations

import re
from typing import Iterable, List, Set


_TABLE_RE = re.compile(r"(?i)\b(?:from|join)\s+([a-z_][a-z0-9_]*)\b")
_SUBQUERY_RE = re.compile(r"(?i)\b(?:exists\s*\(|in\s*\(\s*select\b|\(\s*select\b)")
_WHERE_RE = re.compile(r"(?i)\bwhere\b")
_GROUP_RE = re.compile(r"(?i)\bgroup\s+by\b")
_ORDER_RE = re.compile(r"(?i)\border\s+by\b")
_HAVING_RE = re.compile(r"(?i)\bhaving\b")
_JOIN_COND_RE = re.compile(r"(?i)\bjoin\b.*?\bon\b")

# Leaf-atom-ish patterns (stable/deterministic, no DNF expansion).
_ATOM_RE = re.compile(
    r"(?ix)"
    r"("
    r"\b[a-z_][a-z0-9_.]*\s*(?:<=|>=|!=|=|<|>)\s*(?:'[^']*'|[a-z_][a-z0-9_.]*|[-+]?\d+(?:\.\d+)?)"
    r"|\b[a-z_][a-z0-9_.]*\s+between\s+[^\s]+\s+and\s+[^\s]+"
    r"|\b[a-z_][a-z0-9_.]*\s+like\s+'[^']*'"
    r"|\b[a-z_][a-z0-9_.]*\s+in\s*\("
    r"|\b[a-z_][a-z0-9_.]*\s+is\s+(?:not\s+)?null"
    r")"
)


def query_tables(query_sql: str) -> Set[str]:
    return {m.group(1).lower() for m in _TABLE_RE.finditer(query_sql)}


def query_complexity(query_sql: str) -> int:
    sql = query_sql or ""
    tables = len(query_tables(sql))
    joins = len(re.findall(r"(?i)\bjoin\b", sql))
    join_conds = len(_JOIN_COND_RE.findall(sql))

    where_predicates = 0
    if _WHERE_RE.search(sql):
        where_predicates = len(re.findall(r"(?i)\band\b|\bor\b", sql)) + 1

    subqueries = len(_SUBQUERY_RE.findall(sql))

    extra = 0
    if _GROUP_RE.search(sql):
        extra += 1
    if _ORDER_RE.search(sql):
        extra += 1
    if _HAVING_RE.search(sql):
        extra += 1

    return int(tables + joins + join_conds + where_predicates + subqueries + extra)


def _count_atoms(expr: str) -> int:
    if not expr:
        return 0
    return len(_ATOM_RE.findall(expr))


def policy_complexity(policy_lines: Iterable[str], query_sql: str, parse_policy_entry_with_id) -> int:
    q_tables = query_tables(query_sql)
    total = 0

    for line in policy_lines:
        pid, target, expr = parse_policy_entry_with_id(line)
        _ = pid  # deterministic scan only; parity irrelevant for complexity count.
        target = (target or "").lower()
        expr_l = (expr or "").lower()

        refs = {m.group(1).lower() for m in re.finditer(r"\b([a-z_][a-z0-9_]*)\.[a-z_][a-z0-9_]*\b", expr_l)}
        relevant = False
        if target in q_tables:
            relevant = True
        elif refs.intersection(q_tables):
            relevant = True

        if relevant:
            total += _count_atoms(expr)

    return int(total)


def policy_ids_csv(policy_ids: List[int]) -> str:
    return ",".join(str(x) for x in policy_ids)
