#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple


Token = Tuple[str, str]
PostfixTok = Tuple[str, str]
ConjTerm = Tuple[str, ...]


def _tokenize(expr: str) -> List[Token]:
    s = expr.strip()
    out: List[Token] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            out.append((c, c))
            i += 1
            continue
        if c.isalpha() or c == "_":
            j = i + 1
            while j < len(s) and (s[j].isalnum() or s[j] == "_"):
                j += 1
            w = s[i:j]
            wl = w.lower()
            if wl in ("and", "or", "true", "false"):
                out.append((wl.upper(), wl))
            else:
                out.append(("VAR", w))
            i = j
            continue
        raise ValueError(f"unexpected char at {i}: {c!r}")
    return out


@dataclass
class _Parser:
    toks: Sequence[Token]
    i: int = 0

    def _peek(self) -> Token | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _eat(self, k: str) -> bool:
        t = self._peek()
        if t is None or t[0] != k:
            return False
        self.i += 1
        return True

    def parse(self) -> List[PostfixTok]:
        out = self._parse_or()
        if self._peek() is not None:
            raise ValueError("trailing tokens")
        return out

    def _parse_or(self) -> List[PostfixTok]:
        out = self._parse_and()
        while self._eat("OR"):
            rhs = self._parse_and()
            out.extend(rhs)
            out.append(("OR", ""))
        return out

    def _parse_and(self) -> List[PostfixTok]:
        out = self._parse_primary()
        while self._eat("AND"):
            rhs = self._parse_primary()
            out.extend(rhs)
            out.append(("AND", ""))
        return out

    def _parse_primary(self) -> List[PostfixTok]:
        if self._eat("("):
            out = self._parse_or()
            if not self._eat(")"):
                raise ValueError("missing )")
            return out
        t = self._peek()
        if t is None:
            raise ValueError("unexpected end")
        if t[0] == "TRUE":
            self.i += 1
            return [("TRUE", "")]
        if t[0] == "FALSE":
            self.i += 1
            return [("FALSE", "")]
        if t[0] == "VAR":
            self.i += 1
            return [("VAR", t[1])]
        raise ValueError(f"unexpected token: {t}")


def parse_postfix(expr: str) -> List[PostfixTok]:
    return _Parser(_tokenize(expr)).parse()


def _norm_term(xs: Sequence[str]) -> ConjTerm:
    vals = sorted({x for x in xs if x})
    return tuple(vals)


def _dedup_terms(terms: Sequence[ConjTerm]) -> List[ConjTerm]:
    uniq = sorted(set(terms), key=lambda t: (len(t), t))
    return uniq


def _is_subset(a: ConjTerm, b: ConjTerm) -> bool:
    sa = set(a)
    sb = set(b)
    return sa.issubset(sb)


def prune_subsumed(terms: Sequence[ConjTerm]) -> List[ConjTerm]:
    ordered = _dedup_terms(terms)
    kept: List[ConjTerm] = []
    for t in ordered:
        if any(_is_subset(k, t) for k in kept):
            continue
        kept.append(t)
    return kept


def enumerate_exact_terms(postfix: Sequence[PostfixTok]) -> List[ConjTerm]:
    st: List[List[ConjTerm]] = []
    for k, v in postfix:
        if k == "TRUE":
            st.append([tuple()])
            continue
        if k == "FALSE":
            st.append([])
            continue
        if k == "VAR":
            st.append([_norm_term([v])])
            continue
        if k not in ("AND", "OR"):
            raise ValueError(f"bad postfix token kind: {k}")
        if len(st) < 2:
            raise ValueError("stack underflow")
        r = st.pop()
        l = st.pop()
        if k == "OR":
            st.append(_dedup_terms(l + r))
        else:
            out: List[ConjTerm] = []
            for a in l:
                for b in r:
                    out.append(_norm_term(list(a) + list(b)))
            st.append(_dedup_terms(out))
    if len(st) != 1:
        raise ValueError("final stack size != 1")
    return _dedup_terms(st[0])


def eval_postfix_bool(postfix: Sequence[PostfixTok], values: Dict[str, bool]) -> bool:
    st: List[bool] = []
    for k, v in postfix:
        if k == "TRUE":
            st.append(True)
        elif k == "FALSE":
            st.append(False)
        elif k == "VAR":
            st.append(bool(values.get(v, False)))
        else:
            b = st.pop()
            a = st.pop()
            st.append((a and b) if k == "AND" else (a or b))
    if len(st) != 1:
        raise ValueError("bad eval stack")
    return st[0]


def eval_terms_bool(terms: Sequence[ConjTerm], values: Dict[str, bool]) -> bool:
    for t in terms:
        if all(values.get(v, False) for v in t):
            return True
    return False


def _expect_terms(expr: str, expected: Sequence[Sequence[str]]) -> None:
    postfix = parse_postfix(expr)
    got = prune_subsumed(enumerate_exact_terms(postfix))
    exp = prune_subsumed([_norm_term(x) for x in expected])
    if got != exp:
        raise AssertionError(f"{expr}: expected {exp}, got {got}")
    print(f"[ok] terms {expr} -> {got}")


def _check_mask_semantics(expr: str, vars_: Sequence[str]) -> None:
    postfix = parse_postfix(expr)
    terms = prune_subsumed(enumerate_exact_terms(postfix))
    n = 1 << len(vars_)
    for m in range(n):
        vals = {vars_[i]: bool((m >> i) & 1) for i in range(len(vars_))}
        a = eval_postfix_bool(postfix, vals)
        b = eval_terms_bool(terms, vals)
        if a != b:
            raise AssertionError(f"mask semantics mismatch expr={expr} vals={vals} ast={a} terms={b}")
    print(f"[ok] mask {expr} ({n} assignments)")


def main() -> None:
    _expect_terms("A", [["A"]])
    _expect_terms("A OR B", [["A"], ["B"]])
    _expect_terms("A AND B", [["A", "B"]])
    _expect_terms("(A OR B) AND (C OR D)", [["A", "C"], ["A", "D"], ["B", "C"], ["B", "D"]])
    _expect_terms("(A AND B) OR (A AND C)", [["A", "B"], ["A", "C"]])
    _expect_terms("A OR (A AND B)", [["A"]])

    _check_mask_semantics("(A OR B) AND (C OR D)", ["A", "B", "C", "D"])
    _check_mask_semantics("A OR (A AND B)", ["A", "B"])
    print("exact_term_enumerator_unit: PASS")


if __name__ == "__main__":
    main()
