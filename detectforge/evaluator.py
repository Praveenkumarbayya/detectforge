"""A small, dependency-free evaluator for the Sigma detection subset used in this repo.

Why write one? It lets CI *prove* each rule fires on attack telemetry and stays quiet on benign
telemetry, without needing a live SIEM. Supported: field modifiers (contains, startswith, endswith,
all, re), wildcards, lists (OR), null, keyword lists, and conditions with and/or/not, parentheses,
'1 of sel*', 'all of sel*', '1 of them', 'all of them'.  Aggregations (count/near) are not supported
and raise NotImplementedError rather than silently passing.
"""
from __future__ import annotations
import re

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _norm(v):
    return "" if v is None else str(v).lower()


def _glob_to_re(p: str) -> str:
    out = []
    for ch in p:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "^" + "".join(out) + "$"


def _match_one(event_val, pattern, mods: list[str]) -> bool:
    if pattern is None:
        return event_val is None or event_val == ""
    if event_val is None:
        return False
    if "re" in mods:
        return re.search(str(pattern), str(event_val), re.I) is not None
    ev, pt = _norm(event_val), _norm(pattern)
    if "contains" in mods:
        return pt in ev
    if "startswith" in mods:
        return ev.startswith(pt)
    if "endswith" in mods:
        return ev.endswith(pt)
    if isinstance(pattern, str) and ("*" in pattern or "?" in pattern):
        return re.match(_glob_to_re(pt), ev, re.S) is not None
    return ev == pt


def _get(event: dict, field: str):
    if field in event:
        return event[field]
    lf = field.lower()
    for k, v in event.items():
        if k.lower() == lf:
            return v
    return None


def _eval_map(event: dict, sel: dict) -> bool:
    for key, expected in sel.items():
        field, *mods = key.split("|")
        vals = expected if isinstance(expected, list) else [expected]
        ev = _get(event, field)
        hits = [_match_one(ev, v, mods) for v in vals]
        if not (all(hits) if "all" in mods else any(hits)):
            return False
    return True


def _eval_selection(event: dict, sel) -> bool:
    if isinstance(sel, dict):
        return _eval_map(event, sel)
    if isinstance(sel, list):  # list of maps (OR) or keywords (search all values)
        blob = " ".join(_norm(v) for v in event.values())
        return any(_eval_map(event, s) if isinstance(s, dict) else _norm(s) in blob for s in sel)
    raise ValueError(f"unsupported selection: {sel!r}")


class _Cond:
    def __init__(self, text: str, results: dict[str, bool]):
        if re.search(r"\|\s*(count|near|min|max|avg|sum)|\bnear\b", text):
            raise NotImplementedError("aggregation conditions are not supported by the offline evaluator")
        self.t, self.i, self.r = _TOKEN.findall(text), 0, results

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def nxt(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def or_(self):
        v = self.and_()
        while (self.peek() or "").lower() == "or":
            self.nxt()
            v = self.and_() or v
        return v

    def and_(self):
        v = self.not_()
        while (self.peek() or "").lower() == "and":
            self.nxt()
            v = self.not_() and v
        return v

    def not_(self):
        if (self.peek() or "").lower() == "not":
            self.nxt()
            return not self.not_()
        return self.atom()

    def atom(self):
        tok = self.nxt()
        if tok == "(":
            v = self.or_()
            self.nxt()  # ')'
            return v
        if (self.peek() or "").lower() == "of" and (tok.lower() == "all" or tok.isdigit()):
            self.nxt()
            pat = self.nxt()
            names = list(self.r) if pat == "them" else [n for n in self.r if re.match(_glob_to_re(pat.lower()), n.lower())]
            vals = [self.r[n] for n in names]
            return bool(vals) and (all(vals) if tok.lower() == "all" else sum(vals) >= int(tok))
        return self.r[tok]


def matches(rule: dict, event: dict) -> bool:
    det = rule["detection"]
    results = {k: _eval_selection(event, v) for k, v in det.items() if k != "condition"}
    cond = det["condition"]
    if isinstance(cond, list):
        return any(_Cond(c, results).or_() for c in cond)
    return _Cond(cond, results).or_()
