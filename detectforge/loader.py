"""Load and lint Sigma rules (quality gates that mimic a real detection-engineering review)."""
from __future__ import annotations
import re, uuid
from pathlib import Path
import yaml

LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED = ["title", "id", "status", "description", "logsource", "detection", "level", "tags", "falsepositives"]
TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def load_rules(rules_dir: str | Path) -> list[dict]:
    rules = []
    for p in sorted(Path(rules_dir).rglob("*.yml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        d["_path"] = str(p)
        d["_stem"] = p.stem
        rules.append(d)
    return rules


def techniques(rule: dict) -> list[str]:
    return [m.group(1).upper() for t in rule.get("tags", []) if (m := TECH_RE.match(t))]


def tactics(rule: dict) -> list[str]:
    return [t[7:] for t in rule.get("tags", []) if t.startswith("attack.") and not TECH_RE.match(t)]


def lint(rule: dict, tests_dir: str | Path = "tests/data") -> list[str]:
    """Return a list of problems; empty list == rule passes the quality gate."""
    errs = []
    for f in REQUIRED:
        if f not in rule:
            errs.append(f"missing field '{f}'")
    try:
        uuid.UUID(str(rule.get("id", "")))
    except ValueError:
        errs.append("id is not a valid UUID")
    if rule.get("level") not in LEVELS:
        errs.append(f"level must be one of {sorted(LEVELS)}")
    if not techniques(rule):
        errs.append("no ATT&CK technique tag (attack.tNNNN)")
    if not tactics(rule):
        errs.append("no ATT&CK tactic tag (attack.<tactic>)")
    if "condition" not in rule.get("detection", {}):
        errs.append("detection has no condition")
    if not rule.get("falsepositives"):
        errs.append("falsepositives must be documented (analysts need tuning guidance)")
    if not (Path(tests_dir) / f"{rule['_stem']}.json").exists():
        errs.append(f"no unit-test file tests/data/{rule['_stem']}.json")
    return errs
