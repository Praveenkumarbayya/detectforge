"""Turn a Splunk/Sentinel JSON export of real Sysmon events into DetectForge test samples.

Usage:  python -m detectforge import-events export.json --rule proc_ps_encoded_command --kind should_match
It keeps only the fields the rules use, and pseudonymises hostnames and usernames so the sample is safe to publish.
"""
from __future__ import annotations
import json, re
from pathlib import Path

KEEP = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "Computer", "OriginalFileName"]

# Shared profile folders are not personal data, and rules key on them (e.g. C:\Users\Public is a classic
# staging path), so they must survive pseudonymisation unchanged.
_SHARED_PROFILES = r"(?:Public|Default|Default User|All Users)"
_USER_DIR = re.compile(rf"C:\\Users\\(?!{_SHARED_PROFILES}(?:\\|\b))[^\\\s\"']+", re.I)


def _scrub_profile(s: str) -> str:
    return _USER_DIR.sub(r"C:\\Users\\user", s)


def read_events(path: str | Path) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    try:
        data = json.loads(text)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:  # JSON-lines export
        rows = [json.loads(l) for l in text.splitlines() if l.strip()]
    events = []
    for r in rows:
        r = r.get("result", r) if isinstance(r, dict) else r
        if isinstance(r, dict):
            events.append(r)
    return events


def sanitise(events: list[dict], extra_users: list[str] | None = None) -> list[dict]:
    hosts: dict[str, str] = {}
    out = []
    for e in events:
        n = {k: e[k] for k in KEEP if k in e and e[k] not in (None, "")}
        if "Computer" in n:
            n["Computer"] = hosts.setdefault(n["Computer"], f"WS-{len(hosts)+1:03d}")
        if "User" in n:
            n["User"] = "LAB\\user"
        for k in ("CommandLine", "ParentCommandLine"):
            if k in n:
                for u in extra_users or []:
                    n[k] = re.sub(re.escape(u), "user", n[k], flags=re.I)
                n[k] = _scrub_profile(n[k])
        for k in ("Image", "ParentImage"):
            if k in n:
                n[k] = _scrub_profile(n[k])
        out.append(n)
    return out


def add_to_tests(rule_stem: str, events: list[dict], kind: str, tests_dir: str | Path = "tests/data") -> Path:
    assert kind in ("should_match", "should_not_match")
    p = Path(tests_dir) / f"{rule_stem}.json"
    spec = json.loads(p.read_text()) if p.exists() else {"should_match": [], "should_not_match": []}
    spec[kind] += [e for e in events if e not in spec[kind]]
    p.write_text(json.dumps(spec, indent=2))
    return p
