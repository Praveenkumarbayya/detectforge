"""Native (SIEM-specific) detections for logic Sigma single-event rules can't express, e.g. aggregations.

They live in detections_native/<siem>/*.yml with the same metadata as Sigma rules (id, title, level, tags,
falsepositives), so ATT&CK coverage and compliance traceability treat them like any other detection. They are
not run by the offline evaluator. They are validated live in the lab instead.
"""
from __future__ import annotations
import re
import uuid
from pathlib import Path
import yaml
from .loader import techniques

REQUIRED = ["title", "id", "kind", "description", "level", "tags", "falsepositives", "search", "schedule"]
_SEV = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def load_native(native_dir: str | Path = "detections_native") -> list[dict]:
    out = []
    if not Path(native_dir).exists():
        return out
    for p in sorted(Path(native_dir).rglob("*.yml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        d["_path"], d["_stem"] = str(p), p.stem
        out.append(d)
    return out


def render_search(det: dict) -> str:
    """The SPL with {threshold} placeholders filled in, as one line (conf values can't span lines)."""
    spl = det["search"].format(**det.get("thresholds", {}))
    return " ".join(spl.split())


def lint(det: dict) -> list[str]:
    errs = [f"missing field: {k}" for k in REQUIRED if not det.get(k)]
    if det.get("kind") != "splunk_native":
        errs.append("kind must be splunk_native")
    try:
        uuid.UUID(str(det.get("id")))
    except ValueError:
        errs.append("id is not a UUID")
    if not techniques(det):
        errs.append("no ATT&CK technique tag")
    if det.get("search"):
        try:
            s = render_search(det)
            if re.search(r"\{\w+\}", s):
                errs.append("unfilled threshold placeholder in search")
        except KeyError as e:
            errs.append(f"search uses undefined threshold {e}")
    return errs


def to_splunk_savedsearch(det: dict) -> str:
    sch = det["schedule"]
    desc = " ".join(det["description"].split())
    lines = [
        f"[DetectForge - {det['title']}]",
        f"description = {desc} (DetectForge native id {det['id']})",
        f"search = {render_search(det)}",
        "enableSched = 1",
        f"cron_schedule = {sch['cron']}",
        f"dispatch.earliest_time = {sch['earliest']}",
        f"dispatch.latest_time = {sch['latest']}",
        "counttype = number of events",
        "relation = greater than",
        "quantity = 0",
        "alert.track = 1",
        f"alert.severity = {_SEV[det['level']]}",
    ]
    if sch.get("suppress_fields"):  # one alert per (host, source); don't re-alert on overlapping windows
        lines += ["alert.digest_mode = 0", "alert.suppress = 1",
                  f"alert.suppress.fields = {sch['suppress_fields']}",
                  f"alert.suppress.period = {sch['suppress_period']}"]
    else:
        lines.append("alert.digest_mode = 1")
    return "\n".join(lines) + "\n"
