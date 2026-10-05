"""Replay telemetry through all rules, then correlate alerts per host into incidents (kill-chain view)."""
from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timedelta
from .evaluator import matches
from .loader import techniques, tactics

W = {"informational": 1, "low": 2, "medium": 5, "high": 10, "critical": 20}
KILL_CHAIN = ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
              "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
              "exfiltration", "impact"]


def _applies(rule, ev):
    prod = rule["logsource"].get("product")
    return not (ev.get("product") and prod and ev["product"].lower() != prod.lower())


def replay(rules, events):
    alerts = []
    for ev in events:
        for r in rules:
            if _applies(r, ev) and matches(r, ev):
                alerts.append({"time": ev["timestamp"], "host": ev.get("Computer", "?"), "user": ev.get("User", "?"),
                               "rule": r["title"], "level": r["level"], "techniques": techniques(r),
                               "tactics": tactics(r), "cmd": ev.get("CommandLine", "")})
    return alerts


def correlate(alerts, window_min=60, min_tactics=3):
    by_host = defaultdict(list)
    for a in alerts:
        by_host[a["host"]].append(a)
    incidents = []
    for host, al in by_host.items():
        al.sort(key=lambda a: a["time"])
        cur = [al[0]]
        for a in al[1:]:
            gap = datetime.fromisoformat(a["time"]) - datetime.fromisoformat(cur[-1]["time"])
            if gap <= timedelta(minutes=window_min):
                cur.append(a)
            else:
                incidents.append((host, cur)); cur = [a]
        incidents.append((host, cur))
    out = []
    for host, al in incidents:
        tacs = {t for a in al for t in a["tactics"]}
        score = sum(W[a["level"]] for a in al)
        out.append({"host": host, "alerts": al, "tactics": sorted(tacs, key=KILL_CHAIN.index) if tacs <= set(KILL_CHAIN) else sorted(tacs),
                    "score": score, "multi_stage": len(tacs) >= min_tactics})
    return sorted(out, key=lambda i: -i["score"])


def render(incidents) -> str:
    L = []
    for n, inc in enumerate(incidents, 1):
        tag = "MULTI-STAGE INTRUSION" if inc["multi_stage"] else "isolated alert(s)"
        L.append(f"\n=== INCIDENT {n}: host {inc['host']} | risk score {inc['score']} | {tag} ===")
        L.append("kill chain: " + " -> ".join(inc["tactics"]))
        for a in inc["alerts"]:
            L.append(f"  {a['time'][11:19]}  [{a['level'].upper():8}] {a['rule']}  ({', '.join(a['techniques'])})")
            L.append(f"            user={a['user']}  cmd={a['cmd'][:90]}")
        if inc["multi_stage"]:
            L.append("  >> RECOMMENDED: isolate host, reset user creds, preserve memory image, start IR runbook (NIS2 Art.23 / DORA Art.19 reporting clock).")
    return "\n".join(L)
