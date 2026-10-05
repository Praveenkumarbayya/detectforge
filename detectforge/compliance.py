"""Map detections to NIS2 / DORA / ISO 27001:2022 so GRC + SOC speak the same language."""
from __future__ import annotations
from pathlib import Path
import yaml
from .loader import tactics

def controls_for(rule, mapping_file="mappings/compliance.yml") -> dict:
    m = yaml.safe_load(Path(mapping_file).read_text())
    res = {k: list(v) for k, v in m["common"].items()}
    for t in tactics(rule):
        for fw, items in m["by_tactic"].get(t, {}).items():
            res.setdefault(fw, [])
            res[fw] += [i for i in items if i not in res[fw]]
    return res

def markdown(rules) -> str:
    out = ["# Detection-to-Control Traceability Matrix", "",
           "_Indicative mapping (portfolio/education use, not legal advice)._", "",
           "| Detection | NIS2 | DORA | ISO 27001:2022 |", "|---|---|---|---|"]
    for r in rules:
        c = controls_for(r)
        out.append(f"| {r['title']} | {'; '.join(c['nis2'])} | {'; '.join(c['dora'])} | {'; '.join(c['iso27001_2022'])} |")
    return "\n".join(out) + "\n"
