"""Compile Sigma rules into SIEM-native content: Splunk SPL, Microsoft Sentinel KQL + analytics-rule YAML."""
from __future__ import annotations
from pathlib import Path
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.kusto import KustoBackend
from .loader import techniques, tactics

def _sigma(rule):  # strip our private keys before handing to pySigma
    return SigmaCollection.from_dicts([{k: v for k, v in rule.items() if not k.startswith("_")}])

def to_splunk(rule) -> str:
    return SplunkBackend().convert(_sigma(rule))[0]

def to_kql(rule, table="SysmonProcessCreate") -> str:
    # `table` is a parser/function you create in Sentinel over Sysmon EID 1 or SecurityEvent 4688
    return f"{table}\n| where {KustoBackend().convert(_sigma(rule))[0]}"

_TACTIC = {"initial_access": "InitialAccess", "execution": "Execution", "persistence": "Persistence",
           "privilege_escalation": "PrivilegeEscalation", "defense_evasion": "DefenseEvasion",
           "credential_access": "CredentialAccess", "discovery": "Discovery", "lateral_movement": "LateralMovement",
           "collection": "Collection", "command_and_control": "CommandAndControl", "exfiltration": "Exfiltration",
           "impact": "Impact"}
class _Lit(str):
    pass
yaml.SafeDumper.add_representer(_Lit, lambda d, v: d.represent_scalar("tag:yaml.org,2002:str", v, style="|"))

_SEV = {"informational": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "High"}

def to_sentinel_yaml(rule, table="SysmonProcessCreate") -> str:
    doc = {"id": rule["id"], "name": rule["title"], "description": rule["description"],
           "severity": _SEV[rule["level"]], "status": "Available", "requiredDataConnectors": [],
           "queryFrequency": "PT15M", "queryPeriod": "PT15M", "triggerOperator": "GreaterThan", "triggerThreshold": 0,
           "tactics": [_TACTIC[t] for t in tactics(rule) if t in _TACTIC],
           "relevantTechniques": [t.split('.')[0] for t in techniques(rule)],
           "query": _Lit(to_kql(rule, table) + "\n"),
           "entityMappings": [{"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "Computer"}]},
                              {"entityType": "Process", "fieldMappings": [{"identifier": "CommandLine", "columnName": "CommandLine"}]}],
           "version": "1.0.0", "kind": "Scheduled"}
    return yaml.safe_dump(doc, sort_keys=False, width=120)

def export_all(rules, out="out"):
    for sub in ("splunk", "kql", "sentinel"):
        Path(out, sub).mkdir(parents=True, exist_ok=True)
    n = 0
    for r in rules:
        s = r["_stem"]
        Path(out, "splunk", f"{s}.spl").write_text(to_splunk(r) + "\n")
        Path(out, "kql", f"{s}.kql").write_text(to_kql(r) + "\n")
        Path(out, "sentinel", f"{s}.yaml").write_text(to_sentinel_yaml(r))
        n += 1
    return n
