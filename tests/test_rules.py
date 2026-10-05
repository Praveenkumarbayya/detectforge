import json
from pathlib import Path
import pytest
from detectforge import loader, evaluator, hunt

RULES = loader.load_rules("rules")

@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["_stem"])
def test_rule_quality_gate(rule):
    assert loader.lint(rule) == []

@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["_stem"])
def test_rule_detects_attack_and_ignores_benign(rule):
    spec = json.loads(Path(f"tests/data/{rule['_stem']}.json").read_text())
    assert spec["should_match"], "every rule needs at least one true-positive sample"
    assert all(evaluator.matches(rule, e) for e in spec["should_match"])
    assert not any(evaluator.matches(rule, e) for e in spec["should_not_match"])

def test_no_false_positives_on_benign_corpus():
    events = [json.loads(l) for l in Path("tests/data/benign_corpus.jsonl").read_text().splitlines() if l.strip()]
    assert hunt.replay(RULES, events) == []

def test_ransomware_scenario_is_correlated_into_one_multistage_incident():
    events = [json.loads(l) for l in Path("data/scenarios/ransomware_chain.jsonl").read_text().splitlines() if l.strip()]
    inc = hunt.correlate(hunt.replay(RULES, events))
    assert inc[0]["host"] == "WS-042" and inc[0]["multi_stage"] and inc[0]["score"] >= 50

def test_all_rules_compile_to_splunk_and_kql():
    from detectforge import convert
    for r in RULES:
        assert convert.to_splunk(r) and "| where" in convert.to_kql(r)

def test_aggregation_conditions_fail_loudly():
    rule = {"detection": {"sel": {"a": 1}, "condition": "sel | count() > 5"}}
    with pytest.raises(NotImplementedError):
        evaluator.matches(rule, {"a": 1})

def test_importer_sanitises_and_appends(tmp_path):
    from detectforge import importer
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"result": {"Computer": "REALHOST", "User": "REALHOST\\bob", "Image": "C:\\Users\\bob\\x.exe",
                                        "CommandLine": "x.exe bob", "junk": 1}}))
    ev = importer.sanitise(importer.read_events(f), ["bob"])
    assert ev == [{"Image": "C:\\Users\\user\\x.exe", "CommandLine": "x.exe user", "User": "LAB\\user", "Computer": "WS-001"}]
    p = importer.add_to_tests("demo", ev, "should_match", tmp_path)
    assert json.loads(p.read_text())["should_match"] == ev
