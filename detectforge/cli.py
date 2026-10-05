"""detectforge CLI:  validate | test | coverage | convert | compliance | hunt"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import loader, evaluator, coverage, convert, compliance, hunt, importer

G, R_, Y, X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def cmd_validate(a):
    rules, bad = loader.load_rules(a.rules), 0
    for r in rules:
        errs = loader.lint(r, a.tests)
        print(f"{R_+'FAIL' if errs else G+'ok  '}{X}  {r['_stem']}")
        for e in errs:
            print(f"        - {e}"); bad += 1
    print(f"\n{len(rules)} rules checked, {bad} problem(s)")
    return 1 if bad else 0


def cmd_test(a):
    rules, fails = loader.load_rules(a.rules), 0
    for r in rules:
        spec = json.loads((Path(a.tests) / f"{r['_stem']}.json").read_text())
        tp = [evaluator.matches(r, e) for e in spec["should_match"]]
        tn = [evaluator.matches(r, e) for e in spec["should_not_match"]]
        ok = all(tp) and not any(tn)
        fails += not ok
        print(f"{G+'PASS' if ok else R_+'FAIL'}{X}  {r['_stem']:34} TP {sum(tp)}/{len(tp)}  FP {sum(tn)}/{len(tn)}")
    bp = Path(a.tests) / "benign_corpus.jsonl"
    if bp.exists():
        events = [json.loads(l) for l in bp.read_text().splitlines() if l.strip()]
        fp = hunt.replay(rules, events)
        print(f"\nbenign corpus: {len(events)} events -> {len(fp)} alert(s)  {G+'(0 false positives)' if not fp else R_+'FALSE POSITIVES!'}{X}")
        for x in fp: print("   ", x["rule"], "|", x["cmd"][:80])
        fails += bool(fp)
    print(f"\n{len(rules)-fails}/{len(rules)} checks passed" if fails else f"\nall {len(rules)} rules passed")
    return 1 if fails else 0


def cmd_coverage(a):
    rules = loader.load_rules(a.rules)
    coverage.write_all(rules, a.out)
    print(coverage.markdown_report(rules)); print(f"wrote {a.out}/COVERAGE.md and {a.out}/attack_layer.json (open in ATT&CK Navigator)")


def cmd_convert(a):
    n = convert.export_all(loader.load_rules(a.rules), a.out)
    print(f"compiled {n} rules -> {a.out}/splunk, {a.out}/kql, {a.out}/sentinel")


def cmd_compliance(a):
    md = compliance.markdown(loader.load_rules(a.rules))
    Path(a.out).mkdir(exist_ok=True); Path(a.out, "TRACEABILITY.md").write_text(md); print(md)


def cmd_hunt(a):
    rules = loader.load_rules(a.rules)
    events = [json.loads(l) for l in Path(a.logs).read_text().splitlines() if l.strip()]
    alerts = hunt.replay(rules, events)
    print(f"replayed {len(events)} events -> {len(alerts)} alerts")
    print(hunt.render(hunt.correlate(alerts)))


def cmd_import(a):
    ev = importer.sanitise(importer.read_events(a.file), a.user)
    p = importer.add_to_tests(a.rule, ev, a.kind, a.tests)
    print(f"added {len(ev)} sanitised event(s) to {p} as {a.kind}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="detectforge", description=__doc__)
    p.add_argument("--rules", default="rules"); p.add_argument("--tests", default="tests/data"); p.add_argument("--out", default="out")
    sp = p.add_subparsers(dest="cmd", required=True)
    for n, f in [("validate", cmd_validate), ("test", cmd_test), ("coverage", cmd_coverage), ("convert", cmd_convert), ("compliance", cmd_compliance)]:
        sp.add_parser(n).set_defaults(fn=f)
    h = sp.add_parser("hunt"); h.add_argument("logs"); h.set_defaults(fn=cmd_hunt)
    i = sp.add_parser("import-events", help="add sanitised real events (Splunk JSON export) to a rule's tests")
    i.add_argument("file"); i.add_argument("--rule", required=True); i.add_argument("--kind", default="should_match", choices=["should_match", "should_not_match"])
    i.add_argument("--user", action="append", help="real username to scrub (repeatable)"); i.set_defaults(fn=cmd_import)
    a = p.parse_args(argv)
    sys.exit(a.fn(a) or 0)

if __name__ == "__main__":
    main()
