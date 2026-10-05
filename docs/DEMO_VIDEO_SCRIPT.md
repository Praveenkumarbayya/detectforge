# 2–3 minute demo video script (screen-record terminal + browser; voice-over)

Tools: OBS Studio or Loom. Increase terminal font size. Record at 1080p. Keep under 3:00.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:15 | Title slide → README top | "I'm Praveen, a cybersecurity graduate in Dublin. This is DetectForge: a detection-as-code pipeline. The problem: SOC detections are often untested and noisy." |
| 0:15–0:40 | Open `rules/proc_lsass_comsvcs_minidump.yml` + its test JSON | "A detection is a Sigma rule mapped to ATT&CK T1003.001, with documented false positives and a test file with attack and benign events." |
| 0:40–1:05 | `python -m detectforge validate` then `test` | "Validate enforces quality. Test proves each rule fires on attacks, and stays silent across a 300-event benign corpus — zero false positives." |
| 1:05–1:25 | Show GitHub Actions run (green) | "The same checks run in CI, so a bad rule can't be merged." |
| 1:25–1:50 | `convert`, open a `.kql` and a Sentinel `.yaml` | "One rule compiles to Splunk SPL and Microsoft Sentinel KQL, including a deployable analytics rule." |
| 1:50–2:20 | `hunt data/scenarios/ransomware_chain.jsonl` | "Now a simulated ransomware attack. Nine alerts are correlated into one incident on WS-042, with a kill chain from phishing to backup deletion and a risk score." |
| 2:20–2:40 | `coverage` → load `out/attack_layer.json` in ATT&CK Navigator | "Coverage report shows what I detect and what I don't: 53% of my priority techniques, with a gap list to build next." |
| 2:40–3:00 | Open `out/TRACEABILITY.md` | "Each detection maps to NIS2, DORA and ISO 27001 — useful to Irish regulated firms. Repo link below; I'm looking for SOC roles in Dublin." |

Tips: put the GitHub link in the first line of the description; upload to YouTube (unlisted is fine) and embed in the README and LinkedIn Featured section.
