# Project status: DetectForge + Blue Team Case Files

Verified 2026-11-09 against the repo, CI, the lab and Splunk itself (not copied from older checklists).
Legend: ✅ done · 🔶 partly · ❌ not started

| Part | Status | Evidence / what's left |
|---|---|---|
| 0. Prep | 🔶 | Personal prep (permit timeline, accounts) is tracked privately. Host has Git, Python, VS Code, VirtualBox, Docker, Wireshark. |
| 1. DetectForge on GitHub | ✅ | Public repo; CI green on every commit. 🔶 Reading `PROJECT_EXPLAINED.md` end to end is still to do. |
| 2. Lab | ✅ | WIN-LAB (Sysmon64 + UF) → Docker Splunk; indexes `sysmon`, `wineventlog` (+ PowerShell/Operational); snapshot `lab-ready`. See README → Home lab. |
| 3. Real telemetry | ✅ | 9 rules have real sanitised Sysmon events in `tests/data/`; one real-data rule bug fixed (CHANGELOG). Benign simulations stand in for Atomic Red Team (ART itself not installed). |
| 4. Case files | ❌ | Tooling ready for Case 2 (`-Blind` mode). Cases 1–3 are Praveen's blind investigations: see `cases/README.md`. |
| 5. New rules | 🔶 | 5 Sigma rules + 1 native added (78% priority coverage). The brief wants rules *from case findings*, so that comes after Part 4. |
| 6. Sentinel | ❌ | Optional. Splunk already proves the deploy-and-alert loop; KQL/analytics YAML are generated in `out/`. |
| 7. Publish | 🔶 | README, CHANGELOG, resume/blog drafts updated. Still to do: screenshots (`docs/screenshots/`), demo video, LinkedIn, GitHub description/topics, CV. |
| 8. Interview prep | ❌ | Material in `docs/RESUME_AND_INTERVIEW.md`, including two real bug stories. |
| 9. Applying | ❌ | — |

## Lab quick reference
* Start: `powershell -ExecutionPolicy Bypass -File lab\start-lab.ps1`
* Splunk Web: `http://192.168.56.1:8000` from WIN-LAB (**http**, not https), `http://127.0.0.1:8000` from the host
* Deploy rules as alerts: `powershell -ExecutionPolicy Bypass -File lab\deploy-splunk-app.ps1`
* Simulations: `lab/purple/simulations.ps1` (WIN-LAB fetches it from Splunk Web, see `cases/README.md`)
* `UBU-SPLUNK` is retired. Don't start it.

## Estimated remaining effort
* Lean route (Cases 1 + 2, publish, interview prep): about 4–5 days
* Everything (all 3 cases, Sentinel, publish, prep): about 7–8 days
