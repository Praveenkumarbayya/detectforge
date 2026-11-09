# Resume bullets, LinkedIn text & interview talking points

> **Integrity rule:** only claim what you have actually run and can explain line by line. Follow the 2-week plan so every bullet below becomes true *for you* (update the numbers if you add rules/tests).

## Resume entry (paste under "Projects")

**DetectForge — Detection-as-Code SOC Pipeline** | Python, Sigma, MITRE ATT&CK, Splunk (SPL), Microsoft Sentinel (KQL), Sysmon, Docker, GitHub Actions | github.com/<you>/detectforge

* Engineered a detection-as-code pipeline that compiles **vendor-neutral Sigma rules into Splunk SPL/scheduled alerts and Microsoft Sentinel KQL/analytics rules**, gated by GitHub Actions CI (lint, unit tests, benign-corpus false-positive regression).
* Authored and tested **19 ATT&CK-mapped detections** (18 Sigma + 1 native SPL aggregation for brute force/password spray) with documented false-positive guidance; **45 automated tests**, zero false positives on a 300-event benign corpus.
* Built a **home SOC lab** (Windows 11 + Sysmon → Splunk Universal Forwarder → Splunk in Docker) and **deployed the rules as live scheduled alerts**; benign attack simulations triggered exactly the intended alerts, and the real Sysmon events now regression-test the rules in CI.
* Built an **alert-correlation engine** that clusters alerts per host into kill-chain incidents with risk scoring, reducing 9 raw alerts to 1 prioritised multi-stage incident in a ransomware simulation.
* Generated **ATT&CK Navigator coverage layers and gap analysis** (78% of a 28-technique priority list) to drive the detection backlog.
* Mapped detections to **NIS2, DORA and ISO 27001:2022** controls, linking SOC telemetry to EU regulatory evidence (ISO 27001 Lead Auditor background).

Shorter 2-line version for a crowded CV:
* Built DetectForge, a CI-tested detection-as-code pipeline (Sigma → Splunk / Sentinel) with 19 ATT&CK-mapped detections, kill-chain alert correlation and NIS2/DORA/ISO 27001 traceability.
* Deployed the rules as live Splunk alerts in a Sysmon home lab and validated them against real telemetry; 45 automated tests, 0 false positives on a benign corpus.

## LinkedIn headline / About line
"Aspiring SOC / Detection Engineer | SC-200 | ISO 27001 Lead Auditor | Building detection-as-code (Sigma → Sentinel/Splunk) | Dublin | Seeking Critical Skills sponsorship"

## The 60-second pitch ("walk me through your project")
"Most SOC problems are detection-quality problems: untested rules, alert fatigue, and no view of coverage. I built DetectForge to treat detections like software. Rules are written in vendor-neutral Sigma, each with true-positive and benign tests. CI blocks any change that fails or introduces a false positive on a benign corpus. It compiles to Sentinel and Splunk, produces an ATT&CK coverage map and gap list, and a correlation engine turns nine separate alerts from a simulated ransomware attack into a single incident with a kill chain. Because I hold ISO 27001 Lead Auditor, I also mapped each detection to NIS2, DORA and ISO 27001 controls, which matters for Irish financial and critical-infrastructure employers."

## Likely interview questions & strong answers

**Why Sigma instead of writing KQL directly?** Portability and review. One rule format that compiles to any SIEM; the logic is reviewable in Git; a job change or SIEM migration doesn't lose the detection library.

**How do you know a detection works?** Three layers: unit tests with true-positive samples, a benign corpus regression to catch false positives, and (lab) execution of the matching Atomic Red Team test to confirm real telemetry triggers it. Be honest that my sample data is synthetic and real tuning needs production logs.

**Walk me through one rule.** Use *LSASS MiniDump via comsvcs.dll*: T1003.001, why attackers use a signed Windows DLL (living off the land), what telemetry you need (Sysmon EID 1 / 4688 with command-line auditing; EID 10 for real LSASS access), false positives (rare EDR/forensic tools), and what an analyst does next (isolate, reset credentials, check for lateral movement).

**How would you reduce alert fatigue?** Severity by tactic chain, correlation per host/time window, allow-lists documented in `falsepositives`, benign-corpus regression, retiring/tuning rules by hit-rate.

**What are the weaknesses of command-line detections?** Obfuscation, renamed binaries, alternative binaries. Answer: layer behavioural detections (parent/child, LSASS access events, network), and use coverage gaps to prioritise. Mention `-enc` variants and that you'd add decoding logic in enrichment.

**Why is the brute-force detection not a Sigma rule?** It needs counting over a time window (failed logons per source in 15 minutes). My Sigma rules and offline evaluator are single-event matchers. I made aggregations fail loudly instead of silently passing, and wrote this one as native SPL with the same metadata (ATT&CK tags, false positives), so coverage and compliance still see it. It's validated live in the lab instead of offline. Thresholds: ≥10 failures (guessing) or ≥5 distinct accounts (spraying) from one source.

**What would you do next?** Validate the original rules (LSASS dump, shadow-copy deletion) with Atomic Red Team, Entra ID sign-in detections, deploying rules to Sentinel via GitHub Action, and CTI enrichment (MISP/OpenCTI).

**How does this relate to NIS2/DORA?** NIS2 Art. 21 requires incident-handling measures and Art. 23 has reporting timelines; DORA Art. 10 requires detection of anomalous activities and Art. 19 covers major-incident reporting. Detections + tested evidence + traceability = audit evidence. (Say "indicative mapping" — you are not giving legal advice.)

**Tell me about a mistake/bug.** Real ones from this build:
* *Real data caught a sanitiser bug.* My importer pseudonymises usernames by rewriting `C:\Users\<name>`, but it also rewrote `C:\Users\Public`. That's the exact staging path my rundll32 rule keys on. When I imported real lab events, the rundll32 test failed, and that's how I found it. I fixed it to keep shared profile folders and added a regression test. Lesson: sanitisation can silently change detection semantics.
* *"Splunk won't open" for weeks.* TCP to port 8000 succeeded, but browsers and curl got "connection reset". Splunk Web was HTTP-only and I was using `https://`. Then no data arrived, because the forwarder still pointed at a retired Splunk VM. Then Sysmon specifically was missing: the forwarder runs as a low-privilege service account and got access denied (errorCode=5) on the Sysmon channel, fixed by adding it to Event Log Readers. Lesson: test each layer separately (TCP, TLS, app, data path, permissions).

## STAR story (behavioural)
* **S**: SOCs drown in untested, noisy detections. **T**: Show I can build reliable detections end to end. **A**: Designed DetectForge with CI gates, benign regression, coverage analysis and correlation; validated in a lab. **R**: 19 detections deployed as live Splunk alerts, 45 tests, 0 FPs on the corpus, 5 simulated techniques each raising exactly the intended alert in the lab, 9 alerts → 1 prioritised incident, 78% priority coverage with the gaps driving the roadmap.
