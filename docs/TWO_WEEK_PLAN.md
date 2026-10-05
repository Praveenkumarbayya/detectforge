# 2-week execution plan (20+ hrs/week) — make the project *yours*

The repo is a strong foundation, but recruiters and interviewers can tell instantly if you don't understand it. Your job over two weeks is to **run it, break it, extend it and validate it in a lab** so every claim is true.

## Week 1 — Understand, extend, validate
| Day | Goal | Output |
|---|---|---|
| 1 | Set up: Python venv, run all commands, read every file. Read Sigma spec + ATT&CK pages for each rule's technique. | Notes: explain each rule in your own words |
| 2 | Push to GitHub (public), confirm CI green. Add badges. | Live repo + green Actions run |
| 3 | Lab: Windows 10/11 VM (VirtualBox/VMware) + Sysmon (SwiftOnSecurity or Olaf Hartong config). Enable command-line auditing (EID 4688). | Working Sysmon telemetry |
| 4 | Install [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Invoke-AtomicRedTeam). Run tests for T1059.001, T1003.001, T1053.005, T1490. Export Sysmon events. | Real event samples |
| 5 | Add the real (sanitised) events to `tests/data/`; fix any rule that misses real telemetry. Document what you changed and why. | Commit history showing iteration |
| 6 | Write **5 new rules** from the gap list (e.g. T1218.011, T1021.001 RDP enabling, T1047 WMI, T1078/T1110 as aggregation later). Each with tests. | 18+ rules |
| 7 | Rest / review. Draft README changes. | — |

## Week 2 — Deploy, prove, publish
| Day | Goal | Output |
|---|---|---|
| 8 | Microsoft Sentinel free trial on a fresh Azure account (or Wazuh/Elastic locally). Forward Sysmon; create the KQL parser function. Import 2–3 generated analytic rules. | Screenshot of an alert firing |
| 9 | Re-run Atomic tests → capture alert in Sentinel → screenshot the incident. | Evidence for README |
| 10 | Add one aggregation detection (brute force/spray) in KQL/SPL and document why the offline evaluator doesn't cover it. | Honest limitation + new rule |
| 11 | Update numbers in README/resume (rules, tests, coverage). Record the demo video using `DEMO_VIDEO_SCRIPT.md`. | Video on YouTube |
| 12 | Publish the blog/LinkedIn post (`BLOG_POST.md`, your voice). Add project to LinkedIn Featured + resume. | Public write-up |
| 13 | Mock interview: rehearse the 60-second pitch and every Q in `RESUME_AND_INTERVIEW.md` out loud. | Recorded practice |
| 14 | Start applying in bulk (below). | 15+ tailored applications |

## Getting hired *with sponsorship* — practical notes
* **Verify current permit rules yourself** at enterprise.gov.ie (Critical Skills Employment Permit: eligibility, salary thresholds and occupation lists change) and irishimmigration.ie. If you graduated from an Irish institution, check eligibility for the **Stamp 1G graduate permission** — it may give you a time window to work and search without needing an immediate sponsor. Confirm duration and conditions for your qualification level.
* **Target employers with Dublin security teams and a record of hiring international talent:** large consultancies (Accenture, Deloitte, PwC, KPMG, EY), managed security providers (e.g. Integrity360), big tech and fintech/payments with Irish offices (Microsoft, Google, Amazon, Mastercard, Stripe, Workday), and asset-management/banking SOCs. Verify current openings and sponsorship statements on each careers page.
* **Titles to search:** SOC Analyst (Tier 1), Cyber Defence Analyst, Security Operations Analyst, Detection Engineer (junior), Security Analyst, GRC/Cyber Risk Analyst (your ISO 27001 badge is a differentiator), Graduate cybersecurity programmes.
* **Put the repo link, video and one-line pitch in the top third of your CV**; lead your LinkedIn About with "SC-200 | ISO 27001 Lead Auditor | DetectForge".
* **Say sponsorship status truthfully and early** (e.g. "Eligible to work under Stamp 1G; will require Critical Skills sponsorship afterwards") — recruiters prefer clarity.
* Apply 5–10 roles/day with a tailored first paragraph; message the hiring manager/recruiter with your repo link.
