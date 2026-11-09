# I built a detection-as-code pipeline so my SOC rules can't ship untested

*(LinkedIn/blog draft — edit into your own voice, add your screenshots, and replace anything you did differently.)*

Most people building cybersecurity portfolios install a SIEM, forward some logs, and screenshot a dashboard. Hiring managers have seen that a hundred times. What they rarely see is someone who understands **why SOCs fail**.

In my experience studying and lab-testing, it's rarely the tool. It's **detection quality**: rules nobody tested, alert fatigue, no idea what the SOC can *actually* detect, and no bridge to the compliance people asking "can you evidence detection capability?" — a question every Irish regulated firm is now facing under **NIS2** and **DORA**.

So I built **DetectForge**, an open-source detection-as-code pipeline:

**1. Rules as code.** 18 detections written in vendor-neutral Sigma, plus one native Splunk aggregation for brute force/password spray, all mapped to MITRE ATT&CK and each documenting its false positives.

**2. Tests or it doesn't merge.** Every rule needs true-positive and benign test events. A 300-event benign corpus is replayed on every commit; a new false positive fails the build.

**3. Compile once, deploy anywhere.** The pipeline outputs Splunk SPL, Microsoft Sentinel KQL and Sentinel analytics-rule YAML, and deploys the rules to Splunk as scheduled alerts with one command.

**4. Prove it on real telemetry.** In my home lab (Windows 11 + Sysmon → Splunk Universal Forwarder → Splunk in Docker), I ran benign simulations of five techniques: encoded PowerShell, WMI process creation, rundll32 from a public folder, admin-share copy and a password spray. Each raised exactly the alert it should, and nothing else fired. The real events now live in the test suite, and they found a bug: my log sanitiser was rewriting `C:\Users\Public`, the exact path one rule depends on.

**5. Know your blind spots.** It generates an ATT&CK Navigator layer and a gap report. My library covers 78% of my priority techniques — and the report tells me exactly what to build next.

**6. Alerts become a story.** In a simulated ransomware attack (phishing macro → encoded PowerShell → credential dump → shadow-copy deletion), 9 raw alerts collapse into one host-level incident with a kill chain and a risk score.

**7. SOC ↔ GRC.** Each detection is mapped to NIS2, DORA and ISO 27001:2022 controls. I'm an ISO 27001 Lead Auditor, so I wanted the technical and audit worlds to speak the same language.

**What I learned.** Writing the rule is 20% of the work. The other 80% is proving it works, proving it doesn't fire on normal admin activity, and knowing what you *don't* cover. I also learned to be honest about limits: one lab host isn't production, my simulations are benign stand-ins rather than real attack tooling, and the offline evaluator supports a Sigma subset. That's why the brute-force detection is native SPL validated live, not a Sigma rule that silently can't count.

**What's next:** Atomic Red Team validation of the credential-dumping and ransomware-precursor rules, Entra ID sign-in detections, and deploying to Microsoft Sentinel from CI.

Repo: github.com/<you>/detectforge — feedback and PRs welcome. I'm a recent graduate based in Dublin looking for SOC / detection engineering roles — if your team is hiring (and sponsors Critical Skills permits), I'd love to talk.

#cybersecurity #detectionengineering #SOC #MITREATTACK #Sigma #MicrosoftSentinel #Dublin
