# Blue Team Case Files

Three **blind** investigations: the answer is not known when the investigation starts. Each is written up with
[`TEMPLATE.md`](TEMPLATE.md) as `cases/case-0N-<slug>.md`. Method for every case: alert/source → which
user/host/IP → what happened around it → competing explanations → test each → scope → severity → action → write up.
Only after the report is written: check the answer and add *What I missed*.

| # | Case | Data | Status | Report |
|---|---|---|---|---|
| 1 | Blind PCAP investigation | a recent exercise from malware-traffic-analysis.net | ❌ not started | — |
| 2 | Blind purple-team in my own lab | WIN-LAB Sysmon in Splunk (`index=sysmon`, `index=wineventlog`) | ❌ not started (tooling ready) | — |
| 3 | BOTS v1 scenario + NIS2-style notification draft | Splunk *Boss of the SOC* v1 dataset | ❌ not started | — |

## Case 1: blind PCAP (no lab needed)

1. On malware-traffic-analysis.net, pick a recent exercise. Download **only** the PCAP and the description. Don't
   open the answers page.
2. Work in Wireshark: Statistics → Protocol Hierarchy and Conversations; identify the victim (DHCP / NBNS /
   Kerberos); HTTP hosts and TLS SNI; DNS; File → Export Objects. **Hash exports and look them up. Never run them.**
3. Write the timeline, IOCs and ATT&CK mapping; then compare with the published answer.

## Case 2: blind purple-team (lab tooling is ready)

1. Restore WIN-LAB to the `lab-ready` snapshot (VirtualBox → WIN-LAB → Snapshots).
2. In an **Administrator** PowerShell inside WIN-LAB:
   ```powershell
   Invoke-WebRequest 'http://192.168.56.1:8000/en-US/static/app/detectforge_lab/simulations.ps1?v=1' -UseBasicParsing -OutFile C:\Users\Public\simulations.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\simulations.ps1 -Blind -Count 3
   ```
   It runs 3 random techniques from [`lab/purple/simulations.ps1`](../lab/purple/simulations.ps1) at random
   intervals and hides which ones in `C:\Users\Public\case2_answer.b64`.
3. Treat it as a vague alert ("suspicious activity on WIN-LAB in the last hour"). Investigate in Splunk
   (http://192.168.56.1:8000). **Don't** start from Activity → Triggered Alerts: the point is to hunt, then check
   whether the alerts agree with you.
4. Only after the report is written, decode the answer:
   `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((gc C:\Users\Public\case2_answer.b64)))`
5. Anything you missed, or that no DetectForge alert caught → new rule (Part 5).

> The simulation list is in the repo, so you can see *which techniques could* run. The blind part is *which 3 did,
> when, and in what order*. Don't read the script's output while it runs.

## Case 3: BOTS v1 + NIS2-style notification

1. Load the public Splunk *Boss of the SOC v1* dataset into the lab Splunk. It's large, so check disk space first.
2. Pick one scenario (web defacement, or the ransomware-style incident) and investigate it without looking up
   walkthroughs.
3. Add an **NIS2 Art. 23-style notification draft** (24-hour early warning → 72-hour incident notification →
   one-month final report), clearly labelled *exercise, not legal advice*.
