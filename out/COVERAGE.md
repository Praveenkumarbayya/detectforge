# Detection Coverage Report

* Rules: **13**  |  Distinct techniques: **15**
* Priority-technique coverage: **15/28 (53%)**

## Coverage by tactic

| Tactic | Techniques covered |
|---|---|
| Command And Control | T1059.004, T1105, T1140 |
| Credential Access | T1003.001 |
| Defense Evasion | T1027, T1059.001, T1070.001, T1105, T1140, T1218.005, T1562.001 |
| Execution | T1027, T1053.005, T1059.001, T1059.004, T1105, T1204.002, T1218.005, T1566.001 |
| Impact | T1490 |
| Initial Access | T1204.002, T1566.001 |
| Persistence | T1053.005, T1136.001, T1547.001 |
| Privilege Escalation | T1547.001 |

## Gaps (build next)

| Technique | Name | Atomic Red Team tests |
|---|---|---|
| T1059.003 | Windows Command Shell | https://atomicredteam.io/atomic-red-team/atomics/T1059.003/ |
| T1003.003 | NTDS | https://atomicredteam.io/atomic-red-team/atomics/T1003.003/ |
| T1218.011 | Rundll32 | https://atomicredteam.io/atomic-red-team/atomics/T1218.011/ |
| T1021.001 | Remote Desktop Protocol | https://atomicredteam.io/atomic-red-team/atomics/T1021.001/ |
| T1021.002 | SMB/Windows Admin Shares | https://atomicredteam.io/atomic-red-team/atomics/T1021.002/ |
| T1078 | Valid Accounts | https://atomicredteam.io/atomic-red-team/atomics/T1078/ |
| T1110 | Brute Force | https://atomicredteam.io/atomic-red-team/atomics/T1110/ |
| T1486 | Data Encrypted for Impact | https://atomicredteam.io/atomic-red-team/atomics/T1486/ |
| T1041 | Exfiltration Over C2 Channel | https://atomicredteam.io/atomic-red-team/atomics/T1041/ |
| T1071.001 | Web Protocols (C2) | https://atomicredteam.io/atomic-red-team/atomics/T1071.001/ |
| T1047 | WMI | https://atomicredteam.io/atomic-red-team/atomics/T1047/ |
| T1055 | Process Injection | https://atomicredteam.io/atomic-red-team/atomics/T1055/ |
| T1112 | Modify Registry | https://atomicredteam.io/atomic-red-team/atomics/T1112/ |

## Rules

| Rule | Level | Techniques |
|---|---|---|
| Linux Bash Reverse Shell | critical | T1059.004 |
| LSASS Memory Dump via comsvcs.dll MiniDump | critical | T1003.001 |
| Shadow Copy / Backup Deletion (Ransomware Precursor) | critical | T1490 |
| Certutil Used to Download or Decode Payloads | high | T1105, T1140 |
| Microsoft Defender Real-Time Protection Disabled | high | T1562.001 |
| Local User Account Created via net.exe | high | T1136.001 |
| Mshta Executing Remote or Inline Script | high | T1218.005 |
| Office Application Spawning Script Interpreter or Shell | high | T1566.001, T1204.002 |
| Suspicious Encoded PowerShell Command | high | T1059.001, T1027 |
| Windows Event Logs Cleared via wevtutil | high | T1070.001 |
| Linux Download-and-Execute via curl/wget Piped to Shell | medium | T1105, T1059.004 |
| Registry Run Key Persistence via reg.exe | medium | T1547.001 |
| Scheduled Task Created Pointing to User-Writable Path | medium | T1053.005 |
