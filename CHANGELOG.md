# Changelog

Detection changes driven by real lab telemetry (WIN-LAB → Sysmon → Splunk). Each entry says what real data
showed, why it mattered, and what changed.

## 2026-11-09

### `proc_local_account_create`: duplicate alerts on real telemetry (fixed)
* **Found by:** Part 3 simulation `net user dfsimuser /add` in WIN-LAB. The scheduled Splunk alert returned
  **2 results for one action**.
* **Why:** on real Windows, `net.exe` re-launches itself as `net1.exe` with the same command line. The rule matched
  both processes. My hand-written test samples only ever had one process, so the tests couldn't show this.
* **Change:** filter `net1.exe` when its parent is `net.exe`. `net1.exe` launched directly still alerts, because
  calling it directly is a known way to dodge rules that only watch `net.exe`.
* **Tests:** real `net.exe … /add` added as `should_match`; the real `net1.exe` child and the `/delete` cleanup
  commands added as `should_not_match`.

### Importer: pseudonymisation changed detection semantics (fixed)
* **Found by:** importing the real rundll32 event. The sanitiser rewrote `C:\Users\Public\…` to
  `C:\Users\user\…`, and the imported true positive then *failed* `proc_rundll32_susp`.
* **Why:** the scrub replaced every `C:\Users\<name>`. But `Public`, `Default` and `All Users` are shared folders,
  not people, and `C:\Users\Public` is a classic staging path rules depend on.
* **Change:** keep shared profile folders, and stop the regex from consuming quotes and spaces. Regression test
  added.

### Real telemetry added for 9 rules
Encoded PowerShell, WMI process creation, rundll32, admin-share copy, scheduled task, Run key, local account,
wevtutil log clearing and certutil download now each have at least one real, sanitised Sysmon event in
`tests/data/`, from benign simulations in `lab/purple/simulations.ps1`. Real cleanup commands (`schtasks /delete`,
`reg delete`, `net user /delete`) are kept as `should_not_match` so rules stay specific to the malicious action.

### Native brute-force / password-spray detection added
`detections_native/splunk/win_bruteforce_password_spray.yml`: counts EID 4625 failures per source over 15 minutes.
Validated live: a 12-attempt spray across 6 non-existent accounts fired it once.
