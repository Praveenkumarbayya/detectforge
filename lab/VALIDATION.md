# Lab validation: detections firing on real Sysmon telemetry

Real Sysmon process-creation events (EID 1) from WIN-LAB flow to Splunk in index `sysmon`
(see README → Home lab). These benign commands simulate four DetectForge rules without downloading anything.
Run them in an **Administrator PowerShell inside WIN-LAB**:

```powershell
# T1059.001/T1027: encoded PowerShell (prints "detectforge-sim")
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABkAGUAdABlAGMAdABmAG8AcgBnAGUALQBzAGkAbQA=
# T1047: WMI/CIM process creation (starts Notepad)
powershell.exe -NoProfile -Command "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='notepad.exe'} | Out-Null"
# T1218.011: rundll32 loading a DLL from C:\Users\Public (file doesn't exist; an error dialog is expected)
rundll32.exe C:\Users\Public\detectforge_sim.dll,DllRegisterServer
# T1021.002: copy to an admin share (failing is fine; the command line is what's detected)
cmd.exe /c copy C:\Windows\win.ini \\127.0.0.1\C$\Windows\Temp\detectforge_sim.ini
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

Then in Splunk Web (http://192.168.56.1:8000 → Search & Reporting, time range "Last 24 hours"), prefix each
generated query from `out/splunk/` with `index=sysmon EventCode=1`:

| Rule | Search |
|---|---|
| `proc_ps_encoded_command` | `index=sysmon EventCode=1` + contents of `out/splunk/proc_ps_encoded_command.spl` |
| `proc_wmic_process_create` | `index=sysmon EventCode=1` + `out/splunk/proc_wmic_process_create.spl` |
| `proc_rundll32_susp` | `index=sysmon EventCode=1` + `out/splunk/proc_rundll32_susp.spl` |
| `proc_admin_share_access` | `index=sysmon EventCode=1` + `out/splunk/proc_admin_share_access.spl` |

One search for all four simulations at once:

```
index=sysmon EventCode=1 CommandLine="*detectforge_sim*" OR CommandLine="*-EncodedCommand VwBy*" OR CommandLine="*Invoke-CimMethod*Win32_Process*"
| table _time Image ParentImage CommandLine
```

Fields such as `Image` and `CommandLine` come from the `detectforge_lab` app's search-time extraction
(`lab/splunk/detectforge_lab/local/transforms.conf`), so the Sysmon add-on from Splunkbase isn't required.

## Next: turn hits into regression tests

Export matching events (Search → Export → JSON) and import them as true-positive test data:

```powershell
python -m detectforge import-events <export.json> --rule proc_wmic_process_create --user Praveen
```

The importer scrubs host and user names (`--user` adds extra names to remove) before anything is committed.
