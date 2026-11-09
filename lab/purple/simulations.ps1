<#
.SYNOPSIS
  Benign attack-technique simulations for the DetectForge lab (run INSIDE WIN-LAB, as Administrator).

.DESCRIPTION
  Each simulation reproduces the command line of the matching Atomic Red Team test for that technique,
  using harmless targets, and cleans up after itself. No tooling is downloaded and nothing malicious runs.
  They exist to generate real Sysmon/Security telemetry for DetectForge's rules and for Case 2.

    -List                       show the simulations
    -Run T1047,T1053.005        run specific ones
    -All                        run every simulation
    -Blind -Count 3             Case 2: run N random simulations and write the hidden answer to
                                C:\Users\Public\case2_answer.b64 (base64). Do NOT decode until your
                                investigation report is written.
#>
param([string[]]$Run, [switch]$All, [switch]$List, [switch]$Blind, [int]$Count = 3)
$ErrorActionPreference = 'Continue'
$pub = 'C:\Users\Public'

$sims = [ordered]@{
  'T1059.001' = @{ Name = 'Encoded PowerShell'; Do = {
      # same shape as Atomic T1059.001 "-EncodedCommand"; payload just prints a string
      $b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output detectforge-sim'))
      powershell.exe -NoProfile -EncodedCommand $b } }
  'T1047' = @{ Name = 'WMI process creation'; Do = {
      powershell.exe -NoProfile -Command "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='notepad.exe'} | Out-Null"
      Start-Sleep 2; Stop-Process -Name notepad -ErrorAction SilentlyContinue } }
  'T1218.011' = @{ Name = 'Rundll32 from Public folder'; Do = {
      Start-Process rundll32.exe -ArgumentList "$pub\detectforge_sim.dll,DllRegisterServer"
      Start-Sleep 2; Stop-Process -Name rundll32 -ErrorAction SilentlyContinue } }
  'T1021.002' = @{ Name = 'Copy to admin share'; Do = {
      cmd.exe /c "copy C:\Windows\win.ini \\127.0.0.1\C$\Windows\Temp\detectforge_sim.ini"
      Remove-Item C:\Windows\Temp\detectforge_sim.ini -ErrorAction SilentlyContinue } }
  'T1053.005' = @{ Name = 'Scheduled task from user-writable path'; Do = {
      schtasks.exe /create /tn DetectForgeSim /tr "$pub\detectforge_sim.exe" /sc onlogon /ru SYSTEM /f
      schtasks.exe /delete /tn DetectForgeSim /f } }
  'T1547.001' = @{ Name = 'Registry Run key persistence'; Do = {
      reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v DetectForgeSim /t REG_SZ /d "$pub\detectforge_sim.exe" /f
      reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v DetectForgeSim /f } }
  'T1136.001' = @{ Name = 'Local account creation'; Do = {
      net.exe user dfsimuser /add          # no password; deleted immediately
      net.exe user dfsimuser /delete } }
  'T1070.001' = @{ Name = 'Event log clearing (low-value channel)'; Do = {
      wevtutil.exe cl Microsoft-Windows-Bits-Client/Operational } }
  'T1105' = @{ Name = 'Certutil download (from lab Splunk, benign file)'; Do = {
      certutil.exe -urlcache -split -f http://192.168.56.1:8000/robots.txt "$pub\detectforge_sim.txt"
      Remove-Item "$pub\detectforge_sim.txt" -ErrorAction SilentlyContinue } }
  'T1110.003' = @{ Name = 'Password spray (6 non-existent accounts)'; Do = {
      foreach ($u in 1..6) { foreach ($p in 'Wr0ngPass1', 'Wr0ngPass2') {
          net.exe use \\127.0.0.1\IPC$ /user:dfspray$u $p 2>$null | Out-Null } } } }
}

if ($List) { $sims.GetEnumerator() | ForEach-Object { '{0,-10} {1}' -f $_.Key, $_.Value.Name }; return }

if ($Blind) {
  $pick = $sims.Keys | Get-Random -Count $Count
  $answer = "Case 2 answer - run at $(Get-Date -Format s): " + ($pick -join ', ')
  [IO.File]::WriteAllText("$pub\case2_answer.b64", [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($answer)))
  foreach ($k in $pick) { & $sims[$k].Do *> $null; Start-Sleep (Get-Random -Minimum 20 -Maximum 90) }
  Clear-Host
  Write-Host "Done. $Count techniques ran at random intervals. Answer hidden in $pub\case2_answer.b64"
  Write-Host 'Investigate in Splunk first; decode only after your report is written.'
  return
}

# powershell -File passes "-Run a,b" as one string; split it so both invocation styles work
$todo = if ($All) { $sims.Keys } else { $Run -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
if (-not $todo) { Write-Host 'Nothing to do. Use -List, -Run <ids>, -All or -Blind.'; return }
foreach ($k in $todo) {
  if (-not $sims.Contains($k)) { Write-Warning "unknown simulation $k"; continue }
  Write-Host "== $k  $($sims[$k].Name)"
  & $sims[$k].Do
}
