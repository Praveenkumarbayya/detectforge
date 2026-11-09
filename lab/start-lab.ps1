<#
.SYNOPSIS
  Start the DetectForge VirtualBox lab and confirm Splunk Web is reachable.

.DESCRIPTION
  WIN-LAB (Windows 11 + Sysmon, Atomic Red Team) and UBU-SPLUNK (Splunk Enterprise) share the
  VirtualBox NAT network "LabNet" (10.0.2.0/24). If UBU-SPLUNK is powered off, Splunk Web won't
  open inside WIN-LAB. This script:
    1. pins UBU-SPLUNK to 10.0.2.4 with a fixed DHCP lease (so the URL never moves),
    2. makes sure the host port-forward 8000 -> 10.0.2.4:8000 exists,
    3. starts any lab VM that is off (headless),
    4. waits until Splunk Web answers, then prints the URLs to use.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\start-lab.ps1
  powershell -ExecutionPolicy Bypass -File lab\start-lab.ps1 -Stop   # save state of both VMs
#>
param(
  [switch]$Stop,
  [int]$TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'
$vb       = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$net      = 'LabNet'
$splunkVm = 'UBU-SPLUNK'
$winVm    = 'WIN-LAB'
$splunkIp = '10.0.2.4'
$splunkMac = '0800270AEADF'   # UBU-SPLUNK NIC 1

if (-not (Test-Path $vb)) { throw "VirtualBox not found at $vb" }

function Get-VmState($name) {
  (& $vb showvminfo $name --machinereadable | Select-String '^VMState=').Line -replace '^VMState="(.*)"$', '$1'
}

if ($Stop) {
  foreach ($vm in $winVm, $splunkVm) {
    if ((Get-VmState $vm) -eq 'running') { Write-Host "Saving state of $vm..."; & $vb controlvm $vm savestate | Out-Null }
  }
  return
}

# 1. Fixed DHCP lease for the Splunk server (idempotent).
$cfg = (& $vb list dhcpservers) -join "`n"
if ($cfg -notmatch "(?i)$($splunkMac -replace '(..)(?!$)', '$1:')") {
  Write-Host "Pinning $splunkVm to $splunkIp on $net"
  & $vb dhcpserver modify --network $net --mac-address $splunkMac --fixed-address $splunkIp | Out-Null
}

# 2. Host -> Splunk Web forward (so you can also open it from the host browser).
$nat = (& $vb natnetwork list) -join "`n"
if ($nat -notmatch 'SplunkWeb:tcp') {
  Write-Host 'Adding port-forward SplunkWeb host:8000 -> ' "$splunkIp`:8000"
  & $vb natnetwork modify --netname $net --port-forward-4 "SplunkWeb:tcp:[]:8000:[$splunkIp]:8000" | Out-Null
}

# 3. Start VMs (Splunk first so it is ready by the time Windows logs in).
foreach ($vm in $splunkVm, $winVm) {
  $state = Get-VmState $vm
  if ($state -ne 'running') {
    $type = if ($vm -eq $winVm) { 'gui' } else { 'headless' }
    Write-Host "Starting $vm ($state -> $type)"
    & $vb startvm $vm --type $type | Out-Null
  } else {
    Write-Host "$vm already running"
  }
}

# 4. Wait for Splunk Web.
$url = 'http://127.0.0.1:8000/en-US/account/login'
$deadline = (Get-Date).AddSeconds($TimeoutSec)
Write-Host -NoNewline 'Waiting for Splunk Web'
while ((Get-Date) -lt $deadline) {
  try {
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
    if ($r.StatusCode -eq 200) {
      Write-Host "`nSplunk Web is up."
      Write-Host "  From the host:        http://127.0.0.1:8000"
      Write-Host "  From inside WIN-LAB:  http://192.168.56.1:8000   (http, not https - https gets 'connection reset')"
      return
    }
  } catch { Write-Host -NoNewline '.'; Start-Sleep -Seconds 5 }
}
Write-Warning "Splunk Web did not answer within $TimeoutSec s. Log in to $splunkVm and run:"
Write-Warning "  sudo /opt/splunk/bin/splunk status ; sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1"
exit 1
