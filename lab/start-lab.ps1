<#
.SYNOPSIS
  Start the DetectForge home lab and confirm Splunk is reachable from WIN-LAB.

.DESCRIPTION
  Lab layout (see README "Home lab"):
    * Splunk Enterprise runs in Docker Desktop on the host (container "splunk"),
      publishing 8000 (web), 8088 (HEC), 8089 (mgmt), 9997 (forwarder input).
    * WIN-LAB (VirtualBox, Windows 11 + Sysmon + Splunk Universal Forwarder) reaches the
      host on the VirtualBox host-only network at 192.168.56.1.
    * UBU-SPLUNK (old Splunk VM) is retired - this script never starts it.

  Steps: start Docker Desktop if needed -> start the splunk container -> wait until it is
  healthy and Splunk Web answers -> start WIN-LAB -> print the URLs.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\start-lab.ps1
  powershell -ExecutionPolicy Bypass -File lab\start-lab.ps1 -Stop   # save WIN-LAB, stop container
#>
param(
  [switch]$Stop,
  [int]$TimeoutSec = 420
)

$ErrorActionPreference = 'Stop'
$vb        = "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe"
$winVm     = 'WIN-LAB'
$container = 'splunk'
$hostOnly  = '192.168.56.1'

function Get-VmState($name) {
  (& $vb showvminfo $name --machinereadable | Select-String '^VMState=').Line -replace '^VMState="(.*)"$', '$1'
}
function Test-Docker { & docker info --format '{{.ServerVersion}}' 2>$null | Out-Null; $LASTEXITCODE -eq 0 }

if ($Stop) {
  if ((Get-VmState $winVm) -eq 'running') { Write-Host "Saving state of $winVm..."; & $vb controlvm $winVm savestate | Out-Null }
  if (Test-Docker) { Write-Host "Stopping container $container..."; & docker stop $container | Out-Null }
  return
}

$deadline = (Get-Date).AddSeconds($TimeoutSec)

# 1. Docker Desktop
if (-not (Test-Docker)) {
  Write-Host 'Starting Docker Desktop...'
  Start-Process "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
  while (-not (Test-Docker)) {
    if ((Get-Date) -gt $deadline) { throw 'Docker Desktop did not start in time.' }
    Start-Sleep -Seconds 5
  }
}

# 2. Splunk container
$state = (& docker inspect -f '{{.State.Status}}' $container 2>$null)
if ($state -ne 'running') { Write-Host "Starting container $container ($state)"; & docker start $container | Out-Null }

# 3. Wait for healthy + Splunk Web
Write-Host -NoNewline 'Waiting for Splunk'
while ($true) {
  $health = (& docker inspect -f '{{.State.Health.Status}}' $container 2>$null)
  $web = try { (Invoke-WebRequest "http://${hostOnly}:8000/en-US/account/login" -UseBasicParsing -TimeoutSec 5).StatusCode } catch { 0 }
  if ($health -eq 'healthy' -and $web -eq 200) { Write-Host " ready."; break }
  if ((Get-Date) -gt $deadline) { Write-Host ''; throw "Splunk not ready (health=$health, web=$web). Try: docker logs --tail 50 $container" }
  Write-Host -NoNewline '.'; Start-Sleep -Seconds 5
}

# 4. WIN-LAB
if ((Get-VmState $winVm) -ne 'running') { Write-Host "Starting $winVm"; & $vb startvm $winVm --type gui | Out-Null }
else { Write-Host "$winVm already running" }

Write-Host ''
Write-Host 'Splunk Web (use http, NOT https - https gives "connection reset" / curl error 35):'
Write-Host "  inside WIN-LAB : http://${hostOnly}:8000"
Write-Host '  on the host    : http://127.0.0.1:8000'
Write-Host "Forwarder target : ${hostOnly}:9997  (indexes: sysmon, wineventlog)"
