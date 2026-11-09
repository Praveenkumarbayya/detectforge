<#
.SYNOPSIS
  Build and deploy the detectforge_lab Splunk app into the Docker "splunk" container:
  indexes + Sysmon field extraction (lab/splunk/detectforge_lab) plus every DetectForge rule
  compiled into a scheduled alert (savedsearches.conf, generated from rules/*.yml).

.DESCRIPTION
  Detection-as-code deploy step: rules/*.yml -> `python -m detectforge convert` -> savedsearches.conf
  -> app staged in a temp folder -> docker cp -> Splunk restart. Re-run after changing any rule.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\deploy-splunk-app.ps1
#>
param([string]$Container = 'splunk')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

# 1. Compile rules -> out/splunk/savedsearches.conf
Push-Location $repo
try {
  & python -m detectforge validate | Select-Object -Last 1
  if ($LASTEXITCODE) { throw 'rule validation failed; not deploying' }
  & python -m detectforge convert
  if ($LASTEXITCODE) { throw 'convert failed' }
} finally { Pop-Location }

# 2. Stage the app: static config + generated alerts
$stage = Join-Path ([IO.Path]::GetTempPath()) "detectforge_stage_$PID"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $stage | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'splunk\detectforge_lab') $stage -Recurse
Copy-Item (Join-Path $repo 'out\splunk\savedsearches.conf') (Join-Path $stage 'detectforge_lab\local\savedsearches.conf')

# 3. Ship and restart
& docker cp (Join-Path $stage 'detectforge_lab') "${Container}:/opt/splunk/etc/apps/"
if ($LASTEXITCODE) { throw 'docker cp failed' }
Remove-Item $stage -Recurse -Force
& docker exec -u root $Container chown -R splunk:splunk /opt/splunk/etc/apps/detectforge_lab
Write-Host 'Restarting Splunk (about a minute)...'
& docker exec -u splunk $Container /opt/splunk/bin/splunk restart | Select-Object -Last 1
$n = (& docker exec $Container grep -c '^\[DetectForge - ' /opt/splunk/etc/apps/detectforge_lab/local/savedsearches.conf)
Write-Host "Deployed $n DetectForge alerts (every 5 min). Splunk Web: Activity > Triggered Alerts."
