<#
.SYNOPSIS
  Copy the detectforge_lab Splunk app (indexes + Sysmon field extraction) into the
  Docker "splunk" container and restart Splunk so it takes effect.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File lab\deploy-splunk-app.ps1
#>
param([string]$Container = 'splunk')
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'splunk\detectforge_lab'

& docker cp $src "${Container}:/opt/splunk/etc/apps/"
if ($LASTEXITCODE) { throw 'docker cp failed' }
& docker exec -u root $Container chown -R splunk:splunk /opt/splunk/etc/apps/detectforge_lab
Write-Host 'Restarting Splunk (about a minute)...'
& docker exec -u splunk $Container /opt/splunk/bin/splunk restart | Select-Object -Last 1
