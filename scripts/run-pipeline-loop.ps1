<#
.SYNOPSIS
  Run the detection pipeline on a loop so the dashboard stays fresh with real alerts.

.DESCRIPTION
  Every -IntervalMinutes, pulls the last -Hours of telemetry, scores/fuses it, and
  writes EnrichedAlerts to the store the dashboard reads. Runs until Ctrl+C.
  No system changes — just a terminal loop. For hands-off operation, register it as
  a Scheduled Task instead (see scripts/register-pipeline-task.ps1).

  Usage (from anywhere):
      powershell -ExecutionPolicy Bypass -File scripts\run-pipeline-loop.ps1
      powershell -ExecutionPolicy Bypass -File scripts\run-pipeline-loop.ps1 -IntervalMinutes 15
#>
param(
    [int]$IntervalMinutes = 30,
    [double]$Hours = 1,
    [string]$Python = "$env:LOCALAPPDATA\venvs\aisoc\Scripts\python.exe"
)

$repo = Split-Path $PSScriptRoot -Parent
Write-Host "pipeline loop: every $IntervalMinutes min, window ${Hours}h. Ctrl+C to stop."
while ($true) {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] running pipeline..."
    try {
        & $Python "$repo\scripts\run_pipeline.py" --hours $Hours
    } catch {
        Write-Host "  pipeline error (continuing): $($_.Exception.Message)"
    }
    Start-Sleep -Seconds ($IntervalMinutes * 60)
}
