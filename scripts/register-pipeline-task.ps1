<#
.SYNOPSIS
  Register a Windows Scheduled Task that runs the detection pipeline periodically.

.DESCRIPTION
  Hands-off alternative to run-pipeline-loop.ps1: creates a user-level Scheduled
  Task (no admin needed) that runs the pipeline every -IntervalMinutes, starting at
  logon. Remove with: Unregister-ScheduledTask -TaskName AISOC-Pipeline

  Usage:
      powershell -ExecutionPolicy Bypass -File scripts\register-pipeline-task.ps1
#>
param(
    [int]$IntervalMinutes = 30,
    [double]$Hours = 1,
    [string]$Python = "$env:LOCALAPPDATA\venvs\aisoc\Scripts\python.exe",
    [string]$TaskName = "AISOC-Pipeline"
)

$repo = Split-Path $PSScriptRoot -Parent
$action = New-ScheduledTaskAction -Execute $Python `
    -Argument "`"$repo\scripts\run_pipeline.py`" --hours $Hours" -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -AtLogOn
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)).Repetition
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "AI SOC platform: run detection pipeline every $IntervalMinutes min" -Force
Write-Host "registered scheduled task '$TaskName' (every $IntervalMinutes min). Remove with: Unregister-ScheduledTask -TaskName $TaskName"
