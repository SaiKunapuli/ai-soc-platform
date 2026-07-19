<#
.SYNOPSIS
    Register (or unregister) Windows Scheduled Tasks that keep the AI SOC
    dashboard fed with fresh alerts without manual intervention.

.DESCRIPTION
    Creates two user-level Scheduled Tasks (no admin required):

      AISOC-Pipeline  — runs run_pipeline.py  every N minutes (default: 30)
      AISOC-Training  — runs train_model.py   every N hours   (default: 24)

    The pipeline re-scores recent telemetry and writes new EnrichedAlerts to
    the SQLite store the dashboard reads. The training task keeps the baseline
    model current without you remembering to re-train.

    Use -Unregister to remove both tasks. Use -Status to see if they exist.

.PARAMETER PipelineInterval
    How often (in minutes) to run the detection pipeline. Default: 30.

.PARAMETER TrainingInterval
    How often (in hours) to re-train the baseline model. Default: 24.

.PARAMETER PipelineHours
    How many hours of telemetry the pipeline pulls. Default: 1.

.PARAMETER TrainingHours
    How many hours of telemetry training pulls. Default: 168 (7 days).

.PARAMETER Python
    Path to the Python executable in the venv.
    Default: $env:LOCALAPPDATA\venvs\aisoc\Scripts\python.exe

.PARAMETER Unregister
    Remove both scheduled tasks and exit.

.PARAMETER Status
    Show the current state of both tasks and exit.

.EXAMPLE
    # Register both tasks with defaults (pipeline every 30 min, training daily):
    .\scripts\register-pipeline-task.ps1

.EXAMPLE
    # Faster pipeline (15 min), custom Python:
    .\scripts\register-pipeline-task.ps1 -PipelineInterval 15 `
        -Python "D:\venvs\aisoc\Scripts\python.exe"

.EXAMPLE
    # Check task status:
    .\scripts\register-pipeline-task.ps1 -Status

.EXAMPLE
    # Remove the tasks:
    .\scripts\register-pipeline-task.ps1 -Unregister
#>

[CmdletBinding(DefaultParameterSetName = "Register")]
param(
    [Parameter(ParameterSetName = "Register")]
    [int]$PipelineInterval = 30,

    [Parameter(ParameterSetName = "Register")]
    [int]$TrainingInterval = 24,

    [Parameter(ParameterSetName = "Register")]
    [double]$PipelineHours = 1,

    [Parameter(ParameterSetName = "Register")]
    [double]$TrainingHours = 168,

    [Parameter(ParameterSetName = "Register")]
    [string]$Python = "$env:LOCALAPPDATA\venvs\aisoc\Scripts\python.exe",

    [Parameter(ParameterSetName = "Unregister")]
    [switch]$Unregister,

    [Parameter(ParameterSetName = "Status")]
    [switch]$Status
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent

$Cyan   = "Cyan"
$Green  = "Green"
$Yellow = "Yellow"
$Red    = "Red"
$Gray   = "DarkGray"

function Write-OK   { param([string]$T) Write-Host "   OK  $T" -ForegroundColor $Green }
function Write-Warn { param([string]$T) Write-Host "   ⚠   $T" -ForegroundColor $Yellow }
function Write-Err  { param([string]$T) Write-Host "   ✗   $T" -ForegroundColor $Red }
function Write-Info { param([string]$T) Write-Host "   ℹ   $T" -ForegroundColor $Gray }

# ══════════════════════════════════════════════════════════════════════════════
# STATUS
# ══════════════════════════════════════════════════════════════════════════════

if ($Status) {
    Write-Host ""
    Write-Host " AI SOC — Scheduled Task Status" -ForegroundColor $Cyan
    Write-Host "=================================" -ForegroundColor $Cyan
    Write-Host ""

    $tasks = @("AISOC-Pipeline", "AISOC-Training")
    foreach ($name in $tasks) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task) {
            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction SilentlyContinue
            Write-Host " ✓  $name" -ForegroundColor $Green
            Write-Host "       State:         $($task.State)" -ForegroundColor $Gray
            Write-Host "       Last Run:      $(if ($info.LastRunTime -gt [datetime]::MinValue) { $info.LastRunTime } else { 'never' })" -ForegroundColor $Gray
            Write-Host "       Next Run:      $(if ($info.NextRunTime -gt [datetime]::MinValue) { $info.NextRunTime } else { 'pending' })" -ForegroundColor $Gray
            Write-Host "       Last Result:   $($info.LastTaskResult)" -ForegroundColor $Gray
        } else {
            Write-Host " ✗  $name  (not registered)" -ForegroundColor $Yellow
        }
        Write-Host ""
    }
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# UNREGISTER
# ══════════════════════════════════════════════════════════════════════════════

if ($Unregister) {
    Write-Host ""
    Write-Host " AI SOC — Unregistering Scheduled Tasks" -ForegroundColor $Cyan
    Write-Host "==========================================" -ForegroundColor $Cyan
    Write-Host ""

    $tasks = @("AISOC-Pipeline", "AISOC-Training")
    foreach ($name in $tasks) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-OK "Removed: $name"
        } else {
            Write-Info "$name was not registered"
        }
    }
    Write-Host ""
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# REGISTER
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " AI SOC — Register Scheduled Tasks"        -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

# Pre-flight checks
if (-not (Test-Path $Python)) {
    Write-Err "Python not found at: $Python"
    Write-Info "Create the venv first: python -m venv $env:LOCALAPPDATA\venvs\aisoc"
    Write-Info "Or specify a custom path: -Python 'D:\venvs\aisoc\Scripts\python.exe'"
    exit 1
}
Write-OK "Python: $Python"

$pipelineScript = Join-Path $RepoRoot "scripts\run_pipeline.py"
$trainingScript = Join-Path $RepoRoot "scripts\train_model.py"

if (-not (Test-Path $pipelineScript)) {
    Write-Err "Pipeline script not found: $pipelineScript"
    exit 1
}
if (-not (Test-Path $trainingScript)) {
    Write-Err "Training script not found: $trainingScript"
    exit 1
}
Write-OK "Scripts found"

# ── Common task settings ─────────────────────────────────────────────────────
$taskSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2)

# Training may take longer (days of data); give it more headroom
$trainingSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -RestartCount 1 `
    -RestartInterval (New-TimeSpan -Minutes 5)

# ── AISOC-Pipeline: run_pipeline.py every N minutes ─────────────────────────
Write-Host ""
Write-Host "── AISOC-Pipeline ──" -ForegroundColor $Cyan
Write-Info "Script:      run_pipeline.py --hours $PipelineHours"
Write-Info "Interval:    every $PipelineInterval minutes"

$pipelineAction = New-ScheduledTaskAction `
    -Execute $Python `
    -Argument "`"$pipelineScript`" --hours $PipelineHours" `
    -WorkingDirectory $RepoRoot

# Start 2 minutes from now, then repeat every PipelineInterval minutes indefinitely
$pipelineTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes $PipelineInterval) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask `
    -TaskName "AISOC-Pipeline" `
    -Action $pipelineAction `
    -Trigger $pipelineTrigger `
    -Settings $taskSettings `
    -Description "AI SOC: run detection pipeline every ${PipelineInterval}min" `
    -Force | Out-Null

Write-OK "AISOC-Pipeline registered (first run in ~2 min, every ${PipelineInterval}min after)"

# ── AISOC-Training: train_model.py every N hours ────────────────────────────
Write-Host ""
Write-Host "── AISOC-Training ──" -ForegroundColor $Cyan
Write-Info "Script:      train_model.py --hours $TrainingHours"
Write-Info "Interval:    every $TrainingInterval hours"

$trainingAction = New-ScheduledTaskAction `
    -Execute $Python `
    -Argument "`"$trainingScript`" --hours $TrainingHours" `
    -WorkingDirectory $RepoRoot

# Start 5 minutes from now, then repeat every TrainingInterval hours indefinitely
$trainingTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (New-TimeSpan -Hours $TrainingInterval) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask `
    -TaskName "AISOC-Training" `
    -Action $trainingAction `
    -Trigger $trainingTrigger `
    -Settings $trainingSettings `
    -Description "AI SOC: retrain baseline model every ${TrainingInterval}h" `
    -Force | Out-Null

Write-OK "AISOC-Training registered (first run in ~5 min, every ${TrainingInterval}h after)"

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " TASKS REGISTERED"                        -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

Write-Host "Task              Interval        First Run" -ForegroundColor $White
Write-Host "────              ────────        ─────────" -ForegroundColor $Gray
Write-Host "AISOC-Pipeline    every ${PipelineInterval}min     in ~2 minutes"  -ForegroundColor $Green
Write-Host "AISOC-Training    every ${TrainingInterval}h       in ~5 minutes"  -ForegroundColor $Green
Write-Host ""

Write-Host "Commands:" -ForegroundColor $White
Write-Host "  Check status:   .\scripts\register-pipeline-task.ps1 -Status"
Write-Host "  Remove tasks:   .\scripts\register-pipeline-task.ps1 -Unregister"
Write-Host "  View in GUI:    taskschd.msc  →  Task Scheduler Library"
Write-Host ""
Write-Host "What happens next:" -ForegroundColor $White
Write-Host "  1. AISOC-Pipeline runs in ~2 min → alerts appear in the dashboard"
Write-Host "  2. AISOC-Training runs in ~5 min → baseline model updated"
Write-Host "  3. Both repeat on their schedule even after reboots"
Write-Host "  4. The dashboard at http://localhost:8000 stays fresh automatically"
Write-Host ""
