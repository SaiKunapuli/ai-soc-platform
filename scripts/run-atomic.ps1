<#
.SYNOPSIS
    Detonate an Atomic Red Team test and record a labeled attack window so the
    detector can be scored against a REAL attack that ran on THIS host — the same
    benign distribution the model learned, which is the honest way to measure
    recall and false positives (no public-dataset domain shift).

.DESCRIPTION
    1. Checks the free Invoke-AtomicRedTeam module is present.
    2. Records the UTC start, runs the atomic, records the UTC end.
    3. Appends a row to simulations/labels.csv (the ground truth evaluate.py uses).
    4. Waits out Sysmon + indexing lag so the events are queryable.

    Executing an atomic runs real attacker TTPs on this machine. Only run it in
    your own lab, and run -Cleanup afterwards. Use -DryRun to exercise the label
    plumbing without detonating anything.

.EXAMPLE
    # one-time, free, no API key:
    Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force

    .\scripts\run-atomic.ps1 -Technique T1059.001 -TestNumbers 1
    .\scripts\run-atomic.ps1 -Technique T1059.001 -TestNumbers 1 -Cleanup
    python scripts/evaluate.py        # score detection against the recorded window
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Technique,
    [string]$TestNumbers = "",
    [string]$AtomicsPath = "C:\AtomicRedTeam\atomics",
    [string]$LabelsCsv = (Join-Path $PSScriptRoot "..\simulations\labels.csv"),
    [string]$LabelHost = $env:COMPUTERNAME,
    [string]$Notes = "",
    [int]$SettleSeconds = 45,
    [switch]$Cleanup,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if ($TestNumbers) { $testsLabel = $TestNumbers } else { $testsLabel = "all" }

$hasModule = Get-Module -ListAvailable -Name invoke-atomicredteam
if (-not $hasModule -and -not $DryRun) {
    Write-Host "Invoke-AtomicRedTeam is not installed." -ForegroundColor Yellow
    Write-Host "Install it (free, no API key):" -ForegroundColor Yellow
    Write-Host "  Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force"
    Write-Host "Then re-run. Or pass -DryRun to record a label window without detonating."
    exit 1
}

$start = (Get-Date).ToUniversalTime()

if ($DryRun) {
    Write-Host "[DryRun] Not detonating $Technique - recording a placeholder window." -ForegroundColor Cyan
    Start-Sleep -Seconds 2
}
else {
    Import-Module invoke-atomicredteam -Force
    $params = @{ AtomicTechnique = $Technique; PathToAtomicsFolder = $AtomicsPath }
    if ($TestNumbers) { $params.TestNumbers = $TestNumbers.Split(",") }

    if ($Cleanup) {
        Invoke-AtomicTest @params -Cleanup
        Write-Host "Cleanup for $Technique complete." -ForegroundColor Green
        exit 0
    }

    Write-Host "Detonating $Technique (tests: $testsLabel) ..." -ForegroundColor Yellow
    Invoke-AtomicTest @params
}

$end = (Get-Date).ToUniversalTime()
Write-Host "Waiting $SettleSeconds s for Sysmon + indexing lag ..."
Start-Sleep -Seconds $SettleSeconds

# -- append the labeled window (schema: start_utc,end_utc,host,technique_id,test_number,notes)
$startStr = $start.ToString("yyyy-MM-ddTHH:mm:ssZ")
$endStr = $end.ToString("yyyy-MM-ddTHH:mm:ssZ")
if ($Notes) { $noteStr = $Notes } else { $noteStr = "Atomic Red Team $Technique" }
$noteStr = $noteStr -replace ',', ';'

if (-not (Test-Path $LabelsCsv)) {
    "start_utc,end_utc,host,technique_id,test_number,notes" | Out-File -FilePath $LabelsCsv -Encoding ascii
}
$row = "$startStr,$endStr,$LabelHost,$Technique,$testsLabel,$noteStr"
$row | Add-Content -Path $LabelsCsv -Encoding ascii

Write-Host "Recorded label $startStr to $endStr host=$LabelHost in $LabelsCsv" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. python scripts/evaluate.py   (score detection against this run)"
Write-Host "  2. re-run this script with -Cleanup to revert the atomic's changes"
