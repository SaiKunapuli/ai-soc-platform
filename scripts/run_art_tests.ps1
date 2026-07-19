# Run Atomic Red Team tests and auto-record results in labels.csv
#
# Usage (elevated PowerShell from the ai-soc-platform/ directory):
#   .\scripts\run_art_tests.ps1
#
# WARNING: Run only on the lab machine. Always runs cleanup after each test.

$ErrorActionPreference = "Stop"
$labelsFile = "simulations\labels.csv"
$hostname = $env:COMPUTERNAME

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Atomic Red Team - Automated Test Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify ART is installed
if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Atomic Red Team not installed." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $labelsFile)) {
    Write-Host "ERROR: $labelsFile not found." -ForegroundColor Red
    exit 1
}

# Technique list: ID, Name, TestNumber, Note
$techs = @(
    @("T1053.005", "Scheduled Task", 1, "Scheduled Task persistence - process chain and registry"),
    @("T1136.001", "Create Local Account", 1, "Local account creation - auth and security log"),
    @("T1057", "Process Discovery", 1, "Process enumeration - rare process chain and burst rate")
)

$total = $techs.Count
$done = 0

foreach ($t in $techs) {
    $id = $t[0]
    $name = $t[1]
    $testNum = $t[2]
    $note = $t[3]

    Write-Host "[$($done+1)/$total] $id - $name" -ForegroundColor Yellow
    Write-Host "       $note" -ForegroundColor DarkGray

    Write-Host "       Showing details..." -ForegroundColor DarkGray
    Invoke-AtomicTest $id -ShowDetails -TestNumbers $testNum 2>&1 | Out-Null

    Write-Host "       Running..." -ForegroundColor DarkGray
    $start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Invoke-AtomicTest $id -TestNumbers $testNum
    $end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    Write-Host "       Cleaning up..." -ForegroundColor DarkGray
    Invoke-AtomicTest $id -TestNumbers $testNum -Cleanup 2>&1 | Out-Null

    $line = "$start,$end,$hostname,$id,$testNum,$note"
    Add-Content -Path $labelsFile -Value $line
    Write-Host "       Recorded: $start -> $end" -ForegroundColor Green

    $done++
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Done - $done/$total techniques run" -ForegroundColor Cyan
Write-Host " Labels appended to $labelsFile" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Last $total entries in labels.csv:" -ForegroundColor DarkGray
$lines = Get-Content $labelsFile
$startIdx = [Math]::Max(0, $lines.Count - $total)
for ($i = $startIdx; $i -lt $lines.Count; $i++) {
    Write-Host "  $($lines[$i])" -ForegroundColor DarkGray
}
