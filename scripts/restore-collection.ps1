<#
.SYNOPSIS
  Restore Wazuh data collection after Docker/agent bounce.

.DESCRIPTION
  Automates the full recovery sequence:
    1. Ensure Docker Desktop + engine are up (launch if needed).
    2. Wait for the Wazuh manager container and the indexer.
    3. Check the agent. If it isn't Active, break the common post-reboot
       enrollment deadlock: delete the stale agent via the API, restart the
       agent service, restart the manager so remoted reloads keys.
    4. Verify events are flowing again.

  Run from the repo root in an ELEVATED PowerShell (the agent service restart
  needs admin):
      powershell -ExecutionPolicy Bypass -File scripts\restore-collection.ps1

  Indexer creds are read from .env; API creds default to the wazuh-docker
  single-node defaults (override with -ApiUser / -ApiPass).
#>
param(
    [string]$ComposeDir = "$PSScriptRoot\..\..\wazuh-docker\single-node",
    [string]$Manager = "single-node-wazuh.manager-1",
    [string]$IndexerUrl = "https://localhost:9200",
    [string]$ApiUrl = "https://localhost:55000",
    [string]$ApiUser = "wazuh-wui",
    [string]$ApiPass = "MyS3cr37P450r.*-",
    [string]$AgentName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Continue"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Log($m) { Write-Host "[$(Get-Date -Format HH:mm:ss)] $m" }

# --- indexer creds from repo .env ---
$envFile = "$PSScriptRoot\..\.env"
$idxUser = "admin"; $idxPass = "SecretPassword"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^AISOC_INDEXER_USER=(.+)$") { $idxUser = $Matches[1].Trim() }
        if ($_ -match "^AISOC_INDEXER_PASSWORD=(.+)$") { $idxPass = $Matches[1].Trim() }
    }
}
$idxCred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${idxUser}:${idxPass}"))

function Test-Engine { docker version --format "{{.Server.Version}}" 2>$null }

function Wait-For($what, [scriptblock]$check, [int]$tries = 24, [int]$delay = 5) {
    for ($i = 0; $i -lt $tries; $i++) {
        if (& $check) { Log "$what ready"; return $true }
        Start-Sleep -Seconds $delay
    }
    Log "TIMEOUT waiting for $what"; return $false
}

function Agent-Active {
    $line = docker exec $Manager /var/ossec/bin/agent_control -l 2>$null | Select-String $AgentName
    return ($line -match "Active")
}

function Last-Event-Minutes {
    try {
        $body = '{"size":1,"sort":[{"timestamp":"desc"}],"query":{"term":{"data.win.system.eventID":"1"}}}'
        $r = Invoke-RestMethod -Uri "$IndexerUrl/wazuh-archives-*/_search" -Method Post -Body $body `
            -ContentType "application/json" -Headers @{ Authorization = "Basic $idxCred" }
        $ts = [datetime]$r.hits.hits[0]._source.timestamp
        return [math]::Round(((Get-Date).ToUniversalTime() - $ts.ToUniversalTime()).TotalMinutes, 1)
    } catch { return 99999 }
}

# ---- 1. Docker engine ----
if (-not (Test-Engine)) {
    Log "Docker engine down — launching Docker Desktop"
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (-not (Wait-For "Docker engine" { [bool](Test-Engine) } 30 6)) { exit 1 }
}
Log "Docker engine: $(Test-Engine)"

# ---- 2. manager container (restart=always brings it) + indexer ----
Wait-For "manager container" { docker ps --filter "name=$Manager" --format "{{.Names}}" | Select-String $Manager } | Out-Null
Wait-For "indexer" {
    try { (Invoke-RestMethod -Uri "$IndexerUrl/_cluster/health" -Headers @{ Authorization = "Basic $idxCred" }).status -in @("green", "yellow") }
    catch { $false }
} 30 6 | Out-Null

# ---- 3. agent ----
Log "checking agent..."
if (Wait-For "agent Active" { Agent-Active } 6 10) {
    Log "agent already connected"
} else {
    Log "agent not connected — breaking enrollment deadlock"
    # delete any stale agent(s) with our name via the API
    try {
        $apiAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ApiUser}:${ApiPass}"))
        $tok = (Invoke-RestMethod -Uri "$ApiUrl/security/user/authenticate" -Method Post `
            -Headers @{ Authorization = "Basic $apiAuth" }).data.token
        $agents = (Invoke-RestMethod -Uri "$ApiUrl/agents?select=id,name" -Headers @{ Authorization = "Bearer $tok" }).data.affected_items
        $ids = $agents | Where-Object { $_.name -eq $AgentName -and $_.id -ne "000" } | ForEach-Object { $_.id }
        if ($ids) {
            $list = ($ids -join ",")
            Invoke-RestMethod -Uri "$ApiUrl/agents?agents_list=$list&older_than=0s&status=all" -Method Delete `
                -Headers @{ Authorization = "Bearer $tok" } | Out-Null
            Log "deleted stale agent id(s): $list"
        } else { Log "no stale agent to delete" }
    } catch { Log "API delete failed: $($_.Exception.Message)" }

    Log "restarting agent service (needs admin)"
    Restart-Service WazuhSvc -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 8
    Log "restarting manager so remoted reloads keys"
    docker restart $Manager | Out-Null
    Wait-For "agent Active" { Agent-Active } 18 10 | Out-Null
}

# ---- 4. verify data flow ----
Start-Sleep -Seconds 10
$mins = Last-Event-Minutes
if ($mins -lt 5) { Log "COLLECTION RESTORED - most recent event $mins min ago" }
else { Log "WARNING: still stale ($mins min). Check the agent log manually." }
