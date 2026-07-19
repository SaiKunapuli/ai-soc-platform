<#
.SYNOPSIS
    One-command host provisioning for the AI SOC split-VM lab.
    Starts Wazuh Docker, enables archives, opens the firewall, installs the
    AI SOC platform, verifies Ollama, trains the baseline, and launches
    the dashboard — everything the host needs to receive + detect attacks.

.DESCRIPTION
    Run this on the host machine (the one with Docker Desktop + WSL2).
    It performs Phases 1 and 3 from docs/VM_DEPLOYMENT_GUIDE.md:

      Phase 1 — Host Setup:
        1.1  Start Wazuh Docker stack (single-node)
        1.2  Verify the stack is healthy
        1.3  Enable the archives index (required for ML)
        1.4  Open Windows Firewall for agent port 1514
        1.5  Detect host IP on the VM network
        1.6  Install the AI SOC platform (venv + pip + .env)
        1.7  Verify Ollama is ready
        1.8  Verify the full host stack (Python ↔ indexer)

      Phase 3 — Smoke Test:
        3.2  Train the baseline model
        3.3  Run the detection pipeline
        3.4  Launch the dashboard

    Every step is idempotent — re-running the script is safe.

.PARAMETER ProjectRoot
    Path to the SOC project root (contains ai-soc-platform/ and wazuh-docker/).
    Default: the parent directory of this script's location (scripts/../).

.PARAMETER WazuhDockerDir
    Path to the wazuh-docker/single-node directory.
    Default: $ProjectRoot/wazuh-docker/single-node

.PARAMETER VenvPath
    Where to create the Python virtual environment.
    Default: $env:LOCALAPPDATA\venvs\aisoc (outside OneDrive to avoid sync churn)

.PARAMETER IndexerPassword
    Wazuh indexer admin password. Must match docker-compose.yml.
    Default: SecretPassword

.PARAMETER OllamaModel
    LLM model to pull for the copilot.
    Default: qwen2.5:7b-instruct

.PARAMETER SkipDocker
    Skip Wazuh Docker startup (useful if already running).

.PARAMETER SkipFirewall
    Skip firewall rule creation.

.PARAMETER SkipOllama
    Skip Ollama verification.

.PARAMETER SkipTraining
    Skip baseline model training + pipeline run.

.PARAMETER NoDashboard
    Do not launch the dashboard at the end.

.EXAMPLE
    # Full setup — all defaults:
    .\scripts\setup-host-lab.ps1

.EXAMPLE
    # Skip Docker (already running), custom paths:
    .\scripts\setup-host-lab.ps1 -SkipDocker `
        -ProjectRoot "D:\SOC" `
        -IndexerPassword "MyCustomPassword"
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Project root containing ai-soc-platform/ and wazuh-docker/")]
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),

    [Parameter(HelpMessage = "Path to wazuh-docker/single-node")]
    [string]$WazuhDockerDir = "",

    [Parameter(HelpMessage = "Python venv path (keep outside OneDrive)")]
    [string]$VenvPath = "$env:LOCALAPPDATA\venvs\aisoc",

    [Parameter(HelpMessage = "Wazuh indexer admin password")]
    [string]$IndexerPassword = "SecretPassword",

    [Parameter(HelpMessage = "Ollama LLM model name")]
    [string]$OllamaModel = "qwen2.5:7b-instruct",

    [Parameter(HelpMessage = "Indexer URL for .env")]
    [string]$IndexerUrl = "https://localhost:9200",

    [switch]$SkipDocker,
    [switch]$SkipFirewall,
    [switch]$SkipOllama,
    [switch]$SkipTraining,
    [switch]$NoDashboard
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

# ── normalise paths ──────────────────────────────────────────────────────────
$ProjectRoot       = (Resolve-Path $ProjectRoot).Path
if (-not $WazuhDockerDir) { $WazuhDockerDir = Join-Path $ProjectRoot "wazuh-docker\single-node" }
$AiSocDir          = Join-Path $ProjectRoot "ai-soc-platform"
$WazuhManagerConf  = Join-Path $WazuhDockerDir "config\wazuh_cluster\wazuh_manager.conf"
$EnvFile           = Join-Path $AiSocDir ".env"
$LabelsCsv         = Join-Path $AiSocDir "simulations\labels.csv"

# ── colours ──────────────────────────────────────────────────────────────────
$Cyan    = "Cyan"
$Green   = "Green"
$Yellow  = "Yellow"
$Red     = "Red"
$Gray    = "DarkGray"
$White   = "White"

function Write-Step  { param([string]$Text) Write-Host "`n── $Text ──" -ForegroundColor $Cyan }
function Write-OK    { param([string]$Text) Write-Host "   OK  $Text" -ForegroundColor $Green }
function Write-Warn  { param([string]$Text) Write-Host "   ⚠   $Text" -ForegroundColor $Yellow }
function Write-Err   { param([string]$Text) Write-Host "   ✗   $Text" -ForegroundColor $Red }
function Write-Info  { param([string]$Text) Write-Host "   ℹ   $Text" -ForegroundColor $Gray }
function Write-Bold  { param([string]$Text) Write-Host $Text -ForegroundColor $White }

function Test-Admin {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " AI SOC — Host Lab Provisioning Script"   -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " Project Root  : $ProjectRoot"             -ForegroundColor $White
Write-Host " Wazuh Docker  : $WazuhDockerDir"          -ForegroundColor $White
Write-Host " AI-SOC Dir    : $AiSocDir"                -ForegroundColor $White
Write-Host " Venv Path     : $VenvPath"                -ForegroundColor $Gray
Write-Host " Indexer URL   : $IndexerUrl"              -ForegroundColor $Gray
Write-Host " Ollama Model  : $OllamaModel"             -ForegroundColor $Gray
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# PREREQUISITES
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "PREREQUISITES"

# Admin check — needed for firewall rule; Docker should work without
$isAdmin = Test-Admin
if ($isAdmin) {
    Write-OK "Running as Administrator"
} else {
    Write-Warn "Not running as Administrator — firewall rule will be skipped."
    Write-Info "For the firewall step, re-run elevated or add the rule manually:"
    Write-Info "  New-NetFirewallRule -DisplayName 'Wazuh Agent (1514)' -Direction Inbound -Protocol TCP -LocalPort 1514 -Action Allow"
    if (-not $SkipFirewall) {
        $SkipFirewall = $true
        Write-Info "(-SkipFirewall set automatically since not elevated)"
    }
}

# Docker check
if (-not $SkipDocker) {
    if (-not (Test-CommandExists "docker")) {
        Write-Err "Docker is not installed or not on PATH."
        Write-Info "Install Docker Desktop with WSL2 backend, then re-run."
        Write-Info "Or pass -SkipDocker if Wazuh is already running externally."
        exit 1
    }
    Write-OK "Docker CLI found"

    # Check Docker is actually running
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker daemon is not running. Start Docker Desktop, then re-run."
        exit 1
    }
    Write-OK "Docker daemon is running"
}

# Python check
$pythonVersion = $null
try { $pythonVersion = python --version 2>&1 } catch { }
if (-not $pythonVersion -or $pythonVersion -notmatch "3\.(1[1-9]|[2-9]\d)") {
    Write-Err "Python 3.11+ is required but was not found."
    Write-Info "Install from https://python.org, ensure it's on PATH, then re-run."
    exit 1
}
Write-OK "Python: $($pythonVersion.Trim())"

# Verify project directories exist
if (-not (Test-Path $AiSocDir)) {
    Write-Err "AI SOC platform directory not found: $AiSocDir"
    Write-Info "Check the -ProjectRoot parameter points to the correct location."
    exit 1
}
if (-not $SkipDocker -and -not (Test-Path $WazuhDockerDir)) {
    Write-Err "Wazuh Docker directory not found: $WazuhDockerDir"
    exit 1
}
Write-OK "Project directories found"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.1: START WAZUH DOCKER
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.1 — WAZUH DOCKER STACK"

if ($SkipDocker) {
    Write-Warn "-SkipDocker flag set. Assuming Wazuh is already running."
} else {
    # vm.max_map_count
    Write-Info "Setting vm.max_map_count via WSL2 ..."
    wsl -d docker-desktop sysctl -w vm.max_map_count=262144 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Could not set vm.max_map_count. WSL2 may not be running."
        Write-Info "If the indexer fails, run manually:"
        Write-Info "  wsl -d docker-desktop sysctl -w vm.max_map_count=262144"
    } else {
        Write-OK "vm.max_map_count = 262144"
    }

    Push-Location $WazuhDockerDir

    # Generate certs if not present
    $certDir = Join-Path $WazuhDockerDir "config\wazuh_indexer_ssl_certs"
    $certsExist = (Test-Path (Join-Path $certDir "root-ca.pem")) -and `
                  (Test-Path (Join-Path $certDir "wazuh.manager.pem"))
    if (-not $certsExist) {
        Write-Info "Generating SSL certificates (one-time) ..."
        docker compose -f generate-indexer-certs.yml run --rm generator 2>&1 | Out-Null
        Write-OK "Certificates generated"
    } else {
        Write-OK "SSL certificates already present"
    }

    # Check if already running
    $runningCount = (docker ps --filter "name=wazuh" --format "{{.Names}}" 2>$null | Measure-Object).Count
    if ($runningCount -ge 3) {
        Write-OK "Wazuh containers already running ($runningCount found)"
    } else {
        Write-Info "Starting Wazuh Docker stack (first run downloads ~2GB) ..."
        $composeResult = docker compose up -d 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Docker compose failed:"
            Write-Host ($composeResult -join "`n") -ForegroundColor $Gray
            Pop-Location
            exit 1
        }
        Write-OK "Wazuh Docker stack started"

        Write-Info "Waiting for indexer to bootstrap (up to 90 seconds) ..."
        $waited = 0
        do {
            Start-Sleep -Seconds 10
            $waited += 10
            $health = $null
            try {
                $health = curl.exe -k -s -u "admin:$IndexerPassword" "$IndexerUrl/_cluster/health" 2>$null | ConvertFrom-Json
            } catch { }
            if ($health -and $health.status -eq "green") {
                Write-OK "Indexer is healthy (green) after ~$waited s"
                break
            }
            if ($waited % 30 -eq 0) {
                $statusText = if ($health) { $health.status } else { "unknown" }
                Write-Info "  ... still waiting ($waited s, status: $statusText)"
            }
        } while ($waited -lt 120)

        if (-not $health -or $health.status -ne "green") {
            Write-Warn "Indexer may still be bootstrapping. Continuing — re-run later if needed."
        }
    }
    Pop-Location
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.2: VERIFY STACK HEALTHY
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.2 — STACK HEALTH CHECK"

Write-Info "Checking indexer at $IndexerUrl ..."
try {
    $healthResult = curl.exe -k -s -u "admin:$IndexerPassword" "$IndexerUrl/_cluster/health" 2>$null | ConvertFrom-Json
    Write-OK "Cluster status: $($healthResult.status) | nodes: $($healthResult.number_of_nodes) | data nodes: $($healthResult.number_of_data_nodes)"

    if ($healthResult.status -eq "red") {
        Write-Err "Cluster is RED — the indexer failed to start."
        Write-Info "Check: docker compose logs wazuh.indexer"
    } elseif ($healthResult.status -eq "yellow") {
        Write-Warn "Cluster is YELLOW — replicas are still initialising. This is normal for single-node."
    }
} catch {
    Write-Err "Cannot reach the indexer at $IndexerUrl"
    Write-Info "Check: docker ps — are all three Wazuh containers running?"
    Write-Info "Check: the IndexerPassword matches docker-compose.yml (default: SecretPassword)"
}

# Check that running containers look right
if (-not $SkipDocker) {
    Write-Info "Running Wazuh containers:"
    docker ps --filter "name=wazuh" --format "table {{.Names}}\t{{.Status}}" 2>$null | ForEach-Object {
        Write-Host "     $_" -ForegroundColor $Gray
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.3: ENABLE ARCHIVES INDEX
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.3 — ARCHIVES INDEX"

if ($SkipDocker) {
    Write-Warn "-SkipDocker set. Cannot enable archives — do it manually if not done."
} else {
    if (-not (Test-Path $WazuhManagerConf)) {
        Write-Err "Wazuh manager config not found at: $WazuhManagerConf"
        Write-Info "Archives must be enabled manually. See docs/VM_DEPLOYMENT_GUIDE.md Step 1.3."
    } else {
        $managerConfig = Get-Content $WazuhManagerConf -Raw

        if ($managerConfig -match '<logall_json>yes</logall_json>') {
            Write-OK "Archives index already enabled in wazuh_manager.conf"
        } else {
            Write-Info "Enabling archives index (logall_json: no → yes) ..."
            $managerConfig = $managerConfig -replace '<logall_json>no</logall_json>', '<logall_json>yes</logall_json>'
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($WazuhManagerConf, $managerConfig, $utf8NoBom)
            Write-OK "Archives enabled in wazuh_manager.conf"

            Write-Info "Restarting Wazuh manager to pick up config ..."
            Push-Location $WazuhDockerDir
            $restartResult = docker compose restart wazuh.manager 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Manager restart had issues. Try manually:"
                Write-Info "  docker compose restart wazuh.manager"
            }
            Pop-Location

            # Wait for restart
            Write-Info "Waiting 20 seconds for manager restart ..."
            Start-Sleep -Seconds 20

            # Verify the archives index was created
            Write-Info "Checking for wazuh-archives-* index ..."
            $archivesCheck = curl.exe -k -s -u "admin:$IndexerPassword" "$IndexerUrl/_cat/indices/wazuh-archives-*?h=index" 2>$null
            if ($archivesCheck -match "wazuh-archives") {
                Write-OK "Archives index present: $($archivesCheck.Trim())"
            } else {
                Write-Warn "Archives index not found yet. It will appear once events flow."
                Write-Info "If it never appears, check the filebeat archives module is enabled."
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.4: FIREWALL RULE
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.4 — FIREWALL (AGENT PORT 1514)"

if ($SkipFirewall) {
    Write-Warn "-SkipFirewall set or not elevated. Skipping firewall rule."
} else {
    $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Agent (1514)" -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-OK "Firewall rule already exists: 'Wazuh Agent (1514)'"
        Write-Info "  Enabled: $($existingRule.Enabled) | Action: $($existingRule.Action) | Direction: $($existingRule.Direction)"
    } else {
        Write-Info "Creating inbound firewall rule for TCP 1514 ..."
        New-NetFirewallRule `
            -DisplayName "Wazuh Agent (1514)" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 1514 `
            -Action Allow `
            -Profile Any | Out-Null
        Write-OK "Firewall rule created: 'Wazuh Agent (1514)' — inbound TCP 1514 allowed"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.5: DETECT HOST IP ON VM NETWORK
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.5 — HOST IP DETECTION"

Write-Info "Scanning network adapters for VM-facing IPs ..."

# Look for common VM network adapters
$vmAdapters = @(
    "VirtualBox Host-Only Network",
    "VMware Network Adapter VMnet1",
    "vEthernet (Default Switch)",
    "vEthernet (WSL)"
)

$foundIps = @()
$allAdapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown"
}

foreach ($adapter in $allAdapters) {
    $alias = $adapter.InterfaceAlias
    $ip    = $adapter.IPAddress
    $foundIps += @{ IP = $ip; Alias = $alias }
}

Write-Info "Non-loopback IPv4 addresses found:"
$index = 1
foreach ($entry in $foundIps) {
    $marker = ""
    if ($entry.Alias -match "Host-Only|VMnet|vEthernet|VirtualBox|VMware|Hyper-V") {
        $marker = "  ←  VM network (use this)"
    }
    Write-Host "     [$index] $($entry.IP)  ($($entry.Alias))$marker" -ForegroundColor $White
    $index++
}

# Try to auto-detect the best one
$vmIp = $null
foreach ($entry in $foundIps) {
    if ($entry.Alias -match "Host-Only|VMnet1") {
        $vmIp = $entry.IP
        break
    }
}
if (-not $vmIp -and $foundIps.Count -gt 0) {
    # Fallback: first non-loopback that isn't physical/WSL/vEthernet
    foreach ($entry in $foundIps) {
        if ($entry.Alias -notmatch "Wi-Fi|Ethernet\b|Bluetooth|vEthernet|WSL") {
            $vmIp = $entry.IP
            break
        }
    }
}
if (-not $vmIp -and $foundIps.Count -gt 0) {
    $vmIp = $foundIps[0].IP
    Write-Warn "Could not identify a VM network adapter. Guessing: $vmIp"
    Write-Info "Verify this IP is reachable from the VM. If not, run 'ipconfig' and"
    Write-Info "look for 'Host-Only Network' or 'VMnet1', then pass that IP manually."
}

if ($vmIp) {
    Write-Host ""
    Write-Bold "   Detected VM-facing IP: $vmIp"
    Write-Info "Use this IP when running setup-vm-target.ps1 on the VM:"
    Write-Bold "       .\scripts\setup-vm-target.ps1 -HostIP $vmIp"
} else {
    Write-Warn "Could not auto-detect VM network IP. Run 'ipconfig' and look for:"
    Write-Info "  - VirtualBox Host-Only Network"
    Write-Info "  - VMware Network Adapter VMnet1"
    Write-Info "  - vEthernet (Default Switch)"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.6: INSTALL AI SOC PLATFORM
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.6 — AI SOC PLATFORM INSTALL"

Push-Location $AiSocDir

# Create venv if needed
$venvPython = Join-Path $VenvPath "Scripts\python.exe"
if (Test-Path $venvPython) {
    Write-OK "Virtual environment already exists: $VenvPath"
} else {
    Write-Info "Creating virtual environment at $VenvPath ..."
    python -m venv $VenvPath
    Write-OK "Virtual environment created"
}

# Pip install (using venv's pip directly — no activation needed)
Write-Info "Installing / upgrading ai-soc-platform in editable mode ..."
$pipResult = & "$VenvPath\Scripts\pip.exe" install -e ".[dev]" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "pip install failed."
    Write-Host $pipResult
    Pop-Location
    exit 1
}
Write-OK "aisoc package installed (editable mode)"

# Configure .env
$envExample = Join-Path $AiSocDir ".env.example"
if (Test-Path $EnvFile) {
    Write-OK ".env file already exists — checking contents ..."
    $envContent = Get-Content $EnvFile -Raw
    if ($envContent -notmatch "AISOC_INDEXER_PASSWORD=$IndexerPassword") {
        Write-Warn ".env password may not match. Double-check AISOC_INDEXER_PASSWORD."
    }
    if ($envContent -notmatch "AISOC_OLLAMA_MODEL=$OllamaModel") {
        Write-Warn ".env model may not match. Double-check AISOC_OLLAMA_MODEL."
    }
} else {
    if (Test-Path $envExample) {
        Write-Info "Creating .env from .env.example ..."
        $envTemplate = Get-Content $envExample -Raw
        $envTemplate = $envTemplate -replace 'AISOC_INDEXER_PASSWORD=.*', "AISOC_INDEXER_PASSWORD=$IndexerPassword"
        $envTemplate = $envTemplate -replace 'AISOC_OLLAMA_MODEL=.*', "AISOC_OLLAMA_MODEL=$OllamaModel"
        $envTemplate = $envTemplate -replace 'AISOC_OLLAMA_URL=.*', "AISOC_OLLAMA_URL=http://localhost:11434"
        $envTemplate = $envTemplate -replace 'AISOC_INDEXER_URL=.*', "AISOC_INDEXER_URL=$IndexerUrl"
        $envTemplate = $envTemplate -replace 'AISOC_INDEXER_VERIFY_CERTS=.*', "AISOC_INDEXER_VERIFY_CERTS=false"
        Set-Content -Path $EnvFile -Value $envTemplate -Encoding ASCII
        Write-OK ".env created with defaults"
    } else {
        Write-Info ".env.example not found — creating minimal .env ..."
        @"
AISOC_INDEXER_URL=$IndexerUrl
AISOC_INDEXER_USER=admin
AISOC_INDEXER_PASSWORD=$IndexerPassword
AISOC_INDEXER_VERIFY_CERTS=false
AISOC_OLLAMA_URL=http://localhost:11434
AISOC_OLLAMA_MODEL=$OllamaModel
AISOC_API_BASE_URL=http://localhost:8000
"@ | Set-Content -Path $EnvFile -Encoding ASCII
        Write-OK "Minimal .env created"
    }
}

# Ensure labels.csv exists
if (Test-Path $LabelsCsv) {
    Write-OK "labels.csv exists"
} else {
    Write-Info "Creating empty labels.csv ..."
    "start_utc,end_utc,host,technique_id,test_number,notes" | Out-File -FilePath $LabelsCsv -Encoding ascii
    Write-OK "labels.csv created (empty — add rows after each ART run)"
}

Pop-Location

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.7: VERIFY OLLAMA
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.7 — OLLAMA (LLM COPILOT)"

if ($SkipOllama) {
    Write-Warn "-SkipOllama set. Copilot features will not work without Ollama."
} elseif (Test-CommandExists "ollama") {
    $ollamaVer = ollama --version 2>&1
    Write-OK "Ollama found: $($ollamaVer.Trim())"

    # Check if the model is already pulled
    $modelList = ollama list 2>&1
    if ($modelList -match $OllamaModel) {
        Write-OK "Model '$OllamaModel' already pulled"
    } else {
        Write-Info "Pulling model '$OllamaModel' (~4 GB, may take several minutes) ..."
        ollama pull $OllamaModel 2>&1 | ForEach-Object {
            if ($_ -match "pulling|verifying|writing|success") {
                Write-Info "  $_"
            }
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Ollama pull may have had issues. Try manually: ollama pull $OllamaModel"
        } else {
            Write-OK "Model '$OllamaModel' pulled successfully"
        }
    }
} else {
    Write-Warn "Ollama is not installed. The LLM copilot will not work."
    Write-Info "Install it: winget install Ollama.Ollama"
    Write-Info "Then: ollama pull $OllamaModel"
    Write-Info "Or re-run with -SkipOllama to suppress this warning."
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1.8: VERIFY FULL HOST STACK
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "1.8 — FULL STACK VERIFICATION"

Push-Location $AiSocDir

Write-Info "Testing Python ↔ Indexer connection ..."
$testScript = @"
import sys
sys.path.insert(0, r'$AiSocDir\src')
from aisoc.ingestion.indexer_client import IndexerClient
c = IndexerClient()
status = c.cluster_status()
print(f"CLUSTER_OK|{status.get('cluster_name','?')}|{status.get('status','?')}|nodes={status.get('number_of_nodes','?')}")
"@

$testResult = & "$VenvPath\Scripts\python.exe" -c $testScript 2>&1
if ($testResult -match "CLUSTER_OK") {
    Write-OK "Python can query the indexer: $testResult"
} else {
    Write-Err "Python cannot reach the indexer."
    if ($testResult -match "ConnectionRefused|ConnectionError") {
        Write-Info "The indexer is not running or not reachable at $IndexerUrl"
        Write-Info "Check: docker ps"
    } elseif ($testResult -match "Authentication|unauthorized|401") {
        Write-Info "Authentication failed. Check AISOC_INDEXER_PASSWORD in .env"
    } else {
        Write-Info "Error: $testResult"
    }
}

# Count events in archives
Write-Info "Counting events in wazuh-archives-* ..."
$eventCount = curl.exe -k -s -u "admin:$IndexerPassword" "$IndexerUrl/wazuh-archives-*/_count" 2>$null | ConvertFrom-Json
if ($eventCount -and $eventCount.count) {
    Write-OK "Archives index contains $($eventCount.count) events"
} else {
    Write-Info "Archives index is empty or not yet created. Events will appear once a VM agent connects."
}

Pop-Location

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3.2: TRAIN BASELINE MODEL
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "3.2 — BASELINE MODEL TRAINING"

if ($SkipTraining) {
    Write-Warn "-SkipTraining set. Skipping model training."
} else {
    Push-Location $AiSocDir

    Write-Info "Training baseline model (pulls events from the archives) ..."
    Write-Info "This may take a minute on a cold setup with few events."

    $trainResult = & "$VenvPath\Scripts\python.exe" scripts/train_model.py 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Model trained successfully"
        # Extract key stats
        $trainText = $trainResult -join "`n"
        if ($trainText -match "(\d+) windows") {
            Write-Info "  Training windows: $($Matches[1])"
        }
        if ($trainText -match "(\d+) process events") {
            Write-Info "  Process events: $($Matches[1])"
        }
        if ($trainText -match "(\d+) DNS events") {
            Write-Info "  DNS events: $($Matches[1])"
        }
        if ($trainText -match "(\d+) network events") {
            Write-Info "  Network events: $($Matches[1])"
        }

        # Cold start warning
        if ($trainText -match "Training Isolation Forest on (\d+) windows") {
            $windowCount = [int]$Matches[1]
            if ($windowCount -lt 5) {
                Write-Warn "Very few training windows ($windowCount). The model will be noisy."
                Write-Info "Let the VM run normal activity for 2+ hours, then re-run:"
                Write-Info "  python scripts/train_model.py --hours 24"
            }
        }
    } else {
        Write-Warn "Model training had issues (this may be normal for a cold start)."
        Write-Host ($trainResult -join "`n") -ForegroundColor $Gray
        Write-Info "Re-run manually once events are flowing:"
        Write-Info "  & $VenvPath\Scripts\Activate.ps1"
        Write-Info "  cd $AiSocDir"
        Write-Info "  python scripts/train_model.py --hours 24"
    }

    Pop-Location
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3.3: RUN DETECTION PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "3.3 — DETECTION PIPELINE"

if ($SkipTraining) {
    Write-Warn "-SkipTraining set. Skipping pipeline run."
} else {
    Push-Location $AiSocDir

    Write-Info "Running the detection pipeline ..."
    $pipelineResult = & "$VenvPath\Scripts\python.exe" scripts/run_pipeline.py 2>&1
    if ($LASTEXITCODE -eq 0) {
        $pipelineText = $pipelineResult -join "`n"
        if ($pipelineText -match "(\d+) alert(s?) emitted") {
            $alertCount = $Matches[1]
            if ($alertCount -eq "0") {
                Write-OK "Pipeline ran — 0 alerts emitted (expected for normal activity)"
            } else {
                Write-OK "Pipeline ran — $alertCount alert(s) emitted"
            }
        } else {
            Write-OK "Pipeline completed"
        }
    } else {
        Write-Warn "Pipeline had issues:"
        Write-Host ($pipelineResult -join "`n") -ForegroundColor $Gray
    }

    Pop-Location
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3.4: LAUNCH DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "3.4 — DASHBOARD"

if ($NoDashboard) {
    Write-Warn "-NoDashboard set. Dashboard not launched."
    Write-Info "Start it manually:"
    Write-Info "  & $VenvPath\Scripts\Activate.ps1"
    Write-Info "  cd $AiSocDir"
    Write-Info "  uvicorn aisoc.api.main:app --port 8000 --reload"
} else {
    Write-Info "Launching dashboard in a new terminal window ..."

    $launchCmd = @"
& '$VenvPath\Scripts\Activate.ps1' ; cd '$AiSocDir' ; Write-Host '' ; Write-Host '╔══════════════════════════════════════╗' -ForegroundColor Cyan ; Write-Host '║  AI SOC Dashboard — http://localhost:8000  ║' -ForegroundColor Cyan ; Write-Host '╚══════════════════════════════════════╝' -ForegroundColor Cyan ; Write-Host '' ; uvicorn aisoc.api.main:app --port 8000 --reload
"@

    Start-Process powershell -ArgumentList "-NoExit", "-Command", $launchCmd
    Write-OK "Dashboard launching at http://localhost:8000"
    Write-Info "Close the terminal window to stop the dashboard."
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

$elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " HOST SETUP COMPLETE  ($elapsed s)      " -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

Write-Host "Services:" -ForegroundColor $White

# Wazuh Docker check
if (-not $SkipDocker) {
    $running = (docker ps --filter "name=wazuh" --format "{{.Names}}" 2>$null)
    $expected = @("wazuh.manager", "wazuh.indexer", "wazuh.dashboard")
    foreach ($svc in $expected) {
        if ($running -like "*$svc*") { Write-Host "   ✓  $svc" -ForegroundColor $Green }
        else                          { Write-Host "   ✗  $svc" -ForegroundColor $Yellow }
    }
} else {
    Write-Host "   ?  Wazuh Docker (skipped)" -ForegroundColor $Gray
}

# Python venv
if (Test-Path $venvPython) { Write-Host "   ✓  Python venv ($VenvPath)" -ForegroundColor $Green }
else                       { Write-Host "   ✗  Python venv" -ForegroundColor $Yellow }

# .env
if (Test-Path $EnvFile)    { Write-Host "   ✓  .env configured" -ForegroundColor $Green }
else                       { Write-Host "   ✗  .env missing" -ForegroundColor $Yellow }

# Ollama
if ((Test-CommandExists "ollama") -and (ollama list 2>&1) -match $OllamaModel) {
    Write-Host "   ✓  Ollama ($OllamaModel)" -ForegroundColor $Green
} elseif (Test-CommandExists "ollama") {
    Write-Host "   ⚠  Ollama installed but model not pulled" -ForegroundColor $Yellow
} else {
    Write-Host "   ✗  Ollama not installed" -ForegroundColor $Yellow
}

# Firewall
if ((Get-NetFirewallRule -DisplayName "Wazuh Agent (1514)" -ErrorAction SilentlyContinue)) {
    Write-Host "   ✓  Firewall (TCP 1514)" -ForegroundColor $Green
} else {
    Write-Host "   ⚠  Firewall rule missing (port 1514)" -ForegroundColor $Yellow
}

Write-Host ""
Write-Host "Key URLs:" -ForegroundColor $White
Write-Host "   AI SOC Dashboard : http://localhost:8000"        -ForegroundColor $Cyan
Write-Host "   Wazuh Dashboard  : https://localhost"              -ForegroundColor $Cyan
Write-Host "   Indexer API      : $IndexerUrl"                    -ForegroundColor $Cyan

if ($vmIp) {
    Write-Host ""
    Write-Host "Provision the VM with:" -ForegroundColor $White
    Write-Bold "   .\scripts\setup-vm-target.ps1 -HostIP $vmIp"
}

Write-Host ""
Write-Host "When the VM sends its first events:" -ForegroundColor $White
Write-Host "   1. Re-run: python scripts/train_model.py --hours 24"
Write-Host "   2. Run:    python scripts/run_pipeline.py"
Write-Host "   3. Visit:  http://localhost:8000"
Write-Host "   4. Run an ART technique on the VM, then:"
Write-Host "      python scripts/evaluate.py"
Write-Host ""
