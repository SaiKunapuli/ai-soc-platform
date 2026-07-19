<#
.SYNOPSIS
    One-command VM provisioning for the AI SOC split-VM lab.
    Installs Sysmon, the Wazuh agent (pointed at your host), and Atomic Red Team
    on a fresh Windows VM — everything needed to run attacks and ship telemetry.

.DESCRIPTION
    Run this on a fresh Windows 10/11 VM (elevated PowerShell). It performs,
    in order, exactly the steps from docs/VM_DEPLOYMENT_GUIDE.md Phase 2:

      2.1  Verify network connectivity to the host
      2.2  Install Sysmon (Sysinternals + SwiftOnSecurity config)
      2.3  Install the Wazuh agent (downloads MSI, silent install)
      2.4  Configure the agent to collect the Sysmon event channel
      2.5  Verify the agent is running and check connectivity to Wazuh manager
      2.6  Generate noise events to confirm end-to-end telemetry
      2.7  Install Atomic Red Team (Invoke-AtomicRedTeam + atomics)
      2.8  Print snapshot reminder (VM snapshot must be done in hypervisor)

    Every step is idempotent — re-running the script is safe.

.PARAMETER HostIP
    The IPv4 address of the host machine running Wazuh Docker.
    The Wazuh agent will ship events to this IP on port 1514.

.PARAMETER WazuhAgentUrl
    Direct download URL for the Wazuh Windows agent MSI.
    Must match the Wazuh manager version (default: 4.14.6).
    Find the correct URL at:
      https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html

.PARAMETER AtomicsPath
    Where to install the Atomic Red Team technique definitions.
    Default: C:\AtomicRedTeam\atomics

.PARAMETER SkipSysmon
    Skip Sysmon installation (useful if Sysmon is already configured).

.PARAMETER SkipArt
    Skip Atomic Red Team installation.

.EXAMPLE
    # Full install — all you need is the host IP:
    .\scripts\setup-vm-target.ps1 -HostIP 192.168.56.1

.EXAMPLE
    # Skip ART, custom agent version:
    .\scripts\setup-vm-target.ps1 -HostIP 192.168.56.1 -SkipArt `
        -WazuhAgentUrl "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Host IP running Wazuh Docker (e.g. 192.168.56.1)")]
    [string]$HostIP,

    [Parameter(HelpMessage = "Wazuh agent MSI download URL")]
    [string]$WazuhAgentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi",

    [Parameter(HelpMessage = "ART atomics install path")]
    [string]$AtomicsPath = "C:\AtomicRedTeam\atomics",

    [Parameter(HelpMessage = "Wazuh manager port")]
    [int]$ManagerPort = 1514,

    [switch]$SkipSysmon,
    [switch]$SkipArt
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

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

function Test-ConnectionToHost {
    param([string]$Ip, [int]$TimeoutMs = 2000)
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($Ip, $TimeoutMs)
        return ($reply.Status -eq "Success")
    } catch { return $false }
}

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " AI SOC — VM Target Provisioning Script"   -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " Host IP      : $HostIP"                   -ForegroundColor $White
Write-Host " VM Hostname  : $env:COMPUTERNAME"          -ForegroundColor $White
Write-Host " Manager Port : $ManagerPort"                -ForegroundColor $White
Write-Host " Agent URL    : $WazuhAgentUrl"             -ForegroundColor $Gray
Write-Host " Atomics Path : $AtomicsPath"               -ForegroundColor $Gray
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# PREREQUISITES
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "PREREQUISITES"

if (-not (Test-Admin)) {
    Write-Err "This script must run ELEVATED (Run as Administrator)."
    Write-Info "Right-click PowerShell → Run as Administrator, then re-run."
    exit 1
}
Write-OK "Running as Administrator"

# ── Step 2.1: Verify network connectivity ────────────────────────────────────

Write-Step "2.1 — NETWORK CONNECTIVITY"

Write-Info "Checking ping to host ($HostIP) ..."
if (-not (Test-ConnectionToHost -Ip $HostIP)) {
    Write-Err "Cannot ping $HostIP."
    Write-Info "Check:"
    Write-Info "  1. VM network mode is Host-Only or Bridged (not NAT)"
    Write-Info "  2. Host firewall allows ICMP (or just continue — agent uses TCP 1514)"
    Write-Warn "Ping failed, but TCP 1514 may still work. Continuing..."
} else {
    Write-OK "Ping to $HostIP successful"
}

Write-Info "Checking TCP connectivity to Wazuh manager ($HostIP`:$ManagerPort) ..."
$tcpTest = Test-NetConnection -ComputerName $HostIP -Port $ManagerPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-OK "TCP $HostIP`:$ManagerPort is reachable — Wazuh manager port is open"
} else {
    Write-Warn "TCP $HostIP`:$ManagerPort is NOT reachable."
    Write-Info "The Wazuh agent will keep retrying. Ensure:"
    Write-Info "  1. Wazuh Docker is running on the host"
    Write-Info "  2. Host firewall has an inbound rule for port $ManagerPort"
    Write-Info "     (New-NetFirewallRule -DisplayName 'Wazuh Agent (1514)' -Direction Inbound -Protocol TCP -LocalPort 1514 -Action Allow)"
    Write-Info "Will continue — agent installation can proceed without connectivity."
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.2: SYSMON
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.2 — SYSMON INSTALLATION"

if ($SkipSysmon) {
    Write-Warn "-SkipSysmon flag set. Skipping Sysmon installation."
} elseif (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Write-OK "Sysmon64 service already exists — skipping install."
    $svc = Get-Service Sysmon64
    Write-Info "  Status: $($svc.Status)"
} else {
    Write-Info "Downloading Sysmon ..."
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    $sysmonDir = "$env:TEMP\Sysmon"
    $sysmonConfig = "$env:TEMP\sysmonconfig.xml"

    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                      -OutFile $sysmonZip -ErrorAction Stop
    Write-OK "Sysmon downloaded"

    if (Test-Path $sysmonDir) { Remove-Item -Recurse -Force $sysmonDir }
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
    Write-OK "Sysmon extracted"

    Write-Info "Downloading SwiftOnSecurity sysmon config ..."
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
                      -OutFile $sysmonConfig -ErrorAction Stop

    Write-Info "Installing Sysmon (this may take ~10 seconds) ..."
    $installResult = & "$sysmonDir\Sysmon64.exe" -accepteula -i $sysmonConfig 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Sysmon installation failed. Output:"
        Write-Host $installResult
        exit 1
    }
    Write-OK "Sysmon installed and running"

    # Clean up temp files
    Remove-Item $sysmonZip -Force -ErrorAction SilentlyContinue
    Remove-Item $sysmonDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $sysmonConfig -Force -ErrorAction SilentlyContinue
}

# Verify Sysmon is running
$sysmonSvc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-OK "Sysmon64 service: RUNNING"
} elseif ($sysmonSvc) {
    Write-Warn "Sysmon64 service is $($sysmonSvc.Status) — attempting to start ..."
    Start-Service Sysmon64
    Write-OK "Sysmon64 started"
} else {
    Write-Err "Sysmon64 service not found. Detection will be blind without it."
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.3: WAZUH AGENT
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.3 — WAZUH AGENT INSTALLATION"

$agentService = Get-Service Wazuh -ErrorAction SilentlyContinue

if ($agentService) {
    Write-OK "Wazuh agent service already exists — skipping install."

    # Check if the manager address needs updating
    $ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    if (Test-Path $ossecConf) {
        $currentConfig = Get-Content $ossecConf -Raw
        if ($currentConfig -notmatch [regex]::Escape("<address>$HostIP</address>")) {
            Write-Warn "Existing agent points to a different manager. Updating ossec.conf ..."
            $currentConfig = $currentConfig -replace '<address>.*?</address>', "<address>$HostIP</address>"
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($ossecConf, $currentConfig, $utf8NoBom)
            Restart-Service -Name Wazuh
            Write-OK "Manager address updated to $HostIP and agent restarted"
        } else {
            Write-OK "Manager address already set to $HostIP"
        }
    }
} else {
    Write-Info "Downloading Wazuh agent MSI ..."
    Write-Info "URL: $WazuhAgentUrl"
    $agentMsi = "$env:TEMP\wazuh-agent.msi"

    try {
        Invoke-WebRequest -Uri $WazuhAgentUrl -OutFile $agentMsi -ErrorAction Stop
        Write-OK "Agent MSI downloaded ($([math]::Round((Get-Item $agentMsi).Length / 1MB, 1)) MB)"
    } catch {
        Write-Err "Failed to download Wazuh agent from: $WazuhAgentUrl"
        Write-Info "Check the URL is correct for your Wazuh version at:"
        Write-Info "  https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html"
        Write-Info "Then re-run with: -WazuhAgentUrl '<correct-url>'"
        exit 1
    }

    Write-Info "Installing Wazuh agent (silent — may take 30 seconds) ..."
    Write-Info "  Manager: $HostIP"
    Write-Info "  Registration Server: $HostIP"

    $msiArgs = @(
        "/i", $agentMsi,
        "/q",
        "WAZUH_MANAGER=`"$HostIP`"",
        "WAZUH_REGISTRATION_SERVER=`"$HostIP`""
    )

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow -PassThru

    if ($proc.ExitCode -ne 0) {
        Write-Err "MSI install failed with exit code: $($proc.ExitCode)"
        Write-Info "Common causes: wrong MSI version, disk full, or existing agent remnants."
        exit 1
    }
    Write-OK "Wazuh agent installed"

    # Clean up
    Remove-Item $agentMsi -Force -ErrorAction SilentlyContinue
}

# Verify agent service
$agentSvc = Get-Service Wazuh -ErrorAction SilentlyContinue
if ($agentSvc -and $agentSvc.Status -eq "Running") {
    Write-OK "Wazuh agent service: RUNNING"
} elseif ($agentSvc) {
    Write-Warn "Wazuh agent is $($agentSvc.Status) — attempting to start ..."
    Start-Service Wazuh
    Start-Sleep -Seconds 3
    $agentSvc.Refresh()
    if ($agentSvc.Status -eq "Running") {
        Write-OK "Wazuh agent started"
    } else {
        Write-Err "Wazuh agent failed to start. Check:"
        Write-Info "  Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 30"
    }
} else {
    Write-Err "Wazuh agent service not found after install."
    exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.4: CONFIGURE SYSMON EVENT CHANNEL
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.4 — SYSMON EVENT CHANNEL CONFIGURATION"

$ossecConfPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

if (-not (Test-Path $ossecConfPath)) {
    Write-Err "ossec.conf not found at: $ossecConfPath"
    Write-Info "Agent installation may have failed or used a non-standard path."
    exit 1
}

$ossecConfig = Get-Content $ossecConfPath -Raw

$sysmonBlock = @"
  <!-- Sysmon Event Channel -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

if ($ossecConfig -match 'Microsoft-Windows-Sysmon/Operational') {
    Write-OK "Sysmon event channel already configured in ossec.conf"
} else {
    Write-Info "Adding Sysmon event channel to ossec.conf ..."

    # Insert the Sysmon block before the closing </ossec_config> tag
    $ossecConfig = $ossecConfig -replace '(?=</ossec_config>)', "$sysmonBlock`r`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($ossecConfPath, $ossecConfig, $utf8NoBom)
    Write-OK "Sysmon event channel added"

    Write-Info "Restarting Wazuh agent to pick up new config ..."
    Restart-Service -Name Wazuh
    Start-Sleep -Seconds 5

    $agentSvc.Refresh()
    if ($agentSvc.Status -eq "Running") {
        Write-OK "Wazuh agent restarted successfully"
    } else {
        Write-Err "Wazuh agent failed to restart after config change."
        Write-Info "Check ossec.conf for XML errors: notepad '$ossecConfPath'"
        Write-Info "Then manually restart: Restart-Service -Name Wazuh"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.5: VERIFY AGENT CONNECTIVITY
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.5 — AGENT-MANAGER CONNECTIVITY CHECK"

# Re-check TCP
$tcpRetest = Test-NetConnection -ComputerName $HostIP -Port $ManagerPort `
                                 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

if ($tcpRetest.TcpTestSucceeded) {
    Write-OK "Agent can reach Wazuh manager at $HostIP`:$ManagerPort"
} else {
    Write-Warn "Still cannot reach Wazuh manager at $HostIP`:$ManagerPort"
    Write-Info "The agent will retry. Once the host is ready, check the Wazuh Dashboard"
    Write-Info "at https://$HostIP → Agents — this VM should appear as 'Active'."
}

Write-Info "Checking agent log for recent activity ..."
$agentLog = "C:\Program Files (x86)\ossec-agent\ossec.log"
if (Test-Path $agentLog) {
    $recentLines = Get-Content $agentLog -Tail 5 -ErrorAction SilentlyContinue
    if ($recentLines) {
        Write-Info "Last 5 lines of ossec.log:"
        foreach ($line in $recentLines) {
            Write-Host "     $line" -ForegroundColor $Gray
        }
    }
}

Write-Info "Make note of this VM's hostname for labels.csv:"
Write-Bold "     $env:COMPUTERNAME"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.6: GENERATE NOISE EVENTS
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.6 — TELEMETRY SMOKE TEST"

Write-Info "Generating test events so you can verify end-to-end on the host ..."
Write-Info "Running: whoami, systeminfo (truncated), Get-Process sample"

whoami /all 2>&1 | Out-Null
systeminfo 2>&1 | Select-Object -First 5 | Out-Null
Get-Process | Select-Object -First 15 Name, Id, CPU | Format-Table -AutoSize

Write-Info "On the HOST, wait 30–60 seconds, then run:"
Write-Bold "     curl.exe -k -u admin:SecretPassword 'https://localhost:9200/wazuh-archives-*/_search?size=3&pretty'"
Write-Info "You should see events with agent.name = '$env:COMPUTERNAME'"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.7: ATOMIC RED TEAM
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.7 — ATOMIC RED TEAM INSTALLATION"

if ($SkipArt) {
    Write-Warn "-SkipArt flag set. Skipping Atomic Red Team installation."
} elseif (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-OK "Invoke-AtomicTest already available — skipping install."
} else {
    Write-Info "Installing invoke-atomicredteam module (from PowerShell Gallery) ..."
    try {
        Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force -ErrorAction Stop
        Write-OK "invoke-atomicredteam module installed"
    } catch {
        Write-Err "Failed to install invoke-atomicredteam module."
        Write-Info "Manual install:"
        Write-Info "  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)"
        Write-Info "  Install-AtomicRedTeam -getAtomics"
        Write-Warn "Continuing — you can install ART manually later."
    }
}

# Download atomics (technique definitions)
if (-not $SkipArt) {
    Import-Module invoke-atomicredteam -Force -ErrorAction SilentlyContinue

    $artInstalled = Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue
    if ($artInstalled) {
        if (Test-Path $AtomicsPath) {
            Write-OK "Atomics already downloaded at: $AtomicsPath"
        } else {
            Write-Info "Downloading Atomic Red Team technique definitions ..."
            Write-Info "Destination: $AtomicsPath"
            Write-Info "(~200 MB — may take 1–3 minutes)"

            try {
                Install-AtomicRedTeam -getAtomics -Force -ErrorAction Stop
                Write-OK "Atomics downloaded"
            } catch {
                Write-Warn "Atomics download had issues. Try manually:"
                Write-Info "  Import-Module invoke-atomicredteam -Force"
                Write-Info "  Install-AtomicRedTeam -getAtomics -Force"
            }
        }
    }
}

# Verify ART works
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Import-Module invoke-atomicredteam -Force -ErrorAction SilentlyContinue
    Write-Info "Testing ART — showing T1059.001 details ..."
    try {
        Invoke-AtomicTest T1059.001 -ShowDetails 2>&1 | Select-Object -First 8 | Out-Null
        Write-OK "Atomic Red Team is ready"
    } catch {
        Write-Warn "ART module loaded but -ShowDetails had an issue."
        Write-Info "Try manually: Import-Module invoke-atomicredteam -Force; Invoke-AtomicTest T1059.001 -ShowDetails"
    }
} elseif (-not $SkipArt) {
    Write-Warn "Invoke-AtomicTest still not available after install attempt."
    Write-Info "This may be a PowerShell Gallery / TLS issue. Manual install:"
    Write-Info "  1. Open fresh elevated PowerShell"
    Write-Info "  2. [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
    Write-Info "  3. IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)"
    Write-Info "  4. Install-AtomicRedTeam -getAtomics -Force"
}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2.8: SNAPSHOT REMINDER
# ══════════════════════════════════════════════════════════════════════════════

Write-Step "2.8 — SNAPSHOT"

Write-Host ""
Write-Host "   ╔══════════════════════════════════════════════════════════╗" -ForegroundColor $Yellow
Write-Host "   ║   ⚠  TAKE A VM SNAPSHOT NOW                              ║" -ForegroundColor $Yellow
Write-Host "   ║                                                          ║" -ForegroundColor $Yellow
Write-Host "   ║   In your hypervisor (Hyper-V / VMware / VirtualBox):    ║" -ForegroundColor $Yellow
Write-Host "   ║   Take a snapshot named:                                 ║" -ForegroundColor $Yellow
Write-Host "   ║                                                          ║" -ForegroundColor $Yellow
Write-Host "   ║   'Clean Baseline — Sysmon + Wazuh Agent + ART'          ║" -ForegroundColor $Yellow
Write-Host "   ║                                                          ║" -ForegroundColor $Yellow
Write-Host "   ║   Revert to this snapshot before EVERY ART run to        ║" -ForegroundColor $Yellow
Write-Host "   ║   keep your baseline clean and labels honest.            ║" -ForegroundColor $Yellow
Write-Host "   ╚══════════════════════════════════════════════════════════╝" -ForegroundColor $Yellow
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

$elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 1)

Write-Host "========================================" -ForegroundColor $Cyan
Write-Host " PROVISIONING COMPLETE  ($elapsed s)    " -ForegroundColor $Cyan
Write-Host "========================================" -ForegroundColor $Cyan
Write-Host ""

Write-Host "Installed components:" -ForegroundColor $White
$checklist = @(
    @{ Name = "Sysmon64";              Check = [bool](Get-Service Sysmon64 -ErrorAction SilentlyContinue) },
    @{ Name = "Wazuh Agent";           Check = [bool](Get-Service Wazuh -ErrorAction SilentlyContinue) },
    @{ Name = "Sysmon Event Channel";  Check = ($ossecConfig -match [regex]::Escape("Microsoft-Windows-Sysmon/Operational")) },
    @{ Name = "Atomic Red Team";       Check = [bool](Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) },
    @{ Name = "ART Atomics";           Check = (Test-Path $AtomicsPath) }
)

foreach ($item in $checklist) {
    $icon = if ($item.Check) { "✓" } else { "✗" }
    $color = if ($item.Check) { $Green } else { $Yellow }
    Write-Host "   $icon  $($item.Name)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Key info for the host side:" -ForegroundColor $White
Write-Host "   VM hostname for labels.csv : $env:COMPUTERNAME" -ForegroundColor $Cyan
Write-Host "   Agent ships to              : $HostIP`:$ManagerPort" -ForegroundColor $Cyan
Write-Host "   Wazuh Dashboard             : https://$HostIP" -ForegroundColor $Cyan
Write-Host ""
Write-Host "Next steps on the HOST:" -ForegroundColor $White
Write-Host "   1. Check Wazuh Dashboard → Agents → this VM is 'Active'"
Write-Host "   2. python scripts/train_model.py         (learn baseline)"
Write-Host "   3. python scripts/run_pipeline.py        (score + alert)"
Write-Host "   4. Start the dashboard at http://localhost:8000"
Write-Host ""
Write-Host "Next steps on THIS VM:" -ForegroundColor $White
Write-Host "   1. TAKE THE SNAPSHOT (see above)"
Write-Host "   2. Run a test attack:"
Write-Host "      Import-Module invoke-atomicredteam -Force"
Write-Host "      Invoke-AtomicTest T1059.001 -ShowDetails"
Write-Host "      Invoke-AtomicTest T1059.001 -TestNumbers 1"
Write-Host "   3. Cleanup: Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup"
Write-Host "   4. Revert to snapshot before the next run"
Write-Host ""
