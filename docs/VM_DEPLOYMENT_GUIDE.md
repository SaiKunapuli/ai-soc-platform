# Split-VM Deployment Guide — AI SOC Platform

*A step-by-step guide to deploying the AI SOC detection platform against a Windows
VM running Atomic Red Team. Each step has a "✅ Expected Result" so you always know
if you're on the right track.*

---

## Architecture

```
┌──────────────────────────────────┐      ┌──────────────────────────────────────┐
│       WINDOWS VM (TARGET)        │      │            YOUR HOST                  │
│                                  │ TCP  │                                      │
│  Sysmon ──┐                      │ 1514 │  ┌────────────────────────────────┐  │
│           ├── Wazuh Agent ───────┼──────┼──► wazuh.manager (Docker)         │  │
│  Windows ─┘                      │      │  │  · rule alerts                  │  │
│           Event Logs             │      │  │  · archives (all events)    │  │
│                                  │      │  └───────────┬────────────────────┘  │
│  Atomic Red Team                 │      │              │                       │
│  (Invoke-AtomicTest)             │      │              ▼                       │
│                                  │      │  ┌────────────────────────────────┐  │
│   IP: 192.168.56.101             │      │  │ wazuh.indexer (OpenSearch)      │  │
│   (host-only network)            │      │  │  port 9200                      │  │
└──────────────────────────────────┘      │  └───────────┬────────────────────┘  │
                                          │              │ localhost:9200        │
                                          │              ▼                       │
                                          │  ┌────────────────────────────────┐  │
                                          │  │ ai-soc-platform (Python)        │  │
                                          │  │  · ingestion → features → ML    │  │
                                          │  │  · fusion → alerts → SQLite     │  │
                                          │  │  · FastAPI dashboard            │  │
                                          │  └────────────────────────────────┘  │
                                          │                                      │
                                          │  IP: 192.168.56.1 (host-only)        │
                                          └──────────────────────────────────────┘
```

---

## Prerequisites

| What | Where | Minimum |
|------|-------|---------|
| Docker Desktop + WSL2 | Host | Running |
| 8 GB free RAM | Host | For Wazuh Docker |
| Python 3.11+ | Host | `python --version` |
| Windows 10/11 VM | Hyper-V / VMware / VirtualBox | 4 GB RAM, 2 CPUs |
| Network between VM and host | Hypervisor setting | Ping works both ways |
| Host-only or Bridged network | Hypervisor setting | Static or known IPs |

> **Snapshot everything.** Before installing anything on the VM, take a snapshot.
> Before every ART run, revert to a clean snapshot. This keeps your baseline clean
> and your labels honest.

---

## Phase 1: Host Setup — Wazuh Docker + AI Platform

### Step 1.1: Start the Wazuh Docker stack

```powershell
# Open PowerShell on your HOST

# 1. Increase vm.max_map_count (required for OpenSearch)
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

> **⚠️ IMPORTANT — Reboot note:** After every host reboot, you must re-run the
> `sysctl` command above before starting Wazuh. Without it, the indexer will crash.
> To make it permanent, add to `%UserProfile%\.wslconfig`:
> ```
> [wsl2]
> kernelCommandLine = "sysctl.vm.max_map_count=262144"
> ```

```powershell
# 2. Navigate to the Wazuh Docker directory
cd C:\Projects\SOC\wazuh-docker\single-node

# 3. Generate certs (ONE TIME only)
docker compose -f generate-indexer-certs.yml run --rm generator

# 4. Start the stack (first run downloads ~2GB of Docker images)
docker compose up -d
```

**✅ Expected Result:**
```
[+] Running 4/4
 ✔ Container single-node-wazuh.indexer-1   Started
 ✔ Container single-node-wazuh.manager-1   Started
 ✔ Container single-node-wazuh.dashboard-1 Started
```

> ⏱️ First launch takes 2–5 minutes (Docker pulls ~2GB of images, then the indexer
> bootstraps). Subsequent starts take ~30 seconds.

### Step 1.2: Verify the stack is healthy

```powershell
# Check all containers are running
docker ps --format "table {{.Names}}\t{{.Status}}"

# Check indexer health
curl.exe -k -u admin:SecretPassword "https://localhost:9200/_cluster/health?pretty"
```

**✅ Expected Result:**
```
NAMES                                   STATUS
single-node-wazuh.manager-1             Up 2 minutes
single-node-wazuh.indexer-1             Up 2 minutes
single-node-wazuh.dashboard-1           Up 2 minutes
```

```json
{
  "cluster_name" : "wazuh-indexer",
  "status" : "green",
  ...
}
```

> If status is `yellow`: wait 60 seconds and retry — the indexer is still bootstrapping.
> If status is `red` or the command fails: check Docker Desktop is running with WSL2.

### Step 1.3: Enable the archives index (REQUIRED for ML)

The ML layer needs **all** events, not just rule matches. By default, Wazuh only
indexes events that matched a rule.

> **Better approach — edit the mounted config file on the host** (survives
> container rebuilds):
>
> 1. Open `wazuh-docker\single-node\config\wazuh_cluster\wazuh_manager.conf`
> 2. Find the existing `<global>` section inside `<ossec_config>`
> 3. Add `<logall_json>yes</logall_json>` inside it:
> ```xml
> <ossec_config>
>   <global>
>     <logall_json>yes</logall_json>
>     ...existing entries...
>   </global>
>   ...
> </ossec_config>
> ```
> 4. If there's no `<global>` section, add one inside `<ossec_config>`
> 5. Restart the stack: `docker compose restart wazuh.manager`

**Quick method — edit inside the running container** (must redo after rebuilds):

```powershell
# Exec into the manager container
docker exec -it single-node-wazuh.manager-1 bash

# Add logall_json inside the existing <global> block
sed -i 's|<global>|<global>\n    <logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf

# Verify it was added
grep -A2 '<global>' /var/ossec/etc/ossec.conf

# Restart the manager
/var/ossec/bin/wazuh-control restart

# Exit the container
exit
```

**✅ Expected Result (after restart):**
```
Killing wazuh-modulesd...   [OK]
Killing wazuh-analysisd...  [OK]
...
Starting wazuh-analysisd... [OK]
Starting wazuh-modulesd...  [OK]
Completed.
```

### Step 1.4: Open the firewall for the VM

The Wazuh agent on the VM sends events to port 1514 on your host. Windows Firewall
blocks this by default.

```powershell
# Run elevated (Administrator) on the HOST
New-NetFirewallRule `
  -DisplayName "Wazuh Agent (1514)" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 1514 `
  -Action Allow `
  -Profile Any

# Verify the rule was created
Get-NetFirewallRule -DisplayName "Wazuh Agent (1514)" | Format-Table DisplayName, Enabled, Action
```

**✅ Expected Result:**
```
DisplayName            Enabled Action
-----------            ------- ------
Wazuh Agent (1514)     True    Allow
```

### Step 1.5: Note your host IP on the VM's network

```powershell
# On the HOST
ipconfig

# Look for the adapter that corresponds to your VM network:
#   Hyper-V: "vEthernet (Default Switch)" or your custom switch
#   VMware:  "VMware Network Adapter VMnet1" (Host-only)
#   VirtualBox: "VirtualBox Host-Only Network"

# NOTE THE IPv4 ADDRESS — you'll need it for Step 2.3
# Example: 192.168.56.1
```

**✅ Expected Result:**
```
Ethernet adapter VirtualBox Host-Only Network:

   IPv4 Address. . . . . . . . . : 192.168.56.1
   Subnet Mask . . . . . . . . . : 255.255.255.0
```

> **Write this IP down:** `HOST_IP = ____________`

### Step 1.6: Install the AI SOC platform

```powershell
# On the HOST
cd C:\Projects\SOC\ai-soc-platform

# Create virtualenv OUTSIDE OneDrive (avoids sync conflicts)
python -m venv $env:LOCALAPPDATA\venvs\aisoc
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1

# Install the package
pip install -e ".[dev]"

# Configure .env
copy .env.example .env

# Edit .env — set the indexer password to match docker-compose.yml
# AISOC_INDEXER_PASSWORD=SecretPassword
notepad .env
```

**✅ Expected Result:**
```
Successfully installed aisoc-0.1.0 ...
```

> Your `.env` should contain:
> ```
> AISOC_INDEXER_URL=https://localhost:9200
> AISOC_INDEXER_USER=admin
> AISOC_INDEXER_PASSWORD=SecretPassword
> AISOC_INDEXER_VERIFY_CERTS=false
> AISOC_OLLAMA_URL=http://localhost:11434
> AISOC_OLLAMA_MODEL=qwen2.5:7b-instruct
> ```

### Step 1.7: Install and start Ollama (LLM copilot)

```powershell
# On the HOST — install if not already present:
winget install Ollama.Ollama

# (If winget isn't available, download the installer from https://ollama.com)

# Verify the install
ollama --version

# Pull the model (first time ~4 GB download, takes several minutes)
ollama pull qwen2.5:7b-instruct

# Verify it works
ollama run qwen2.5:7b-instruct "Say 'AI SOC copilot is ready.'"
```

**✅ Expected Result:**
```
ollama version 0.x.x
pulling manifest ...
verifying sha256 digest ...
writing manifest ...
success

>>> AI SOC copilot is ready.
```

### Step 1.8: Verify the full host stack

```powershell
# On the HOST — test the Python pipeline can talk to the indexer
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1
cd C:\Projects\SOC\ai-soc-platform
python -c "from aisoc.ingestion.indexer_client import IndexerClient; c = IndexerClient(); print('Cluster:', c.cluster_status())"
```

**✅ Expected Result:**
```
Cluster: {'cluster_name': 'wazuh-indexer', 'status': 'green', ...}
```

> If you get `ConnectionRefusedError` or `AuthenticationException`: double-check
> `.env` has the right password (default: `SecretPassword`) and Docker is running.

### ✅ Phase 1 Complete

You now have:
- Wazuh Docker stack running on your host (manager + indexer + dashboard)
- Archives index enabled (all events stored)
- Firewall open for the VM's agent
- AI SOC platform installed and able to talk to the indexer
- Ollama running with the LLM model

---

## Phase 2: VM Setup — Windows Target + Sensors + ART

> **Before starting:** Take a VM snapshot. Name it "Clean — Before Setup."

### Step 2.1: Verify network connectivity

```powershell
# On the VM (PowerShell)
ipconfig

# Confirm the VM has an IP on the same network as the host
# Example: 192.168.56.101 (host is 192.168.56.1)

# Ping the host
ping 192.168.56.1
```

**✅ Expected Result:**
```
Pinging 192.168.56.1 with 32 bytes of data:
Reply from 192.168.56.1: bytes=32 time<1ms TTL=128
Reply from 192.168.56.1: bytes=32 time<1ms TTL=128
```

> If ping fails: check your hypervisor's network settings. Host-only or Bridged
> mode is required. NAT mode may not route correctly.

### Step 2.2: Install Sysmon

```powershell
# On the VM (elevated PowerShell)

# Download Sysmon + the community config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"

# Install Sysmon
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"

# Verify Sysmon is running
Get-Service Sysmon64
```

**✅ Expected Result:**
```
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.   [OK]
Starting Sysmon64.    [OK]

Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           Sysmon64
```

### Step 2.3: Install the Wazuh Agent

```powershell
# On the VM (elevated PowerShell)

# 1. Find the correct MSI download URL for your manager's version
#    Go to: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
#    Click the MSI link for version 4.14.x and copy the URL
#
#    Example (verify this is the latest 4.14.x before using):
$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi"

# 2. Download it
Invoke-WebRequest -Uri $agentUrl -OutFile "$env:TEMP\wazuh-agent.msi"

# Install — REPLACE 192.168.56.1 WITH YOUR HOST IP from Step 1.5
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
  WAZUH_MANAGER="192.168.56.1" `
  WAZUH_REGISTRATION_SERVER="192.168.56.1"

# Verify the agent service is running
Get-Service Wazuh
```

**✅ Expected Result:**
```
Status   Name               DisplayName
------   ----               -----------
Running  Wazuh              Wazuh
```

### Step 2.4: Configure the agent to collect Sysmon events

```powershell
# On the VM (elevated PowerShell)

# Open the agent config
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Add this block INSIDE the <ossec_config> element (before the final </ossec_config>):
```

```xml
  <!-- Sysmon Event Channel -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

```powershell
# Save the file (Ctrl+S in Notepad), then close Notepad

# Restart the agent to pick up the new config
Restart-Service -Name Wazuh

# Verify the agent restarted
Get-Service Wazuh
```

**✅ Expected Result:**
```
Status   Name               DisplayName
------   ----               -----------
Running  Wazuh              Wazuh
```

### Step 2.5: Verify the agent connected to the manager

```powershell
# On the HOST — check the Wazuh dashboard
# Open a browser to: https://localhost

# Login: admin / SecretPassword
# Navigate to: Wazuh → Agents
```

**✅ Expected Result:**
- Your VM shows up as an agent with status **Active** (green dot)
- Wait up to 60 seconds after restarting the agent — it takes time to register

> If the agent shows "Disconnected" or doesn't appear:
> 1. On the VM: check `C:\Program Files (x86)\ossec-agent\ossec.log` for errors
> 2. On the host: verify firewall rule from Step 1.4 exists
> 3. On the VM: verify you can `telnet 192.168.56.1 1514` (or use `Test-NetConnection`)

### Step 2.6: Generate some test events to confirm end-to-end

```powershell
# On the VM (PowerShell — does NOT need elevation)
whoami /all
systeminfo
Get-Process | Select-Object -First 10 Name, Id

# On the HOST — wait 30 seconds, then query for events from the VM agent
curl.exe -k -u admin:SecretPassword "https://localhost:9200/wazuh-archives-*/_search?q=agent.name:*&size=3&pretty"
```

**✅ Expected Result:**
The curl command returns JSON with `"hits"` containing events. Look for your VM's
hostname in `agent.name`. You should see Sysmon process-creation events (Event ID 1).

```json
{
  "hits" : {
    "total" : { "value" : 3, ... },
    "hits" : [
      {
        "_source" : {
          "agent" : { "name" : "DESKTOP-XXXXX" },
          "data" : { "win" : { "system" : { "eventID" : "1" } } }
        }
      }
    ]
  }
}
```

> If you see 0 hits or no events: wait another 60 seconds for the filebeat pipeline.
> If still empty: check that Step 1.3 (archives) was done correctly.

### Step 2.7: Install Atomic Red Team

```powershell
# On the VM (elevated PowerShell)

# Install the module (free, no API key needed)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Download the atomics (technique definitions)
Install-AtomicRedTeam -getAtomics -Force

# Verify it's installed
Get-Command Invoke-AtomicTest

# Show a technique to confirm atomics are available
Invoke-AtomicTest T1059.001 -ShowDetails
```

**✅ Expected Result:**
```
CommandType     Name                 Version    Source
-----------     ----                 -------    ------
Function        Invoke-AtomicTest     ...        invoke-atomicredteam

[Showing details for T1059.001 — PowerShell]
  Test 1: Run PowerShell...
  Test 2: ...
...
```

### Step 2.8: SNAPSHOT — Clean Baseline

```powershell
# On the HYPERVISOR (Hyper-V Manager / VMware / VirtualBox)
# Take a snapshot of the VM
# Name it: "Clean Baseline — Sysmon + Wazuh Agent + ART Installed"

# This is your golden image. Revert to this before EVERY ART run.
```

**✅ Expected Result:**
Snapshot created. You can now revert to a clean state at any time.

### ✅ Phase 2 Complete

You now have:
- Windows VM with Sysmon collecting process, network, and DNS events
- Wazuh agent shipping events to your host
- Events flowing end-to-end: VM → Wazuh Agent → Manager → Indexer
- Atomic Red Team installed and ready to detonate
- A clean snapshot to revert to

---

## Phase 3: First Test Run — Smoke Test

This phase confirms the entire pipeline works before you run real attacks.

### Step 3.1: On the VM — make normal noise

```powershell
# On the VM
# Just use the machine normally for a few minutes:
#   Open programs, browse folders, run basic commands

# Or generate deliberate noise:
1..5 | ForEach-Object { Get-Process; Start-Sleep -Seconds 3 }
```

### Step 3.2: On the host — train the baseline model

```powershell
# On the HOST
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1
cd C:\Projects\SOC\ai-soc-platform

# Pull ~2 hours of events and train the ML model
python scripts/train_model.py
```

**✅ Expected Result (cold start — brand new setup):**
```
Fetching events from 2026-07-17T20:00:00Z to 2026-07-17T22:00:00Z
  process events: 23
  network events: 8
  DNS events:     15
Building features...
Training Isolation Forest on 1 windows...
Model saved to models/anomaly_detector.joblib
Baseline seeded with 1 scores
```

> **⚠️ Cold start warning:** A brand-new setup will have very few events (likely 0–3
> windows). That's normal. A model trained on <10 windows will produce unreliable,
> noisy scores. **Before running real ART tests**, let the VM run normal activity
> for at least 2–4 hours (or pass `--hours 24` to pull a wider window), then
> re-train. The evaluation metrics depend on having a meaningful baseline.

**✅ Expected Result (after accumulating a few hours of normal use):**
```
Fetching events from ... to ...
  process events: 1,234
  network events: 567
  DNS events:     890
Building features...
Training Isolation Forest on 12 windows...
Model saved to models/anomaly_detector.joblib
Baseline seeded with 12 scores
```

### Step 3.3: Run the detection pipeline

```powershell
# On the HOST
python scripts/run_pipeline.py
```

**✅ Expected Result:**
```
Fetching recent events...
Scoring 3 windows...
Fusing rule alerts + ML scores...
  0 alerts emitted (normal activity, no rules triggered)
```

> For normal activity with no attacks, you should see **0 alerts** (or only LOW/MEDIUM
> alerts from noisy but benign Wazuh rules). This is correct — the pipeline shouldn't
> scream on normal behavior.

### Step 3.4: Start the dashboard and view results

```powershell
# On the HOST (in a new terminal window)
# IMPORTANT: Run from the ai-soc-platform directory so the import paths resolve
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1
cd C:\Projects\SOC\ai-soc-platform

# Start the API server (--reload auto-restarts on code changes)
uvicorn aisoc.api.main:app --port 8000 --reload
```

**✅ Expected Result:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

Open `http://localhost:8000` in your browser.

**✅ Expected Result:**
- The "Mission Control" dashboard loads
- KPI counters display (may show 0 alerts if no attacks yet)
- The "Event Rate" chart animates with live data from the indexer
- "Threat Posture" ring shows green/normal

### ✅ Phase 3 Complete

The full pipeline works: events flow from VM → Wazuh → AI platform → dashboard.
Now you're ready to run real attacks.

---

## Phase 4: Running Atomic Red Team

> **⚠️ BEFORE EVERY ART RUN: Revert the VM to the "Clean Baseline" snapshot.**
> This prevents leftover artifacts from contaminating the next run's results.

### Step 4.1: Revert and verify

```powershell
# On the HYPERVISOR
# 1. Revert VM to snapshot: "Clean Baseline — Sysmon + Wazuh Agent + ART Installed"
# 2. Start the VM

# On the VM — verify everything is running
Get-Service Sysmon64, Wazuh | Format-Table Name, Status
ping 192.168.56.1     # confirm connectivity to host
```

**✅ Expected Result:**
```
Name        Status
----        ------
Sysmon64    Running
Wazuh       Running

Pinging 192.168.56.1... Reply from 192.168.56.1: bytes=32 time<1ms
```

### Step 4.2: Record the start time, then detonate

```powershell
# On the VM (elevated PowerShell)

# Technique: PowerShell encoded command (T1059.001)
# This is a good starter — it has a strong Sysmon signal
# and triggers Wazuh rules

# 1. Read what the test does first
Invoke-AtomicTest T1059.001 -ShowDetails

# 2. Record the start time (UTC)
$start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "START: $start" -ForegroundColor Cyan

# 3. DETONATE
Invoke-AtomicTest T1059.001 -TestNumbers 1

# 4. Record the end time
$end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "END:   $end" -ForegroundColor Cyan

# 5. SAVE THESE TIMESTAMPS — you'll need them for the labels file
Write-Host ""
Write-Host "COPY THIS LINE:" -ForegroundColor Yellow
Write-Host "$start,$end,$env:COMPUTERNAME,T1059.001,1,encoded command test" -ForegroundColor Green
```

**✅ Expected Result:**
The `Invoke-AtomicTest` command runs and shows output as PowerShell executes the
encoded command. You'll see the `START` and `END` timestamps printed.

```
START: 2026-07-18T15:30:00Z
[Atomic test output...]
END:   2026-07-18T15:30:45Z

COPY THIS LINE:
2026-07-18T15:30:00Z,2026-07-18T15:30:45Z,DESKTOP-XXXXX,T1059.001,1,encoded command test
```

### Step 4.3: Record the label on the host

```powershell
# On the HOST — append the label to the ground-truth file
cd C:\Projects\SOC\ai-soc-platform

# Paste the line you copied from Step 4.2
# If labels.csv doesn't exist yet, create it with the header first:
if (-not (Test-Path "simulations\labels.csv")) {
    "start_utc,end_utc,host,technique_id,test_number,notes" | Out-File -FilePath "simulations\labels.csv" -Encoding ascii
}

# Then append your line (replace with the actual timestamps from the VM)
"2026-07-18T15:30:00Z,2026-07-18T15:30:45Z,DESKTOP-XXXXX,T1059.001,1,encoded command test" | Add-Content -Path "simulations\labels.csv" -Encoding ascii

# Verify the file
Get-Content simulations\labels.csv
```

**✅ Expected Result:**
```
start_utc,end_utc,host,technique_id,test_number,notes
2026-07-18T15:30:00Z,2026-07-18T15:30:45Z,DESKTOP-XXXXX,T1059.001,1,encoded command test
```

### Step 4.4: Run cleanup

```powershell
# On the VM — clean up the atomic's changes
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

Write-Host "Cleanup complete." -ForegroundColor Green

# OPTIONAL: Revert the VM to snapshot to guarantee a clean state
# for the next run. This is safer than relying on -Cleanup.
```

**✅ Expected Result:**
```
Cleanup for T1059.001 complete.
```

### Step 4.5: Wait for indexing lag

```powershell
# Sysmon + Wazuh agent + filebeat + OpenSearch indexing takes time
# Wait at least 60 seconds before running the pipeline

Write-Host "Waiting 90 seconds for indexing lag..." -ForegroundColor Yellow
Start-Sleep -Seconds 90
```

### ✅ Phase 4 Complete

You've run your first Atomic Red Team test and recorded the ground-truth label.

---

## Phase 5: Detection & Evaluation

### Step 5.1: Run the detection pipeline

```powershell
# On the HOST
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1
cd C:\Projects\SOC\ai-soc-platform

python scripts/run_pipeline.py
```

**Example output (your actual numbers will vary):**
```
Fetching recent events...
Scoring 5 windows...
Fusing rule alerts + ML scores...

Alert #1: DESKTOP-XXXXX | 2026-07-18T15:30:00Z
  Detected: PowerShell execution with encoded commands
  Rules:    [Rule 92204: PowerShell detected (level 12)]
  ML Score: 0.87 (98th percentile) — anomalous
  Severity: HIGH
  MITRE:    T1059.001 (PowerShell), T1027 (Obfuscated Files)

Total: 1 alert emitted
```

> **Key things to verify:**
> - The `host` matches your VM name ✓
> - The `window_start` is within a few minutes of your ART run ✓
> - The MITRE techniques match what you ran (T1059.001) ✓
> - The severity is at least HIGH when rule + ML both fired ✓
>
> **If you see 0 alerts:** the attack window may not have fallen within the
> pipeline's lookback range. Wait 2 more minutes and re-run. Also check that
> the archives index is receiving events (Step 1.3).

### Step 5.2: Evaluate detection quality

```powershell
# On the HOST
python scripts/evaluate.py
```

**Example output (your numbers WILL vary — especially on a cold baseline):**
```
Loading model from models/anomaly_detector.joblib...
Loading labels from simulations/labels.csv...
  Found 1 labeled attack window(s)

Scoring 50 windows around attack windows...

Detection Quality (threshold = 95th percentile):
  True Positives:  1
  False Positives: 2
  Precision:       0.33
  Recall:          1.00
  F1 Score:        0.50
  ROC-AUC:         0.94
  PR-AUC:          0.72
```

> **What these numbers mean:**
> - **Recall 1.00** = the detector caught all labeled attacks. Excellent.
> - **Precision 0.33** = some false positives. Expected on a cold baseline; improves
>   as the baseline accumulates more "normal" data.
> - **ROC-AUC > 0.90** = the model ranks attack windows well above normal ones.
>
> **On a cold baseline (<10 training windows), expect:** lower precision, more false
> positives, and potentially lower ROC-AUC. These numbers improve steadily as you
> accumulate hours of normal-activity data and re-train. The published evaluation
> numbers (see `docs/EVALUATION.md`) are from a mature baseline with weeks of data.

### Step 5.3: View alerts on the dashboard

```powershell
# On the HOST — open http://localhost:8000 in your browser

# You should see:
#   1. The alert in the alert list (left panel)
#   2. Click it to see details (right panel): behavior, rules, ML score, MITRE
#   3. Click "Run AI Analysis" to have the LLM write an incident report
```

**✅ Expected Result (after clicking "Run AI Analysis"):**
- A structured analysis appears with:
  - Plain-English explanation of what happened
  - Severity assessment with rationale
  - Recommended investigation steps
  - Extracted IOCs (IPs, hashes, filenames from the alert)
  - MITRE ATT&CK technique table

> ⏱️ First analysis takes 10–30 seconds while the LLM processes. Subsequent
> analyses are cached.

### ✅ Phase 5 Complete

You've proven the system works end-to-end:
- Atomic Red Team attack → Sysmon event → Wazuh → Feature extraction → ML anomaly
  scoring → Fusion alert → Dashboard display → LLM analysis

---

## Phase 6: Running More Techniques

Once you've confirmed the pipeline works with T1059.001, expand your test suite.
Here are the recommended techniques from the project's `simulations/README.md`:

```powershell
# On the VM (revert to snapshot before each run!)

# T1082 — System Information Discovery (good ML test: recon burst)
$s = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1082 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# T1057 — Process Discovery (tests "rare process chain" features)
$s = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1057 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# T1136.001 — Create Local Account (clear Windows Event Log signal)
$s = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1136.001 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# T1053.005 — Scheduled Task (persistence, good Wazuh rule coverage)
$s = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1053.005 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
```

> **Record each run** to `simulations/labels.csv` and re-run `python scripts/evaluate.py`
> after each batch. More labels = more trustworthy metrics.

---

## Quick Reference Card

### IP Addresses

| Machine | IP | Notes |
|---------|-----|-------|
| Host (VM network) | `192.168.56.1` | From Step 1.5 |
| VM (host-only) | `192.168.56.101` | Confirm with `ipconfig` |

### Ports

| Port | Service | Listens On | Needed By |
|------|---------|-----------|-----------|
| 1514 | Wazuh Manager (agent) | Host | VM's Wazuh agent |
| 9200 | Wazuh Indexer (OpenSearch) | Host | ai-soc-platform (localhost) |
| 8000 | ai-soc API | Host | Your browser (localhost) |
| 443 | Wazuh Dashboard | Host | Your browser (localhost) |
| 11434 | Ollama LLM | Host | ai-soc-platform (localhost) |

### Credentials

| Service | Username | Password | Source |
|---------|----------|----------|--------|
| Wazuh Indexer | `admin` | `SecretPassword` | `docker-compose.yml` |
| Wazuh Dashboard | `admin` | `SecretPassword` | `docker-compose.yml` |
| Wazuh API | `wazuh-wui` | `MyS3cr37P450r.*-` | `docker-compose.yml` |

### Key Commands

```powershell
# === HOST ===

# Start Wazuh
cd wazuh-docker\single-node
docker compose up -d

# Stop Wazuh
docker compose down

# View logs
docker compose logs -f wazuh.manager
docker compose logs -f wazuh.indexer

# Activate Python venv
& $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1

# Run pipeline
cd ai-soc-platform
python scripts/run_pipeline.py

# Train model
python scripts/train_model.py

# Evaluate
python scripts/evaluate.py

# Start dashboard
uvicorn aisoc.api.main:app --port 8000 --reload

# === VM ===

# Check services
Get-Service Sysmon64, Wazuh

# Restart agent
Restart-Service -Name Wazuh

# Check agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20

# Show ART technique details
Invoke-AtomicTest T1059.001 -ShowDetails

# Run ART technique
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Cleanup ART technique
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

### The Cycle

```
Revert VM snapshot
    → Run ART technique (record timestamps)
        → Wait 90s for indexing
            → On host: python scripts/run_pipeline.py
                → On host: python scripts/evaluate.py
                    → Append new label to simulations/labels.csv
                        → REPEAT
```

---

## Troubleshooting

### "No events from the VM appear in the indexer"

1. On the VM: `Get-Service Wazuh` — is it running?
2. On the VM: check `C:\Program Files (x86)\ossec-agent\ossec.log` for errors
3. On the host: `docker compose logs wazuh.manager | Select-String "ERROR"`
4. On the VM: `Test-NetConnection -ComputerName 192.168.56.1 -Port 1514`
5. On the host: verify the firewall rule from Step 1.4 is enabled
6. Verify the archives index exists: `curl.exe -k -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-archives-*"`

### "train_model.py or run_pipeline.py has 0 events"

- The time window may be too narrow. Try `python scripts/train_model.py --hours 24`
- Verify the archives index was enabled: check Step 1.3
- Check that events are actually flowing: `curl.exe -k -u admin:SecretPassword "https://localhost:9200/wazuh-archives-*/_count?pretty"`

### "Connection refused to localhost:9200"

- Docker stack may be down: `docker ps` — are all three containers running?
- WSL2 may have restarted: re-run `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose up -d`
- Indexer may still be bootstrapping: wait 60 seconds

### "Agent shows Disconnected in Wazuh Dashboard"

1. Re-run Step 2.5 after 60 seconds
2. Check VM can reach host: `ping 192.168.56.1`
3. Check the agent's `ossec.conf` has the correct manager address
4. On the host: `docker compose logs wazuh.manager | Select-String "Registration"`

### "Wazuh agent shows Disconnected in Dashboard"

1. Wait 60 seconds — agent registration takes time
2. Check VM can reach host: `ping 192.168.56.1`
3. **Most common cause:** The host IP changed (DHCP). Use host-only networking
   with static IPs, or update `ossec.conf` on the VM with the new host IP.
4. Check the agent's `ossec.conf` has the correct manager address
5. On the host: `docker compose logs wazuh.manager | Select-String "Registration"`
6. Verify firewall rule from Step 1.4 is still enabled

### "Invoke-AtomicTest not found"

- ART module needs to be re-imported in new PowerShell sessions:
  ```powershell
  Import-Module invoke-atomicredteam -Force
  ```

### "Indexer fails to start after host reboot"

- You forgot to re-run the `vm.max_map_count` command. See the warning in Step 1.1.
  ```powershell
  wsl -d docker-desktop sysctl -w vm.max_map_count=262144
  docker compose up -d
  ```
  To make it permanent, add to `%UserProfile%\.wslconfig` as shown in Step 1.1.

### "evaluate.py reports 0 attacks found"

- Check that `simulations/labels.csv` exists and has entries
- Check that the timestamps in `labels.csv` are within the pipeline's lookback window
- Check that your VM's `host` name in `labels.csv` matches the agent name in Wazuh
- Pad your label windows by ±2 minutes to account for timing jitter

---

## Next Steps After Successful Deployment

1. **Accumulate baseline data** — let `run_pipeline.py` run on a schedule for a
   week of normal activity to get trustworthy anomaly scores.

2. **Run the full ART suite** — use `scripts/run_art_tests.ps1` (copy it to the VM
   or adapt it) to run all techniques in one batch.

3. **Retrain from feedback** — after accumulating analyst verdicts (TP/FP/Benign),
   run `scripts/retrain_feedback.py` to improve the model.

4. **Scale to more VMs** — add a second Windows VM with different configurations
   (e.g., a server OS, different software) to test cross-host detection.

5. **Test evasion** — try pacing ART techniques across window boundaries, using
   dictionary-word DGA domains, or stopping Sysmon mid-attack to understand the
   system's blind spots.
