# Scripts

Entry points and automation for the AI SOC platform. Everything in this directory
drives the `aisoc` package — these are the *keys*, not the *engine*.

## Execution Order (Split-VM Lab)

```
   HOST                            VM
   ────                            ──
1. setup-host-lab.ps1 ──► prints IP ──► 2. setup-vm-target.ps1 -HostIP <ip>
       │                                       │
       ▼                                       ▼
   Wazuh Docker + archives               Sysmon + Wazuh Agent
   venv + pip + .env + Ollama            Atomic Red Team
   train model + pipeline + dashboard    Snapshot reminder
       │                                       │
       └────────────── events flow ────────────┘
                          │
3. (VM) Run ART technique, record timestamps
4. (Host) python scripts/run_pipeline.py
5. (Host) python scripts/evaluate.py
```

## Deployment Scripts (PowerShell)

| Script | Machine | What It Does |
|--------|---------|-------------|
| `setup-host-lab.ps1` | **Host** | Starts Wazuh Docker, enables archives, opens firewall, detects VM IP, installs Python venv + aisoc + .env, verifies Ollama, trains baseline, launches dashboard. Run this first. |
| `setup-vm-target.ps1` | **VM** | Installs Sysmon, Wazuh agent (pointed at your host), configures Sysmon event channel, installs Atomic Red Team. Requires `-HostIP <ip>` from Step 1.5 of the host script. Run elevated. |

Both are idempotent — safe to re-run. See `docs/VM_DEPLOYMENT_GUIDE.md` for the full walkthrough.

## Pipeline Scripts (Python)

| Script | Purpose | When to Run |
|--------|---------|-------------|
| `train_model.py` | Pull events from Wazuh archives, build features, fit Isolation Forest, save model to `models/` | Baseline (run once, then weekly) |
| `run_pipeline.py` | Pull recent events → score → fuse → write alerts to SQLite | After every ART run, or on a schedule |
| `evaluate.py` | Score detection quality against `simulations/labels.csv` ground truth | After each batch of ART runs |
| `self_learning_pipeline.py` | Pipeline variant that retrains incrementally | Experimental |
| `retrain_from_feedback.py` | Retrain model incorporating analyst TP/FP/Benign verdicts from the dashboard | After accumulating feedback |
| `scorecard.py` | Compute per-technique detection metrics | Periodic reporting |

## Atomic Red Team Scripts (PowerShell)

| Script | What It Does |
|--------|-------------|
| `run-atomic.ps1` | Run a single ART technique and record the label window to `simulations/labels.csv`. Supports `-DryRun` and `-Cleanup`. Run on the VM. |
| `run_art_tests.ps1` | Batch-run multiple ART techniques (T1053.005, T1136.001, T1057) and auto-record labels. Run on the VM. |

## Demo & Testing

| Script | Purpose |
|--------|---------|
| `seed_alerts.py` | Populate `data/alerts.db` with hand-crafted sample alerts so the dashboard has data to display before real pipeline runs |
| `copilot_demo.py` | Try the LLM copilot on a sample alert |
| `copilot_compare.py` | Compare LLM copilot output across multiple models |
| `load_mordor_data.py` | Load OTRF Security-Datasets (Mordor) captures for offline feature-coverage evaluation |
| `coverage_report.py` | Report which MITRE techniques have feature signals (from Mordor coverage data) |
| `update_threat_intel.py` | Refresh threat-intel feeds |

## Ops Scripts (PowerShell / Batch)

| Script | Purpose |
|--------|---------|
| `run-pipeline-loop.ps1` | Run the pipeline in a foreground loop (Ctrl+C to stop). For background operation, use `register-pipeline-task.ps1` instead. |
| `register-pipeline-task.ps1` | Register two Windows Scheduled Tasks: `AISOC-Pipeline` (runs `run_pipeline.py` every 30 min) and `AISOC-Training` (runs `train_model.py` daily). Use `-Status` to check, `-Unregister` to remove. |
| `restore-collection.ps1` | One-command recovery after Docker or the Wazuh agent falls over |
| `collection-startup.cmd` | Batch wrapper for collection startup in constrained environments |

## Quick Start (Cheat Sheet)

```powershell
# === HOST (elevated) ===
.\scripts\setup-host-lab.ps1
# ▶ Wazuh Docker starts, venv created, model trained, dashboard opens
# ▶ Take note of the detected VM IP

# === VM (elevated) ===
.\scripts\setup-vm-target.ps1 -HostIP 192.168.56.1
# ▶ Sysmon + Wazuh Agent + ART installed. TAKE A SNAPSHOT.

# === VM: run an attack ===
Import-Module invoke-atomicredteam -Force
$s = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Invoke-AtomicTest T1059.001 -TestNumbers 1
$e = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
# Append $s,$e line to simulations/labels.csv on the host
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# === HOST: detect + evaluate ===
python scripts/run_pipeline.py
python scripts/evaluate.py

# ▶ View alerts at http://localhost:8000
```
