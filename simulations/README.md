# Attack simulation — Atomic Red Team

Atomic Red Team runs are this project's **ground truth**. Every simulated technique execution is
recorded with its time window in `labels.csv`; those windows are the positive labels for
evaluating both rule-based and ML detection. No labels → no honest metrics.

⚠️ Run only on this lab machine, only techniques you understand. Always run the cleanup step.

## Install (elevated PowerShell)

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

## Starter techniques (safe, high signal in Sysmon)

| Technique | Name | Why it's a good starter |
|-----------|------|------------------------|
| T1059.001 | PowerShell | Encoded commands light up Sysmon Event ID 1 + Wazuh rules |
| T1082 | System Information Discovery | Benign-looking recon burst — good ML test case |
| T1057 | Process Discovery | Same — tests "rare process chain" features |
| T1136.001 | Create Local Account | Clear Windows Event Log signal |
| T1053.005 | Scheduled Task | Classic persistence, well covered by Wazuh rules |

## Run pattern (always the same)

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails          # read what it does first
$start = Get-Date -Format o
Invoke-AtomicTest T1059.001 -TestNumbers 1
$end = Get-Date -Format o
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
# then append a row to labels.csv with $start/$end
```

## labels.csv format

```csv
start_utc,end_utc,host,technique_id,test_number,notes
2026-07-10T02:14:00Z,2026-07-10T02:16:30Z,DESKTOP-XX,T1059.001,1,encoded command test
```

Pad windows by ±60s when evaluating — event timestamps lag execution slightly.
