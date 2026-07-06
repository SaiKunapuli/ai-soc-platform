# AI-Powered SOC Platform — Overview

> Wazuh tells you when something matches a known bad pattern; the ML layer tells you when the system is behaving in a way it has never behaved before.

An intelligent SIEM + incident-response assistant. Three detection/response capabilities layered on a traditional SIEM base:

1. **Rule-based detection** — Wazuh + Sysmon (known threats, high precision)
2. **ML behavioral anomaly detection** — per-entity baselines, UEBA-style (unknown/novel threats)
3. **LLM SOC copilot** — explains alerts, maps to MITRE ATT&CK, recommends response, writes incident reports

## Docs

- [Architecture](01-architecture.md) — layers, data flow, components
- [Roadmap](02-roadmap.md) — six phases with exit criteria
- [Design Decisions](03-design-decisions.md) — decisions made, open questions

The implementation is the `aisoc` Python package in [../src/aisoc/](../src/aisoc/) — one module per architecture layer.

## Hard constraints

- **Free/open-source only** — no paid APIs or services. LLM layer runs locally via Ollama.
- Dev/lab machine is Windows 11 → Wazuh server runs in Docker (WSL2 backend); this machine doubles as the monitored endpoint (Sysmon + Wazuh agent).

## Elevator pitch (resume framing)

Behavioral Baseline + Drift Detection Engine on top of a SIEM: per-entity behavior modeling (UEBA), unsupervised anomaly detection (Isolation Forest → autoencoder), alert fusion with MITRE ATT&CK mapping, and an LLM analyst that turns enriched alerts into investigation and containment playbooks.
