# AI SOC Platform

Intelligent SIEM + incident-response assistant. Layers ML behavioral anomaly detection (UEBA-style) and a local-LLM SOC copilot on top of a Wazuh + Sysmon foundation.

> Wazuh tells you when something matches a known bad pattern; the ML layer tells you when the system is behaving in a way it has never behaved before.

**Everything in this project is free/open-source** — Wazuh, OpenSearch, scikit-learn, FastAPI, Ollama. No paid APIs.

## Architecture

```
Sysmon + Wazuh agent (Windows host)
        │
Wazuh server ── Wazuh Indexer (OpenSearch)          [docker/]
        │
aisoc.ingestion    pull alerts + raw archive events
aisoc.features     per-entity, time-windowed behavioral features
aisoc.detection    Isolation Forest anomaly scoring (autoencoder later)
aisoc.enrichment   fuse rule alerts + ML scores → EnrichedAlert, MITRE mapping
aisoc.copilot      local LLM (Ollama): explanation, severity, playbook, report
aisoc.api          FastAPI backend
dashboard/         Streamlit v1
```

Full design docs live in [docs/](docs/) — overview, architecture, roadmap, design decisions.

## Repo layout

```
docs/             design docs: architecture, roadmap, decisions
docker/           Wazuh lab runbook (single-node stack via Docker/WSL2)
simulations/      Atomic Red Team runbook + ground-truth attack labels
src/aisoc/        the Python package (layers above)
notebooks/        exploratory analysis, model evaluation
dashboard/        Streamlit app (Phase 5)
tests/            pytest suite
```

## Setup

Requires Python 3.11+.

> **OneDrive note:** this repo lives inside a OneDrive-synced folder. Create the
> virtualenv OUTSIDE OneDrive to avoid sync churn and file-locking pain, e.g.:
>
> ```powershell
> python -m venv $env:LOCALAPPDATA\venvs\aisoc
> & $env:LOCALAPPDATA\venvs\aisoc\Scripts\Activate.ps1
> ```

```powershell
pip install -e ".[dev]"
copy .env.example .env   # then fill in indexer credentials
```

Optional extras:

- `pip install -e ".[deep]"` — PyTorch, for the autoencoder (Phase 6)
- `pip install -e ".[dashboard]"` — Streamlit (Phase 5)

## Getting started (Phase 1)

1. Stand up the Wazuh lab — follow [docker/README.md](docker/README.md)
2. Install Sysmon + the Wazuh agent on this machine (same doc)
3. Simulate attacks and record labels — follow [simulations/README.md](simulations/README.md)

## Status

- [ ] Phase 1 — lab foundation (Wazuh, Sysmon, Atomic Red Team)
- [ ] Phase 2 — ML core (process features + Isolation Forest)
- [ ] Phase 3 — enrichment + MITRE mapping
- [ ] Phase 4 — LLM copilot (Ollama)
- [ ] Phase 5 — API + dashboard
- [ ] Phase 6 — autoencoder, feedback loop, graph viz
