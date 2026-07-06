# Roadmap

Six phases. Each has an **exit criterion** — don't start the next phase until it's met. Scope discipline is the whole game: one log source, one feature family, one model first.

## Phase 1 — Lab foundation
Get real telemetry flowing and prove you can generate attacks to detect.

- [ ] Install Docker Desktop (WSL2 backend) — the one missing prerequisite on the dev machine
- [ ] Wazuh single-node stack in Docker — see [../docker/README.md](../docker/README.md)
- [ ] Sysmon installed on the Windows host with SwiftOnSecurity config
- [ ] Wazuh agent on the host, enrolled with the server
- [ ] Enable `wazuh-archives-*` (`logall_json`) — required for ML baselines later
- [ ] Install Atomic Red Team (Invoke-AtomicRedTeam)
- [ ] Run 2–3 safe techniques (e.g. T1059.001 PowerShell, T1082 system discovery) and see them appear in the Wazuh dashboard
- [ ] Record run windows in [../simulations/labels.csv](../simulations/labels.csv)

**Exit criterion:** an Atomic Red Team run visibly lands as Wazuh alerts, and raw archive events are queryable in the indexer.

## Phase 2 — ML core (process features + Isolation Forest)
- [ ] `aisoc.ingestion` pulls archive events from the indexer into DataFrames
- [ ] `aisoc.features.process_features` builds 10-min windowed features per host
- [ ] Collect ≥1 week of normal-usage baseline data (starts passively once Phase 1 is up — begin early)
- [ ] Train Isolation Forest; score all windows
- [ ] Evaluate: do labeled attack windows score above the 95th percentile of normal windows?

**Exit criterion:** a metrics table (precision/recall over labeled windows) — honest numbers, even if mediocre.

## Phase 3 — Enrichment + MITRE
- [ ] `EnrichedAlert` fusion: window + entity → Wazuh rule alerts + ML score in one object
- [ ] MITRE passthrough from Wazuh rules; behavior→technique map for ML-only detections
- [ ] Alerting policy: percentile threshold + corroboration logic (anomaly ≠ malicious)

**Exit criterion:** running one command over a time range emits well-formed `EnrichedAlert` JSON for the attack windows.

## Phase 4 — LLM copilot (Ollama, free)
- [ ] Pull a model (start: `llama3.1:8b` or `qwen2.5:7b-instruct`)
- [ ] `CopilotAnalysis` structured output: explanation, interpretation, severity + rationale, investigation steps, containment
- [ ] IOC grounding validation (no invented indicators)
- [ ] Markdown incident report generator

**Exit criterion:** feed a real enriched alert in, get a report a human analyst would call useful.

## Phase 5 — API + dashboard
- [ ] FastAPI: list alerts, alert detail, trigger analysis
- [ ] Streamlit dashboard: active alerts by severity, most-anomalous entities today, incident report view

**Exit criterion:** end-to-end demo — run an atomic test, watch the alert + AI report appear in the dashboard.

## Phase 6 — Upgrades (pick by interest)
- Autoencoder detection layer (multi-step / stealth patterns)
- Auth + network feature families
- Analyst feedback loop (TP/FP labels → retraining) — the "adaptive SOC" story
- Attack-chain graph visualization (user → process → network → host)
- "Explain this alert" at beginner / analyst / technical levels
- Suricata + a Linux VM victim for lateral-movement scenarios

Related: [Architecture](01-architecture.md) · [Design Decisions](03-design-decisions.md)
