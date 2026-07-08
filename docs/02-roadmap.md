# Roadmap

Six phases. Each has an **exit criterion** — don't start the next phase until it's met. Scope discipline is the whole game: one log source, one feature family, one model first.

## Phase 1 — Lab foundation ✅ COMPLETE (2026-07-06)
Get real telemetry flowing and prove you can generate attacks to detect.

- [x] Install Docker Desktop (WSL2 backend) — needed a cold restart to unstick the engine
- [x] Wazuh single-node stack in Docker (v4.14.6) — see [../docker/README.md](../docker/README.md)
- [x] Sysmon installed on the Windows host with SwiftOnSecurity config
- [x] Wazuh agent on the host (ID 001, DESKTOP-STQNCN4), enrolled and Active
- [x] Enable `wazuh-archives-*` (`logall_json` + filebeat archives module) — required for ML baselines
- [x] Install Atomic Red Team (Invoke-AtomicRedTeam) with atomics
- [x] Ran T1082 test 1 — systeminfo execution captured in archives
- [x] Recorded run window in [../simulations/labels.csv](../simulations/labels.csv)

**Exit criterion MET:** T1082 landed in `wazuh-archives-*`, indexer green, 155+ Sysmon EID-1 events queryable. Run more techniques over the coming days to enrich labels; baseline data now accumulates passively.

## Phase 2 — ML core (process features + Isolation Forest) 🔨 WIRED, pending baseline
- [x] `aisoc.ingestion` pulls archive events from the indexer into DataFrames
- [x] `aisoc.features.process_features` builds 10-min windowed features per host
- [x] `AnomalyDetector` — train/score (stable normalization) + feature attribution
- [x] `scripts/train_model.py` (fit + save) and `scripts/run_pipeline.py` (full chain)
- [x] **Full pipeline proven on REAL data (2026-07-06):** live Sysmon → features →
      score → fusion → EnrichedAlerts in the store → copilot triage. On the encoded-PS
      window the copilot correctly downgraded a level-15 Wazuh rule to MEDIUM because
      the ML anomaly score was low (normal for this host) — the thesis working live.
- [x] `scripts/evaluate.py` + `aisoc.detection.evaluate` — precision / recall / F1 /
      ROC-AUC / PR-AUC vs labeled attack windows (built + tested). Training now
      excludes labeled attack windows (clean baseline by construction).
- [x] First provisional eval (2026-07-07, ~29 normal windows): T1082 discovery burst
      caught cleanly (score 1.0); encoded-PowerShell windows missed (~0.24–0.46) —
      the encoded-command signal gets diluted in a 10-min window. ROC-AUC ~0.78.
      Points to a feature-engineering improvement, exactly what the harness is for.
- [ ] Collect ≥1 week of normal-usage baseline (accumulating)
- [ ] Retrain on the full baseline and re-run evaluate.py for the real numbers

**Exit criterion:** a metrics table (precision/recall over labeled windows) — the harness
that produces it is built, tested, and validated. Just needs the week of baseline.

## Phase 3 — Enrichment + MITRE
- [ ] `EnrichedAlert` fusion: window + entity → Wazuh rule alerts + ML score in one object
- [ ] MITRE passthrough from Wazuh rules; behavior→technique map for ML-only detections
- [ ] Alerting policy: percentile threshold + corroboration logic (anomaly ≠ malicious)

**Exit criterion:** running one command over a time range emits well-formed `EnrichedAlert` JSON for the attack windows.

## Phase 4 — LLM copilot (Ollama, free) ✅ COMPLETE (2026-07-06)
- [x] Pulled `qwen2.5:7b-instruct` (dev) + `qwen2.5:14b-instruct` (demo)
- [x] `CopilotAnalysis` structured output: explanation, interpretation, severity + rationale, investigation steps, containment
- [x] IOC grounding + deterministic extraction (reliable, no invented indicators)
- [x] Markdown incident report generator (deterministic sections + LLM summary)

**Exit criterion MET:** sample enriched alert → useful analysis + incident report, verified end to end against the live model (7B ~35s, 14B ~75s on CPU).

## Phase 5 — API + dashboard 🔨 IN PROGRESS (started 2026-07-06)
- [x] SQLite alert store (`aisoc/api/store.py`)
- [x] FastAPI: list alerts, alert detail, analyze (on-demand copilot), report
- [x] Streamlit dashboard: severity metrics, alert list, detail, AI copilot panel
- [x] Seed script for demo alerts; verified API + dashboard serving end to end
- [ ] Wire the *real* fusion pipeline output into the store (currently seeded samples) — lands with Phase 2's trained model
- [ ] "Most anomalous entities today" view (needs real ML scores)

**Exit criterion:** end-to-end demo — run an atomic test, watch the alert + AI report appear in the dashboard. (Front end done; the live-data half waits on Phase 2's baseline.)

## Phase 6 — Upgrades (pick by interest)
- Autoencoder detection layer (multi-step / stealth patterns)
- Auth + network feature families
- Analyst feedback loop (TP/FP labels → retraining) — the "adaptive SOC" story
- Attack-chain graph visualization (user → process → network → host)
- "Explain this alert" at beginner / analyst / technical levels
- Suricata + a Linux VM victim for lateral-movement scenarios
- **Multi-endpoint deployment** — Wazuh agents on other machines (needs LAN exposure
  of the manager; multi-endpoint SOC + real T1021 lateral movement). See decisions #3.

Related: [Architecture](01-architecture.md) · [Design Decisions](03-design-decisions.md)
