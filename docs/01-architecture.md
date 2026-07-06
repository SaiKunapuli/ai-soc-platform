# Architecture

Seven layers. Data flows top to bottom.

```
┌─────────────────────────────────────────────────────────┐
│ 1. COLLECTION      Sysmon + Wazuh agent (Windows host)  │
│                    Wazuh server (Docker)                │
│                    [later: Suricata, Linux VM victim]   │
├─────────────────────────────────────────────────────────┤
│ 2. STORAGE         Wazuh Indexer (OpenSearch)           │
│                    indices: wazuh-alerts-*,             │
│                    wazuh-archives-* (raw events)        │
├─────────────────────────────────────────────────────────┤
│ 3. FEATURES        aisoc.features — per-entity,         │
│                    time-windowed behavioral features    │
├─────────────────────────────────────────────────────────┤
│ 4. ML DETECTION    aisoc.detection — Isolation Forest   │
│                    (Phase 2), autoencoder (later)       │
├─────────────────────────────────────────────────────────┤
│ 5. ENRICHMENT      aisoc.enrichment — fuse Wazuh rule   │
│                    alerts + ML scores → EnrichedAlert,  │
│                    MITRE ATT&CK mapping                 │
├─────────────────────────────────────────────────────────┤
│ 6. COPILOT         aisoc.copilot — local LLM (Ollama)   │
│                    explanation, severity, playbook,     │
│                    incident report                      │
├─────────────────────────────────────────────────────────┤
│ 7. INTERFACE       FastAPI backend + dashboard          │
│                    (Streamlit v1 → React later)         │
└─────────────────────────────────────────────────────────┘
```

## Layer notes

### 1. Collection
- **Sysmon** (SwiftOnSecurity config) on the Windows host → process creation, network connections, file events, DNS.
- **Wazuh agent** ships Sysmon + Windows Event Log to the Wazuh server.
- Suricata is **deferred** — network capture in a single-host lab is a lot of setup for little early signal.

### 2. Storage
Wazuh 4.x does **not** ship Elasticsearch. It ships the **Wazuh Indexer**, an OpenSearch fork. The API is largely Elasticsearch-compatible; we query it with `opensearch-py`. Two indices matter:
- `wazuh-alerts-*` — events that matched a rule (what most people see)
- `wazuh-archives-*` — **all** events, rule match or not. Must be explicitly enabled (`logall_json` in `ossec.conf`). **The ML layer needs this** — behavioral baselines can't be built from rule-matched events only.

### 3. Features
Per-entity (user, host) aggregation over sliding time windows (default 10-minute buckets). Phase 2 scope is **process features only**:
- PowerShell/cmd execution count per window
- encoded/obfuscated command-line flag (`-enc`, high-entropy args)
- rare-process score (frequency of image path in entity history)
- new parent→child process pair (first-seen chain)
- process burst rate

Auth features (logins per hour, failed ratio, time-of-day variance, new source IP) come next; network/file features after that.

### 4. ML detection
- **Isolation Forest** (scikit-learn) on windowed features. Output: normalized anomaly score 0–1.
- Key caveat: **anomalous ≠ malicious**. Scores only become alerts through the fusion layer (percentile threshold against the entity's own baseline, or corroborating Wazuh alert).
- **Autoencoder** (PyTorch) is a later upgrade for multi-step/stealth patterns — optional dependency, not in the base install.

### 5. Enrichment
- `EnrichedAlert` (pydantic schema in [../src/aisoc/enrichment/schemas.py](../src/aisoc/enrichment/schemas.py)) is **the contract of the whole system** — everything upstream produces it, everything downstream consumes it.
- MITRE mapping: Wazuh rule alerts **already carry** `rule.mitre.{id,tactic,technique}` — passthrough. Only ML-originated detections need our own behavior→technique mapping (`aisoc/enrichment/mitre.py`).

### 6. Copilot
- Local LLM via **Ollama** (free). Structured JSON output validated against `CopilotAnalysis` schema.
- **Grounding rule:** the model may only reason over fields present in the `EnrichedAlert`. It must never invent IOCs, IPs, or hostnames. Enforced by prompt + post-validation that every IOC in the output exists in the input.
- Produces: plain-language explanation, attack interpretation, severity (with rationale), investigation steps, containment recommendations, and a formatted incident report.

### 7. Interface
- FastAPI: `/alerts`, `/alerts/{id}`, `/alerts/{id}/analyze`, `/health`.
- Dashboard v1 in Streamlit (fast, free, pure Python); React rewrite only if/when it earns it.

## Ground truth / evaluation
**Atomic Red Team** runs are the labeling mechanism: every simulated technique execution is logged with a timestamp window → those windows are positive labels for evaluating detection (see [../simulations/README.md](../simulations/README.md)). This is a Phase 1 concern, not a stretch goal — without attack windows there is nothing to validate against.

Related: [Roadmap](02-roadmap.md) · [Design Decisions](03-design-decisions.md)
