# Design Decisions

## Decided

| # | Decision | Choice | Why |
|---|----------|--------|-----|
| 1 | Cost constraint | **Free/open-source only** | Personal project; no recurring API costs. Everything below follows from this. |
| 2 | LLM runtime | **Ollama, local** | Free, private, offline. Thin `LLMClient` abstraction in `aisoc.copilot.llm` so a hosted API can slot in later without touching the analyst logic. |
| 3 | Log store | **Wazuh Indexer (OpenSearch)** — not Elasticsearch | It's what Wazuh 4.x actually ships. Query with `opensearch-py`. |
| 4 | First ML model | **Isolation Forest** (scikit-learn) | Simple, fast, no labels needed, well-understood. Autoencoder is a later upgrade, behind an optional `[deep]` dependency extra. |
| 5 | First feature family | **Process features** (Sysmon Event ID 1) | Richest data source in a single-host lab; attacks are trivially simulatable with Atomic Red Team. Auth features second. |
| 6 | Attack simulation | **Atomic Red Team, in Phase 1** | It's the ground-truth labeling mechanism, not a stretch goal. Can't evaluate detection without attack windows. |
| 7 | Suricata | **Deferred** | Network capture in a single-host lab = lots of setup, little early signal. Revisit with a Linux VM victim in Phase 6. |
| 8 | Dashboard v1 | **Streamlit** | Pure Python, free, an afternoon to stand up. React rewrite only if the project outgrows it. |
| 9 | Language/stack | Python 3.11+, pydantic v2, FastAPI, pandas | Standard, free, ML-native. `EnrichedAlert` pydantic schema is the system-wide contract. |
| 10 | ML alerting policy | Anomaly score alone never pages | Anomalous ≠ malicious. Alert = score above entity-baseline percentile **plus** corroboration (Wazuh rule hit or repeated deviation). Keeps the FP story honest. |
| 11 | LLM grounding | Copilot may only cite fields present in the input alert | Post-validate that every IOC in the output exists in the input; hallucinated indicators in a SOC tool are worse than none. |
| 12 | Docs location | **In-repo (`docs/`)**, plain Markdown | Originally Obsidian notes, but Obsidian isn't actually in use. In-repo docs are also what a portfolio reviewer on GitHub will see. |

## Open questions (not blocking Phase 1)

1. **Ollama model choice** — `llama3.1:8b` vs `qwen2.5:7b-instruct`. The dev machine's GPU is an AMD RX 6600, which Ollama may not accelerate on Windows → expect CPU inference; fine for batch alert analysis, decide in Phase 4 by testing on real alerts.
2. **Baseline data volume** — is one week of personal-machine usage enough of a "normal" baseline, or pad it with synthetic benign activity?
3. **Second endpoint** — add a Linux VM victim (makes lateral-movement T1021 scenarios real) or stay single-host through Phase 5?
4. **Repo location** — currently inside a OneDrive-synced folder (leftover from the Obsidian experiment). Recommended: move to a local path like `C:\Users\srika\Projects\ai-soc-platform` before the repo accumulates data/models; OneDrive sync on `.git` is churn with no benefit once the project is on GitHub.

Related: [Architecture](01-architecture.md) · [Roadmap](02-roadmap.md)
