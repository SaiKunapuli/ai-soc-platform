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
| 13 | Copilot model | **Keep both `qwen2.5:7b-instruct` and `:14b-instruct`** | A 3-way comparison (7B / 14B / 14B-analysis+7B-report) showed the two-model "combination" is *not* worth it — alternating models forces Ollama to swap 9GB/4.7GB in and out of RAM, and the report step is too cheap to benefit from the split. Instead: one active model via `AISOC_OLLAMA_MODEL`. 7B for dev (35s end-to-end), 14B for the demo (75s, sharper on ambiguous alerts). Both kept because disk is the only cost. |
| 14 | IOC extraction | **Deterministic in code, LLM only supplements** | The 7B was inconsistent run-to-run at extracting IOCs. Host/user/rule-IDs/process-names are structured data in the alert, so `analyst._alert_iocs` pulls them directly; any LLM-cited IOC is added only if it's present in the alert (grounding). Guarantees reliable IOCs with zero hallucination risk. |
| 15 | Alert persistence | **SQLite (stdlib) under `data/`** | Lightweight store behind the API; no extra dependency. `AlertStore` in `aisoc/api/store.py`. |
| 16 | Dashboard ↔ backend | **Dashboard calls the FastAPI over HTTP** | Same-origin single-page `index.html` served by the API; never touches the store or Ollama directly. Copilot analysis on demand; `/stats` streams live telemetry (event rates, type mix, feed, sensor health) for the mission-control view. |
| 17 | Severity by **agreement** | Rule level alone never sets HIGH | A high-level Wazuh rule (e.g. level-15 "executable dropped in a malware folder") fires constantly on benign dev tooling. Fusion severity now demands the rule AND the ML anomaly to concur: rule-only → MEDIUM, rule+anomaly → HIGH, critical-rule+anomaly → CRITICAL. Stops the dashboard echoing SIEM noise as HIGH. Copilot may still override. |
| 17 | Dashboard tech | **Custom self-contained `index.html`, served by FastAPI at `/`** — Streamlit retired | Streamlit couldn't reach the visual polish the project wanted (clean SaaS card layout + a Jarvis-style animated radar centerpiece). A hand-built HTML/CSS/JS page (no build step, inline everything) gives full design control and, served same-origin by the API, needs no CORS. Streamlit `app.py` kept as legacy. |

## Open questions (not blocking Phase 1)

1. **Ollama model choice** — `llama3.1:8b` vs `qwen2.5:7b-instruct`. The dev machine's GPU is an AMD RX 6600, which Ollama may not accelerate on Windows → expect CPU inference; fine for batch alert analysis, decide in Phase 4 by testing on real alerts.
2. **Baseline data volume** — is one week of personal-machine usage enough of a "normal" baseline, or pad it with synthetic benign activity?
3. **Second endpoint / multi-machine deployment** — deploying the Wazuh agent to other computers does NOT improve the baseline (baselines are per-machine; each host needs its own ~week). It's worth doing only for the *portfolio story* (multi-endpoint SOC, real lateral-movement T1021). No custom package needed — the Wazuh agent + `install-endpoint.ps1` already are the deployment; the real blocker is exposing the Dockerized manager (ports 1514/1515) to the LAN, a networking + security decision. Deferred to Phase 6.
4. **Repo location** — resolved 2025-07-19. Was living under `C:\Users\srika\OneDrive\Documents\Obsidian Vault\SOC\` (a leftover from when docs were Obsidian notes) and the OneDrive overlay caused two classes of failure: file-locks on the indexer cert bind mount (cert generator `cp ... Permission denied`) and OneDrive churn on `.git/`. Moved to `C:\Projects\SOC\` (and `ECA`, `ai-speed-radar` to siblings) via `scripts/move-repos-out-of-onedrive.ps1` with robocopy `/E /COPYALL /R:5 /W:3` plus a per-repo git verify. .git round-tripped intact; GitHub remote unchanged. Recovery: if anything post-move goes wrong, `Remove-Item -Recurse -Force C:\Projects\<repo>` and re-run the script — originals were only deleted after a clean fetch-dry-run in the new location.

Related: [Architecture](01-architecture.md) · [Roadmap](02-roadmap.md)
