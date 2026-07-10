---
title: "AI SOC Platform — Codebase Guide"
subtitle: "A plain-language tour of the whole system"
date: "2026-07-08"
---

# AI SOC Platform — Codebase Guide

*A ground-up explanation for someone who knows how to program and train ML
models, but is new to reading a large, real-world, multi-layer codebase. Nothing
here assumes you know FastAPI, pydantic, OpenSearch, or the architecture patterns
involved — those get defined as they come up.*

---

# 1. The 10,000-foot view

## What is this project?

It's an **AI-powered SOC platform**. A **SOC** (Security Operations Center) is the
team/room in a company whose job is to watch computers for signs of a cyberattack
and respond. This project is a small, self-contained version of the software such a
team uses, with two twists that make it a portfolio piece rather than a toy:

1. It doesn't just use **rules** ("if X happens, alert") — it also uses a **machine
   learning model** that learns what *normal* looks like for a specific machine and
   flags behavior that deviates.
2. It has an **LLM "copilot"** (a local large language model) that reads each alert
   and writes a plain-English explanation, a severity rating, and a
   recommended-response playbook — like a junior analyst that never sleeps.

## What problem does it solve?

Traditional security tools (called **SIEMs** — Security Information and Event
Management systems; think of them as a giant searchable logbook plus a rule engine)
have a famous problem: **alert fatigue**. They fire thousands of rule-based alerts a
day, most of them false positives. A human can't triage them all.

This project's thesis is: *combine two opinions before you panic.*

- The **rule layer** (an off-the-shelf SIEM called **Wazuh**) says "this matches a
  known-bad pattern."
- The **ML layer** says "…but is this actually unusual *for this machine*?"
- Only when **both agree** does an alert get escalated to HIGH/CRITICAL. A noisy rule
  firing on totally normal behavior gets quietly downgraded to MEDIUM.
- Then the **LLM** turns the surviving alerts into readable incident tickets.

So the value is **noise reduction + explanation**: fewer false alarms, and the ones
that remain come pre-explained.

## Tech stack

Everything is **free and runs locally** — a deliberate constraint of the project.

| Layer | Technology | One-line reason |
|---|---|---|
| Language | **Python 3.11+** | ML-native, standard for this domain |
| Data wrangling | **pandas** | turn raw logs into tables of features |
| Machine learning | **scikit-learn** (Isolation Forest) | the anomaly detector |
| Data contracts | **pydantic v2** | define + validate the objects passed between layers |
| Web API | **FastAPI** + **uvicorn** | serve alerts and the dashboard over HTTP |
| HTTP client | **httpx** | talk to the LLM and (in tests) the API |
| Log datastore client | **opensearch-py** | query the Wazuh event database |
| LLM runtime | **Ollama** (external process) | run a local model like `qwen2.5:7b-instruct` |
| Persistence | **sqlite3** (Python stdlib) | store alerts/analyses/feedback in one file |
| Frontend | **one static HTML file + vanilla JS** | the "mission control" dashboard |
| Model storage | **joblib** | save/load the trained model to disk |

Three things run *outside* this repo but are part of the system: **Wazuh** (the SIEM,
run in Docker), **Sysmon** (a Windows sensor that generates the raw events), and
**Ollama** (the local LLM server). This repo is the *brain* that sits on top of them.

> **Term — "the aisoc package":** the actual product code lives in `src/aisoc/`.
> `aisoc` is the importable Python package name (`import aisoc`). Everything else in
> the repo — scripts, tests, docs — either drives it or documents it.

## How do you run it? Where does execution start?

There is **no single `main()`**. This is normal for real systems: a codebase is
often a *library* plus several *entry points* that use it. Here are the entry points:

1. **The web app** — the dashboard + its data API:
   ```
   uvicorn aisoc.api.main:app --port 8000
   ```
   `uvicorn` is an **ASGI server** (ASGI = the modern Python standard for async web
   apps; the server is the thing that actually listens on a TCP port and speaks
   HTTP). `aisoc.api.main:app` means "in the file `src/aisoc/api/main.py`, find the
   object named `app`." That `app` is the FastAPI application. Opening
   `http://localhost:8000/` serves the dashboard.

2. **The batch pipeline** — the scripts in `scripts/`, run by hand or on a schedule:
   ```
   python scripts/train_model.py    # learn "normal" from a week of data
   python scripts/run_pipeline.py   # score recent activity, write alerts
   python scripts/evaluate.py       # measure detection quality
   ```

So execution starts in **one of two places**: the FastAPI `app` (for the live
dashboard) or a script's `main()` (for offline processing). They share data through
a SQLite file, not by calling each other directly.

## Architecture at a glance

```
                        YOUR WINDOWS MACHINE
   ┌───────────────────────────────────────────────────────────┐
   │  Sysmon (sensor)  ──►  Wazuh agent  ──────────┐            │
   └───────────────────────────────────────────────┼───────────┘
                                                    │ ships events
                        DOCKER (the SIEM)           ▼
   ┌───────────────────────────────────────────────────────────┐
   │  Wazuh manager ──► Wazuh Indexer (OpenSearch database)     │
   │      · rule alerts  →  index "wazuh-alerts-*"              │
   │      · ALL events   →  index "wazuh-archives-*"            │
   └───────────────────────────────┬───────────────────────────┘
                                    │  opensearch-py queries
        THE aisoc PACKAGE (this repo)▼      (scripts/run_pipeline.py drives this)
   ┌───────────────────────────────────────────────────────────┐
   │ ingestion → features → detection → enrichment(fusion)      │
   │ (pull      (rows of    (Isolation   (combine rule + ML →    │
   │  events)    numbers)    Forest       EnrichedAlert +        │
   │                         score)       MITRE + severity)      │
   │                                          │                  │
   │                                          ▼                  │
   │                                   SQLite: data/alerts.db    │
   └───────────────────────────────┬───────────────────────────┘
                                    │
        WEB (uvicorn aisoc.api.main)▼        COPILOT (on demand)
   ┌───────────────────────────────────────────────────────────┐
   │ FastAPI  ──►  dashboard/index.html (browser)               │
   │   /alerts /stats /feedback                                 │
   │   /alerts/{id}/analyze ──► copilot ──► Ollama (local LLM)  │
   └───────────────────────────────────────────────────────────┘
```

The golden rule to remember: **data flows left-to-right and top-to-bottom, and the
object that everything converges on is the `EnrichedAlert`.** Keep that object in
mind and the whole system makes sense (more on it in Sections 3 and 4).

---

# 2. The map — folder structure & data flow

The repo you care about is `ai-soc-platform/`. (There's also a sibling folder
`wazuh-docker/` — that's **vendored third-party code** for running the SIEM in
Docker; you did not write it and can treat it as an appliance. Ignore it for
understanding *this* codebase.)

## Folder structure

```
ai-soc-platform/
├── src/aisoc/            ← THE PRODUCT. The importable Python package.
│   ├── config.py             settings (URLs, model name) from env/.env
│   ├── ingestion/            pull raw events out of the Wazuh datastore
│   ├── features/             raw events → tables of numbers per time-window
│   ├── detection/            the ML model (train, score, evaluate, baselines)
│   ├── enrichment/           schemas.py (the contracts) + fusion + MITRE mapping
│   ├── copilot/              the local-LLM analyst (explain, report, ground IOCs)
│   └── api/                  FastAPI web server + SQLite store + live telemetry
│
├── scripts/              ← ENTRY POINTS. Runnable jobs that drive the package.
│   ├── train_model.py        learn "normal", save the model
│   ├── run_pipeline.py       the full chain: events → alerts in the DB
│   ├── evaluate.py           measure detection quality vs. labeled attacks
│   ├── seed_alerts.py        put demo alerts in the DB (for the dashboard)
│   ├── copilot_demo.py /_compare.py   try the LLM by hand
│   └── *.ps1                 Windows ops helpers (recover collection, schedule)
│
├── dashboard/            ← FRONTEND.
│   ├── index.html            the "mission control" single-page app (current)
│   └── app.py                a legacy Streamlit version (superseded, ignorable)
│
├── tests/                ← pytest suite, one file per module
├── docs/                 ← design write-ups (overview, architecture, decisions)
├── docker/, simulations/, notebooks/   ← runbooks + attack labels + placeholders
│
├── pyproject.toml        ← package metadata + dependency list (config)
├── .env.example          ← template for secrets/URLs (config)
├── .github/workflows/    ← CI: run tests on push (config/automation)
└── models/, data/        ← generated at runtime, git-ignored (not in the repo)
```

## Which folders actually matter?

- **Matters most:** `src/aisoc/` — this *is* the system. Within it, the single most
  important file is `enrichment/schemas.py` (the data contracts).
- **Matters:** `scripts/` (how the system is actually run) and `dashboard/index.html`
  (what you see).
- **Skim/ignore for understanding:** `pyproject.toml`, `.env.example`, `.github/`,
  `docker/`, `notebooks/`, `dashboard/app.py`, `tests/` (read tests only to confirm
  how a function is *meant* to be called), and all `__init__.py` files (they mostly
  just mark folders as packages and re-export a name or two).

## The layered-architecture pattern

Notice that `src/aisoc/` is split into folders named after **stages of processing**:
`ingestion → features → detection → enrichment → copilot → api`. This is the
**layered architecture** (a.k.a. "pipes and filters") pattern: each layer does one
job and hands its output to the next, and — importantly — **a layer only knows about
the layer(s) below it, never above.** `features` doesn't know the `api` exists;
`detection` doesn't know about the dashboard. This is why you can understand and test
one layer at a time.

The "handshake" between layers is a small set of **pydantic objects** defined in
`enrichment/schemas.py`. Think of those objects as the *shipping containers*: every
layer agrees on the container shape, so they can be built and swapped independently.

## How data flows through the system (end to end)

Follow one 10-minute slice of time through the whole machine:

1. **Sensor → SIEM.** Sysmon on the Windows box records every process start, network
   connection, and DNS lookup. The Wazuh agent ships these to the Wazuh manager,
   which (a) runs its rules and stores matches in the `wazuh-alerts-*` index, and (b)
   stores *everything* in the `wazuh-archives-*` index. (An **index** in
   OpenSearch/Elasticsearch is like a database table optimized for search.)

2. **Ingestion.** `scripts/run_pipeline.py` calls `IndexerClient`
   (`ingestion/indexer_client.py`) to pull the last few hours of raw Sysmon events
   into **pandas DataFrames** (a DataFrame = an in-memory table, like a spreadsheet).

3. **Features.** `features/combined.py` turns those thousands of raw event rows into
   a small table with **one row per (host, 10-minute window)** and columns of
   numbers like `proc_count`, `encoded_cmd`, `max_dns_entropy`. This numeric table is
   what ML can consume.

4. **Detection.** `detection/isolation_forest.py` scores each window `0.0`
   (totally normal) → `1.0` (very anomalous), using a model previously trained on a
   week of "normal" data. A per-host **BaselineStore** turns that raw score into a
   *percentile* ("this window is more anomalous than 97% of what this host normally
   does").

5. **Enrichment / fusion.** `enrichment/alert_fusion.py` combines, for each window,
   the ML result with any Wazuh rule alerts in the same window, applies the alerting
   policy, maps to MITRE ATT&CK techniques, assigns a provisional severity, and emits
   an **`EnrichedAlert`** — or nothing, if the window is unremarkable.

6. **Persist.** Each `EnrichedAlert` is written to `data/alerts.db` (SQLite) via
   `api/store.py`.

7. **Serve.** The FastAPI app (`api/main.py`) reads that DB and serves alerts to the
   browser dashboard. Separately, live telemetry (`api/stats.py`) is streamed to the
   dashboard for the animated charts.

8. **Copilot (on demand).** When you click "Run AI Analysis" on an alert, the API
   sends the `EnrichedAlert` to the copilot (`copilot/analyst.py`), which asks the
   local LLM (via `copilot/llm.py` → Ollama) for a structured analysis, validates it,
   and returns a report.

Steps 1–6 are an **offline batch job** (the pipeline). Steps 7–8 are the **live web
app**. They never call each other — they meet in the middle at the SQLite file. That
decoupling (batch writes, web reads) is a deliberate design choice: the dashboard
stays fast and works even if the pipeline or the LLM is down.

---

# 3. File by file (the files that matter)

I'll go layer by layer, bottom to top — the order data flows. For each file:
**purpose**, **depends on / used by**, **key functions** (what goes in → what comes
out, in plain English), and **new concepts** where relevant. Trivial and repetitive
files are grouped at the end so they don't drown out the important 20%.

## 3.0 The foundation

### `src/aisoc/config.py` — one place for all settings

- **Purpose:** hold every tunable setting (indexer URL, LLM model name, window size)
  in one object, loaded from environment variables or a `.env` file.
- **Used by:** almost everything (`from aisoc.config import settings`).
- **Key idea:** `Settings` inherits from pydantic's `BaseSettings`. At import time it
  reads env vars prefixed `AISOC_` (e.g. `AISOC_OLLAMA_MODEL`) and the `.env` file,
  falling back to the defaults written in the class. The line `settings = Settings()`
  at the bottom builds one shared instance the whole app imports.
- **New concept — configuration object / 12-factor config:** instead of scattering
  `"http://localhost:11434"` literals across the code, you centralize them and let
  the environment override them. That's how the same code runs on your laptop and on
  a server without edits. `window_minutes: int = 10` here is *the* definition of "a
  window is 10 minutes," referenced everywhere.

### `src/aisoc/enrichment/schemas.py` — THE contracts (read this first)

- **Purpose:** define the handful of objects that every layer passes around. This is
  the single most important file in the repo.
- **Depends on:** only pydantic. **Used by:** every layer.
- **New concept — pydantic `BaseModel` as a "data contract":** a `BaseModel` is a
  class where you declare fields with types, and pydantic *enforces* them at runtime
  — if someone tries to build one with a missing/wrong field, it raises an error
  immediately. It also gives you free JSON conversion (`.model_dump_json()` and
  `.model_validate_json()`). Think of it as a strongly-typed struct + a bouncer +
  a serializer, all in one. Because these objects can turn themselves into JSON and
  back, they travel cleanly across every boundary: function→function, Python→SQLite,
  API→browser, and app→LLM.
- **The objects:**
  - `Severity` — an `Enum` (a fixed set of allowed string values: `low/medium/high/
    critical`). Using an enum instead of raw strings means a typo like `"hgih"` can't
    slip through.
  - `MitreTechnique` — one ATT&CK technique, e.g. id `T1059.001`, name `PowerShell`,
    tactic `Execution`. (**MITRE ATT&CK** is the industry-standard catalog of attacker
    techniques; mapping alerts to it is what makes them "speak SOC.")
  - `RuleAlert` — one Wazuh rule hit, trimmed to the fields we need (`rule_id`,
    `description`, `level` on Wazuh's 0–15 scale, `timestamp`, optional `mitre`).
  - `MlDetection` — the ML result for one window: `anomaly_score` (0–1, and note
    `Field(ge=0.0, le=1.0)` makes pydantic *reject* out-of-range scores),
    `baseline_percentile`, `top_features` (which features drove it), `feature_snapshot`.
  - **`EnrichedAlert`** — the star of the show. It fuses everything about one
    suspicious `(host, window)`: the rule alerts, the ML detection, the merged MITRE
    list, a one-line `detected_behavior`, and a `severity`. Every layer upstream
    *produces* this; every layer downstream *consumes* it. `alert_id` and `created_at`
    use `Field(default_factory=...)` so each new alert auto-gets a unique id and a
    timestamp.
  - `CopilotAnalysis` — the structured output we force the LLM to return: explanation,
    attack interpretation, severity + rationale, investigation steps, containment
    steps, and `iocs` (indicators of compromise). The comment "*validated in analyst,
    not trusted*" is the key security stance — see §3.5.
  - `IncidentReport` — the final human-readable ticket (title, timeline, IOCs, MITRE
    table, and the full `markdown` string).

## 3.1 Ingestion — getting raw events out of the SIEM

### `src/aisoc/ingestion/indexer_client.py`

- **Purpose:** the one place that knows how to query the Wazuh datastore. Everything
  else asks *it* for data and gets back a clean pandas DataFrame.
- **Depends on:** `opensearch-py`, pandas, `config`. **Used by:** the pipeline
  scripts and `api/stats.py`.
- **New concept — OpenSearch / the "index":** Wazuh stores events in **OpenSearch**
  (an open-source fork of Elasticsearch — a search engine used as a database).
  Queries are JSON dictionaries, not SQL. The class hides that JSON behind normal
  Python methods. Two index patterns matter: `wazuh-alerts-*` (only rule matches) and
  `wazuh-archives-*` (literally every event — this is what ML learns "normal" from).
- **New concept — the "client wrapper" / adapter pattern:** `IndexerClient` is an
  **adapter**: it wraps a third-party library (`OpenSearch`) in an interface shaped
  for *our* needs. Benefit: if we ever swapped OpenSearch for something else, only
  this file changes.
- **Key methods:**
  - `fetch_events(index, start, end, query, size)` → **in:** an index name, a time
    range, an optional extra filter; **does:** builds the OpenSearch JSON query
    (time range + filter), runs it, and flattens the nested JSON results with
    `pd.json_normalize`; **out:** a DataFrame where nested fields become dotted
    columns like `data.win.eventdata.image`. (There's a `TODO` noting the 10k-row cap
    — a known limitation for busy days.)
  - `fetch_sysmon_process_events` / `_network_events` / `_dns_events` → convenience
    wrappers that pre-fill the filter for Sysmon Event IDs 1 (process), 3 (network),
    22 (DNS). **Out:** DataFrames of just those event types.
  - `fetch_rule_alerts(start, end, min_level)` → the Wazuh rule hits above a severity
    level, for the fusion layer.
  - `raw_search` / `cluster_status` → escape hatches used by the live-telemetry
    endpoint (aggregation queries and a health check).

## 3.2 Features — turning logs into numbers ML can use

This is classic feature engineering, which you'll recognize from ML work — the twist
is the **time-windowing** and the security-specific signals.

### `src/aisoc/features/windows.py` — shared time helpers

- **Purpose:** the shared trick that all feature families use: chop the timeline into
  fixed 10-minute buckets.
- **Key functions:**
  - `assign_windows(events)` → **in:** a DataFrame with a `timestamp` column; **does:**
    parses timestamps and adds a `window_start` column by "flooring" each timestamp to
    its 10-minute bucket (10:07 and 10:03 both → 10:00); **out:** the same DataFrame
    plus that column. This is what lets us later `groupby(host, window_start)`.
  - `label_windows(features, labels)` → **in:** the feature table + a table of known
    attack time-ranges (`simulations/labels.csv`); **out:** a boolean Series marking
    which windows overlap a real attack. This is the **ground truth** for evaluation.
    Note the asymmetric padding comment — a nice example of a subtle real-world bug
    (a boundary attack leaking into the previous window) fixed thoughtfully.

### `src/aisoc/features/process_features.py` — the first feature family

- **Purpose:** turn Sysmon process-creation events into 8 behavioral numbers per
  `(host, window)`.
- **Depends on:** `windows.assign_windows`, pandas. **Used by:** `combined.py`.
- **Key function `extract(process_events)`** → **in:** a DataFrame of raw EID-1
  events; **does:** a sequence of pandas `groupby` aggregations; **out:** a table with
  one row per `(host, window)` and columns:
  `proc_count`, `ps_count` (script-host launches), `encoded_cmd` (count of obfuscated
  command lines), `max_cmd_entropy`, `max_cmd_len`, `rare_proc_score`,
  `new_parent_child`, `burst_rate`. `FEATURE_COLUMNS` lists them in order — that order
  *is* the model's input contract.
- **New concept worth noting — Shannon entropy as a feature:** `command_line_entropy`
  measures the "randomness" of a command's text. Attackers hide payloads as base64
  blobs, which have distinctively high entropy (~5.5+ bits/char vs ~4.5 for normal
  commands). This is a great example of encoding domain knowledge into a number the
  model can use. "Rarity" and "first-seen parent→child pair" similarly encode "have I
  seen this before on this host?"

### `src/aisoc/features/network_features.py` — the second feature family

- **Purpose:** the same idea for network behavior, from Sysmon EID 3 (connections) +
  EID 22 (DNS). Produces 7 numbers per `(host, window)`:
  `net_conn_count`, `distinct_dest_ips`, `external_conn_count`, `distinct_dest_ports`,
  `dns_query_count`, `distinct_domains`, `max_dns_entropy`.
- **Standout feature — `max_dns_entropy`:** malware that uses **DGA** (Domain
  Generation Algorithms — randomly-generated command-and-control domains like
  `x7f3k9qz2m.com`) produces high-entropy domain names. Reusing the same entropy
  function on domains catches that. `is_external_ip` uses the stdlib `ipaddress`
  module to tell public IPs from private ones (a connection to `10.0.0.5` is
  internal/normal; to a random public IP, maybe not).
- **Honest limitation (documented in the file):** Sysmon doesn't record byte volumes,
  so there are no "bytes exfiltrated" features — that would need a different sensor
  (Suricata). The code says so rather than faking it.

### `src/aisoc/features/combined.py` — glue two families into one vector

- **Purpose:** merge process + network features into a single 15-column table so one
  model sees both dimensions at once.
- **Key function `build(process_events, network_events, dns_events)`** → **does:**
  calls each family's `extract`, then **outer-joins** them on `(host, window_start)`.
  **New concept — outer join + fillna(0):** an *outer join* keeps rows that exist in
  either table; a window with processes but no network activity gets `0` for the
  network columns. `0` is the correct default for count features ("zero connections
  that window"). **Out:** the combined feature table the detector trains/scores on.

## 3.3 Detection — the machine-learning core

### `src/aisoc/detection/isolation_forest.py` — the anomaly model

- **Purpose:** wrap scikit-learn's Isolation Forest into a small class that trains,
  scores, explains, saves, and loads.
- **New concept — Isolation Forest (the *why*, since you know ML):** it's an
  **unsupervised** anomaly detector. Intuition: it repeatedly makes random splits of
  the data; points that get "isolated" in very few splits are outliers (they sit
  alone, far from the crowd), while normal points need many splits to separate. No
  labels needed — you train it purely on "normal" data and it flags anything that
  doesn't fit. Perfect here because you can't label a week of your own activity by
  hand.
- **Key methods of `AnomalyDetector`:**
  - `fit(features)` → **in:** a table of assumed-normal windows; **does:**
    standardizes the columns with `StandardScaler` (z-scores: subtract mean, divide by
    std, so no single big-numbered feature dominates), fits the forest, and *stores the
    training score range* (`_smin/_smax`); **out:** the fitted detector.
  - `score(features)` → **in:** any feature table; **out:** a numpy array of `0→1`
    anomaly scores. It converts sklearn's raw score to 0–1 using the stored training
    range (so a given window always scores the same, independent of the batch it's in
    — a subtle but important correctness choice).
  - `top_contributing_features(window, k=3)` → **out:** the `k` feature names whose
    values deviate most from normal (by z-score). This is the "**why**" behind a
    score — it's what fills `top_features` and drives the MITRE mapping and the LLM's
    context. (Isolation Forest doesn't natively explain itself; this is a simple,
    honest approximation.)
  - `save(path)` / `load(path)` → **new concept — model serialization with joblib:**
    `joblib.dump` pickles the fitted scaler + forest + metadata into one `.joblib`
    file on disk, so `train_model.py` can save the model and `run_pipeline.py` can
    load the exact same trained object later. (joblib is the scikit-learn-recommended
    way to persist models with big numpy arrays.)

### `src/aisoc/detection/baseline.py` — per-entity "is this unusual *for you*?"

- **Purpose:** a small SQLite-backed store of past anomaly scores per host, so a raw
  score can be turned into a **percentile relative to that host's own history**.
- **Why it exists:** an anomaly score of 0.6 is meaningless in isolation. Is 0.6 high
  for *this* machine? The `BaselineStore` answers that: "0.6 is higher than 97% of
  what this host normally scores." That percentile is what the fusion layer thresholds
  on.
- **Key methods:** `record`/`record_many` (add scores), `percentile(entity, score)`
  (returns 0–100, or a neutral 50 if the host has no history yet — a nice guard so a
  brand-new machine isn't flagged as maximally anomalous), `reset` (wipe on retrain,
  because scores from an old model aren't comparable to a new one's).

### `src/aisoc/detection/evaluate.py` — grading the detector

- **Purpose:** given scores + true attack labels, compute detection quality.
- **Key function `evaluate(scores, labels, threshold_pct)`** → **out:** a dict of
  metrics: precision, recall, F1 at a chosen alert threshold, plus **ROC-AUC** and
  **PR-AUC** (threshold-free measures of how well the scores *rank* attacks above
  normal). `format_report` pretty-prints it. This is the honest "does it actually
  work?" tooling — it needs the labeled attack windows from `simulations/labels.csv`.

## 3.4 Enrichment — fusing signals into alerts

### `src/aisoc/enrichment/mitre.py` — features → attacker techniques

- **Purpose:** a lookup table mapping an ML feature to the MITRE technique it hints
  at (`encoded_cmd → T1059.001 PowerShell`, `max_dns_entropy → T1568.002 DGA`, etc.).
- **Key function `map_ml_detection(top_features)`** → **in:** the driving feature
  names; **out:** a de-duplicated list of `MitreTechnique`. Wazuh rule alerts already
  carry their own MITRE tags; this only labels the *ML-originated* signal.

### `src/aisoc/enrichment/alert_fusion.py` — the decision logic (important)

- **Purpose:** the brain of the "combine two opinions" thesis. For each window,
  decide whether to emit an `EnrichedAlert` and how severe it is.
- **Depends on:** `schemas`, `mitre`. **Used by:** `run_pipeline.py`.
- **Key functions:**
  - `fuse_window(host, window, rule_alerts, ml_detection, ...)` → **the alerting
    policy.** It emits an alert only if **(a)** a significant Wazuh rule
    (level ≥ 7) fired, **or (b)** the ML score is above the 95th percentile *and* is
    corroborated (a rule in the same window, or a sustained streak). "Anomaly alone
    never pages" is enforced right here. **Out:** an `EnrichedAlert` or `None`.
  - `_heuristic_severity(...)` → **the thesis in code.** Severity comes from
    *agreement*: a loud rule with a *normal* ML score is only MEDIUM ("investigate,
    don't escalate"); HIGH/CRITICAL require the rule **and** the ML anomaly to concur.
    This is the exact logic that stops noisy "executable dropped" rules from screaming
    HIGH all day.
  - `fuse_stream(windows)` → **in:** a chronological list of per-window records;
    **does:** walks them in order, tracking each host's streak of consecutive
    anomalous windows (so a slow, sustained deviation counts as corroboration even
    with no rule); **out:** the list of `EnrichedAlert`s. This is what the pipeline
    actually calls.

## 3.5 Copilot — the local-LLM analyst

### `src/aisoc/copilot/llm.py` — the thin LLM client

- **Purpose:** the only file that knows how to talk to the LLM. Wraps **Ollama**'s
  HTTP API. Swapping LLM providers = changing this one file.
- **Key methods:**
  - `generate_json(system, prompt, schema)` → **new concept — constrained/structured
    output:** it passes a JSON Schema as Ollama's `format` parameter, which forces the
    model to return JSON matching *exactly* that shape. Instead of hoping the model
    replies in the right format and regex-parsing prose, you get guaranteed-valid JSON
    you can hand straight to pydantic. `temperature: 0.1` keeps it nearly
    deterministic (important for a security tool). **Out:** a parsed dict.
  - `generate_text(system, prompt)` → free-form prose, used only for the report's
    one-paragraph summary.

### `src/aisoc/copilot/prompts.py`

- **Purpose:** the instruction text sent to the LLM (system prompts + task template),
  kept out of the logic. It literally spells out the analyst persona and the
  grounding rules ("only cite indicators present in the alert").

### `src/aisoc/copilot/analyst.py` — analyze + *ground* the output

- **Purpose:** run the LLM on one `EnrichedAlert` and return a **trustworthy**
  `CopilotAnalysis`.
- **Key function `analyze(alert, llm)`** → **does:** serialize the alert to JSON,
  ask the LLM for a `CopilotAnalysis`-shaped answer, validate it with pydantic, then
  **ground the IOCs**. **Out:** a validated `CopilotAnalysis`.
- **New concept — "grounding" (the key security idea):** LLMs hallucinate. In a
  security tool, a made-up IP address is dangerous. `_resolve_iocs` throws away any
  indicator the model cited that does **not** literally appear in the input alert, and
  independently extracts the definitely-real ones (host, user, rule IDs, `.exe` names)
  straight from the alert structure. So the IOC list is trustworthy *by construction*,
  not by trusting the model. The design maxim: "a wrong IOC is worse than a missing
  one."

### `src/aisoc/copilot/report.py` — render the incident ticket

- **Purpose:** turn an alert + its analysis into a Markdown SOC ticket.
- **Key design choice (same spirit as grounding):** every *factual* section — the
  timeline (from real timestamps), the IOC list, the MITRE table — is built
  **deterministically in Python code**, and the LLM is used *only* for the prose
  summary. Facts the model can't touch can't be hallucinated. **Out:** an
  `IncidentReport` whose `.markdown` is the full ticket.

### `src/aisoc/copilot/sample_alert.py`

- **Purpose:** hand-written example `EnrichedAlert`s used for demos, tests, and seeding
  the dashboard before the real pipeline has produced anything.

## 3.6 API — the web boundary

### `src/aisoc/api/store.py` — the SQLite persistence layer

- **Purpose:** the shared "blackboard." The batch pipeline *writes* alerts here; the
  web app *reads* them. Three tables: `alerts`, `analyses`, `feedback`.
- **New concept — persistence via serialized objects:** rather than one DB column per
  alert field, `save_alert` stores the whole `EnrichedAlert` as one JSON blob
  (`alert.model_dump_json()`) plus a few duplicated columns (host, severity) for
  sorting. `list_alerts`/`get_alert` read the blob back and `EnrichedAlert.
  model_validate_json` rebuilds the object. This is a pragmatic middle ground between
  a full ORM (Object-Relational Mapper — a library that auto-maps classes to DB
  tables) and raw SQL. `INSERT OR REPLACE` = "upsert" (insert, or overwrite if the id
  already exists).
- **The `feedback` table** is the newest piece: it records an analyst's verdict
  (`true_positive` / `false_positive` / `benign`) per alert — the labeled signal for a
  future "learn from corrections" loop.

### `src/aisoc/api/stats.py` — live telemetry for the dashboard

- **Purpose:** one read-only function, `gather()`, that runs a handful of OpenSearch
  **aggregation** queries and returns a compact JSON blob: events-per-minute (last
  hour), event-type mix, a live feed of the latest 20 events, and sensor/model health.
  The dashboard polls this every few seconds to drive its animated charts. Wrapped in
  a `try/except` so it degrades gracefully (returns `ok: false`) if the indexer is
  down, rather than crashing the endpoint.

### `src/aisoc/api/main.py` — the FastAPI application

- **Purpose:** define the HTTP endpoints (the API) and serve the dashboard. This is
  the web entry point (`app` is what `uvicorn` runs).
- **New concept — FastAPI + decorators + ASGI:** each `@app.get("/alerts")` is a
  **decorator** that registers the function below it as the handler for that URL +
  HTTP method. FastAPI reads the function's type hints to auto-validate inputs and
  auto-serialize outputs — e.g. `-> list[EnrichedAlert]` means FastAPI turns the
  returned objects into JSON *and* documents the response shape automatically. You
  never write JSON-parsing code. `raise HTTPException(404, ...)` becomes a proper HTTP
  404 response.
- **New concept — middleware:** `app.add_middleware(CORSMiddleware, ...)` wraps every
  request/response. **Middleware** = code that runs around every request (like an
  airport security lane everyone passes through). **CORS** (Cross-Origin Resource
  Sharing) is a browser security rule; enabling it lets the dashboard call the API.
- **The endpoints (the system's public surface):**
  - `GET /` → serves `dashboard/index.html` (with `no-store` headers so the browser
    never shows a stale cached copy — a real bug that was fixed).
  - `GET /health`, `GET /copilot/health` → liveness checks (is the app up? is Ollama
    reachable?).
  - `GET /stats` → the live telemetry from `stats.gather()`.
  - `GET /alerts`, `GET /alerts/{id}` → read alerts from the store.
  - `POST /alerts/{id}/analyze` → run the copilot on one alert, cache + return the
    `CopilotAnalysis`. Returns HTTP 503 if Ollama is down (handled, not crashed).
  - `POST /alerts/{id}/report` → the full Markdown incident report (analyzes first if
    needed). It's a `POST`, not `GET`, because it has side effects (runs the LLM,
    writes to the DB) — a REST convention.
  - `GET /feedback`, `POST /alerts/{id}/feedback` → read/write analyst verdicts.

## 3.7 Scripts — the entry points that drive the package

- **`scripts/train_model.py`** — pull ~a week of events, `combined.build` the
  features, *exclude labeled attack windows* (so the model learns only clean
  "normal"), fit the `AnomalyDetector`, `save` it, and seed the `BaselineStore` with
  the training scores. Run this first, and again weekly.
- **`scripts/run_pipeline.py`** — the full offline chain: fetch recent events →
  `combined.build` → `detector.score` → per-host `BaselineStore.percentile` →
  `fuse_stream` → write `EnrichedAlert`s to the store. This is the file to read to see
  every layer wired together in ~130 lines. It also maps raw Wazuh rule-alert rows
  into `RuleAlert` objects (`_rule_alerts_by_window`).
- **`scripts/evaluate.py`** — load the model, score the window(s) around each labeled
  attack, and print precision/recall/ROC-AUC via `detection.evaluate`.
- **`scripts/seed_alerts.py`** — write the hand-made `sample_alert` examples into the
  DB so the dashboard has something to show immediately.
- **`scripts/*.ps1`** (PowerShell) — Windows operations helpers: `restore-collection`
  (one command to recover after Docker/the agent falls over), `run-pipeline-loop` /
  `register-pipeline-task` (run the pipeline on a schedule). Ops glue, not product
  logic.

## 3.8 The frontend

### `dashboard/index.html`

- **Purpose:** the entire "mission control" UI in one self-contained file — HTML +
  inline CSS + vanilla JavaScript, no build step, no frameworks. It's served as-is by
  `GET /`.
- **How it works:** on load and on a timer, its JavaScript `fetch()`es the API
  (`/alerts`, `/stats`, `/feedback`), then rebuilds the page: the KPI counters, the
  threat-posture ring, the animated event-rate chart, the live event feed, the alert
  list, and the detail panel. Clicking "Run AI Analysis" `POST`s to
  `/alerts/{id}/analyze` and renders the returned `CopilotAnalysis`. It's a
  **single-page app** in the most literal sense — one file, talking to the API over
  HTTP.
- **Note:** `dashboard/app.py` is an **older Streamlit version** of the dashboard,
  kept for reference but superseded by `index.html`. You can ignore it.

## 3.9 Grouped: the trivial / repetitive files

- **`__init__.py` (one per package folder)** — marks a folder as an importable Python
  package; a few also re-export a name (e.g. `ingestion/__init__.py` exposes
  `IndexerClient`). Nothing to study.
- **`tests/test_*.py`** — one pytest file per module. Read these as *usage examples*:
  they show the intended inputs/outputs of each function (e.g. `test_alert_fusion.py`
  encodes the exact severity-by-agreement rules). Notable: `test_api.py` uses
  FastAPI's `TestClient` to call endpoints in-process without a running server.
- **`features/auth_features.py`** — a stub/placeholder for a future third feature
  family (login/auth behavior). Not wired in yet.
- **Config/boilerplate:** `pyproject.toml` (package name, dependency list, tool
  config), `.env.example` (template you copy to `.env`), `.github/workflows/ci.yml`
  (runs `ruff` + `pytest` on every push), `.gitignore`, `.pytest_cache/`,
  `scratch_reports/` (throwaway LLM outputs). None affect runtime behavior.
- **`docs/*.md`, `docker/README.md`, `simulations/README.md`** — prose docs and
  runbooks. `simulations/labels.csv` is the one data file that *matters*: it records
  the time windows of simulated attacks and is the ground truth for evaluation.

---

# 4. The glue — how the pieces actually talk

## The three ways components communicate

Real systems connect their parts in a few distinct ways. This one uses three, and
knowing *which* is used *where* is most of "getting" the architecture:

1. **Direct function calls (inside the batch pipeline).** Within a single run of
   `scripts/run_pipeline.py`, the layers just call each other:
   `combined.build(...)` → `detector.score(...)` → `baseline.percentile(...)` →
   `fuse_stream(...)`. Data is passed as Python objects (DataFrames, then
   `EnrichedAlert`s). This is the fast, in-process path.

2. **A shared database (between the pipeline and the web app).** The pipeline and the
   FastAPI server are **separate processes** that never call each other. They
   communicate through `data/alerts.db`: the pipeline `save_alert`s, the API
   `list_alerts`. **New concept — the "blackboard" / shared-store integration
   pattern:** decoupling producers and consumers through a shared datastore means
   either side can restart, run on a schedule, or fail without taking the other down.
   The trade-off is they're only as fresh as the last pipeline run.

3. **HTTP (between browser ↔ API, and API ↔ LLM).** The dashboard talks to the API
   over HTTP/JSON (`fetch("/alerts")`). The API talks to Ollama over HTTP/JSON
   (`httpx.post(".../api/chat")`). **New concept — this is a client/server boundary:**
   both sides only agree on the *shape of the JSON*, not on each other's code. That's
   exactly why the pydantic schemas matter so much — they define that JSON shape.

```
 pipeline run (one process)         web app (another process)
 ────────────────────────           ─────────────────────────
 ingestion ─┐                        browser ──HTTP──► FastAPI
 features  ─┤ direct calls                              │ reads
 detection ─┤ (Python objects)                          ▼
 enrichment ┘ ───► save_alert ──►  [ data/alerts.db ] ◄─ list_alerts
                                                        │
                                        analyze ──HTTP──► Ollama (LLM)
```

## The key data structures everything revolves around

If you only memorize a few objects, memorize these — they are the "nouns" of the
whole system:

- **The feature DataFrame** — a pandas table with columns `host`, `window_start`, and
  the 15 feature numbers. This is the *only* thing the ML model ever sees. Produced by
  `combined.build`, consumed by `AnomalyDetector`.
- **`MlDetection`** — the ML verdict for one window (score, percentile, top features).
- **`RuleAlert`** — one SIEM rule hit for one window.
- **`EnrichedAlert`** — *the* central object. Everything before it exists to build it;
  everything after it exists to consume it. If you trace only one object through the
  code, trace this one.
- **`CopilotAnalysis` / `IncidentReport`** — the LLM's structured verdict and the
  final rendered ticket.
- **The "window record" dict** — a plain `{host, window_start, window_end,
  rule_alerts, ml_detection}` dict that `run_pipeline.py` builds and hands to
  `fuse_stream`. It's the pipeline's internal hand-off format, one step before the
  `EnrichedAlert`.

## What each external library actually does for us

| Library | What it does here | Mental model |
|---|---|---|
| **pandas** | holds raw events + feature tables; `groupby`/aggregation does the feature math | in-memory Excel with a Python API |
| **scikit-learn** | provides `IsolationForest` (the detector) and `StandardScaler` (the z-scoring) | the ML toolbox |
| **joblib** | saves/loads the fitted model as a `.joblib` file | `pickle` optimized for numpy |
| **pydantic** | defines + validates + (de)serializes every cross-layer object | typed structs with a bouncer and a JSON port |
| **FastAPI** | maps URLs to Python functions, auto-validates/serializes via type hints | the web framework (the receptionist that routes calls) |
| **uvicorn** | the actual server process that listens on the port and runs FastAPI | the engine under FastAPI |
| **httpx** | makes HTTP calls (API→Ollama; tests→API) | `requests`, but supports async + a test client |
| **opensearch-py** | sends JSON queries to the Wazuh datastore, returns results | the database driver for OpenSearch |
| **sqlite3** (stdlib) | the single-file database behind the store | a database in one `.db` file, zero setup |
| **Ollama** (external) | runs the local LLM and exposes it over HTTP | a local ChatGPT-in-a-box |

---

# 5. Cheat sheet — the one-page mental model

## The whole system in one breath

> Sysmon watches the machine → Wazuh stores every event → the **pipeline** pulls
> events, turns them into per-10-minute **feature rows**, an **Isolation Forest**
> scores each row for anomaly, the **fusion** layer combines that score with Wazuh's
> rule alerts and emits an **`EnrichedAlert`** (only escalating to HIGH when *both*
> agree), which is saved to a **SQLite** file → a **FastAPI** app serves those alerts
> to a **browser dashboard**, and on click a local **LLM copilot** writes a grounded,
> plain-English incident report.

## Key files, in priority order

| # | File | Why it matters |
|---|---|---|
| 1 | `enrichment/schemas.py` | the data contracts; defines `EnrichedAlert` — start here |
| 2 | `scripts/run_pipeline.py` | the whole batch flow wired together in one place |
| 3 | `enrichment/alert_fusion.py` | the "combine two opinions" decision logic + severity |
| 4 | `features/combined.py` + `process_/network_features.py` | logs → numbers |
| 5 | `detection/isolation_forest.py` | the ML model wrapper (train/score/explain) |
| 6 | `copilot/analyst.py` | the LLM analyst + IOC grounding (the anti-hallucination bit) |
| 7 | `api/main.py` | the web endpoints + serving the dashboard |
| 8 | `api/store.py` | the SQLite blackboard that connects pipeline and web app |
| 9 | `dashboard/index.html` | the single-file UI |

## Key terms glossary

- **SOC / SIEM** — the security team's room / the software logbook+rules they use
  (here, Wazuh).
- **Sysmon** — a Windows sensor that emits detailed events (EID 1 process, 3 network,
  22 DNS).
- **OpenSearch / index** — the search-engine database Wazuh stores events in / a
  search-optimized "table."
- **Window** — a fixed 10-minute time bucket; the unit of ML analysis, keyed by
  `(host, window_start)`.
- **Feature** — a number summarizing behavior in a window (e.g. `max_dns_entropy`).
- **Isolation Forest** — unsupervised anomaly detector; trained only on "normal."
- **Baseline percentile** — how unusual a score is *for that specific host*.
- **Fusion** — combining rule alerts + ML score into one decision.
- **`EnrichedAlert`** — the central object carrying everything about one detection.
- **MITRE ATT&CK** — the standard catalog of attacker techniques (e.g. `T1059.001`).
- **Grounding** — dropping any LLM-cited indicator not literally present in the input,
  so the copilot can't hallucinate evidence.
- **pydantic model** — a typed, self-validating, JSON-convertible object.
- **FastAPI / decorator / endpoint** — the web framework / the `@app.get(...)` that
  registers a function for a URL / one such URL handler.
- **Middleware** — code that runs around every HTTP request (here, CORS).
- **Blackboard pattern** — decoupling two processes via a shared datastore (the
  SQLite file) instead of direct calls.

## How to trace any feature end-to-end

**Example: "An alert shows up on the dashboard. Where did it come from?"** Walk it
backwards through the layers:

1. The browser called `GET /alerts` → `api/main.py:list_alerts()` →
   `store.list_alerts()` read it from `data/alerts.db`.
2. It got into the DB because a run of `scripts/run_pipeline.py` called
   `store.save_alert()`.
3. The pipeline created it in `fuse_stream()` (`enrichment/alert_fusion.py`), which
   decided it crossed the alerting policy and set its severity.
4. Fusion's inputs were: an `MlDetection` (from `detector.score()` +
   `baseline.percentile()`) and any `RuleAlert`s (from
   `IndexerClient.fetch_rule_alerts()`).
5. The `MlDetection` came from scoring a **feature row** built by
   `features/combined.build()` from raw Sysmon events pulled by
   `IndexerClient.fetch_sysmon_*()`.
6. Those raw events came from Wazuh, which got them from Sysmon on the machine.

**Example: "I clicked Run AI Analysis. What happened?"**
Browser `POST /alerts/{id}/analyze` → `main.py:analyze_alert()` →
`copilot/analyst.analyze(alert)` → `llm.generate_json(...)` (HTTP to Ollama with a
JSON-schema constraint) → pydantic-validate the reply → `_resolve_iocs` grounds the
indicators → cached in the `analyses` table → returned as JSON → rendered by the
dashboard's JavaScript.

**The single mental hook:** *everything is a pipeline that builds one
`EnrichedAlert`, and the web app is just a window onto the pile of alerts that
pipeline produced.*

---

*End of guide. To go deeper, open the files in the priority order above, starting
with `enrichment/schemas.py`, then read `scripts/run_pipeline.py` top to bottom with
this map beside you — it touches every layer in sequence.*
