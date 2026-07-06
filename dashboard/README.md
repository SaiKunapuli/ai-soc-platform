# Dashboard (Phase 5)

Streamlit v1 — pure Python, free, fast to build. Planned views:

- **Active alerts** — severity-sorted EnrichedAlerts from the API, filterable by host/user
- **ML insights** — most anomalous entities today, score timelines per entity
- **Incident view** — full copilot analysis + rendered incident report for one alert

Install: `pip install -e ".[dashboard]"` · Run: `streamlit run dashboard/app.py`

React rewrite only if the project outgrows Streamlit (see design decision #8).
