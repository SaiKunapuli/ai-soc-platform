"""AI SOC Platform dashboard (Streamlit).

Reads alerts from the FastAPI backend and runs the copilot on demand.
Run the API first (uvicorn aisoc.api.main:app), then:
    streamlit run dashboard/app.py
"""

import httpx
import streamlit as st

from aisoc.config import settings

API = settings.api_base_url
SEV_COLOR = {"critical": "#7c1d1d", "high": "#b91c1c", "medium": "#b45309", "low": "#15803d"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}

st.set_page_config(page_title="AI SOC Platform", page_icon="🛡️", layout="wide")


def api_get(path: str, timeout: float = 30):
    """GET -> (ok, payload_or_error_message)."""
    try:
        r = httpx.get(f"{API}{path}", timeout=timeout)
        if r.status_code == 200:
            return True, r.json()
        detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
        return False, f"{r.status_code}: {detail}"
    except httpx.TimeoutException:
        return False, "timed out — the model may still be loading; try again in a moment"
    except Exception as exc:
        return False, f"cannot reach API at {API} ({exc})"


def api_post(path: str, timeout: float = 300):
    try:
        r = httpx.post(f"{API}{path}", timeout=timeout)
        if r.status_code == 200:
            return True, r.json()
        detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
        return False, f"{r.status_code}: {detail}"
    except httpx.TimeoutException:
        return False, "timed out — first analysis loads the model into RAM and can take a while; try again"
    except Exception as exc:
        return False, f"cannot reach API at {API} ({exc})"


@st.cache_data(ttl=10)
def fetch_alerts() -> list[dict]:
    ok, payload = api_get("/alerts")
    if not ok:
        st.error(f"Cannot load alerts — {payload}")
        return []
    return payload


def sev_badge(sev: str | None) -> str:
    color = SEV_COLOR.get(sev or "", "#555")
    return (
        f"<span style='background:{color};color:#fff;padding:2px 8px;"
        f"border-radius:4px;font-size:0.8em;font-weight:600'>{(sev or 'n/a').upper()}</span>"
    )


st.title("🛡️ AI SOC Platform")
st.caption("Behavioral anomaly detection + LLM incident-response copilot on a Wazuh base")

alerts = sorted(fetch_alerts(), key=lambda a: SEV_ORDER.get(a.get("severity"), 4))

# --- top metrics ---
counts = {s: sum(1 for a in alerts if a.get("severity") == s) for s in ("critical", "high", "medium", "low")}
cols = st.columns(5)
cols[0].metric("Total alerts", len(alerts))
cols[1].metric("Critical", counts["critical"])
cols[2].metric("High", counts["high"])
cols[3].metric("Medium", counts["medium"])
cols[4].metric("Low", counts["low"])
st.divider()

if not alerts:
    st.info("No alerts. Seed some with `python scripts/seed_alerts.py`, or wait for the pipeline.")
    st.stop()

left, right = st.columns([1, 2], gap="large")

with left:
    st.subheader("Alerts")
    labels = [f"{(a.get('severity') or 'n/a').upper()} · {a['host']} · {a['detected_behavior'][:40]}" for a in alerts]
    idx = st.radio("Select an alert", range(len(alerts)), format_func=lambda i: labels[i], label_visibility="collapsed")

alert = alerts[idx]

with right:
    st.markdown(f"### {alert['detected_behavior']}  {sev_badge(alert.get('severity'))}", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("Host", alert["host"])
    c2.metric("User", alert.get("user") or "n/a")
    if alert.get("ml"):
        c3.metric("Anomaly score", f"{alert['ml']['anomaly_score']:.2f}",
                  f"{alert['ml'].get('baseline_percentile', 0):.0f}th pct" if alert['ml'].get('baseline_percentile') else None)

    if alert.get("mitre"):
        st.markdown("**MITRE ATT&CK**")
        st.table([{"Technique": t["technique_id"], "Name": t["name"], "Tactic": t["tactic"]} for t in alert["mitre"]])

    if alert.get("rule_alerts"):
        st.markdown("**Wazuh rule alerts**")
        st.table([{"Rule": r["rule_id"], "Level": r["level"], "Description": r["description"]} for r in alert["rule_alerts"]])

    st.divider()
    st.markdown("#### 🤖 AI Copilot")
    if st.button("Analyze this alert", type="primary"):
        with st.spinner("Running local LLM analysis… (first run loads the model into RAM)"):
            ok, payload = api_post(f"/alerts/{alert['alert_id']}/report")
        if ok:
            st.markdown(payload["markdown"])
        else:
            st.error(f"Analysis failed — {payload}")
    else:
        ok, payload = api_get(f"/alerts/{alert['alert_id']}/analysis")
        if ok:
            st.success(f"Cached analysis — severity **{payload['severity']}**")
            st.write(payload["explanation"])
        else:
            st.caption("Not analyzed yet. Click **Analyze** to run the copilot.")
