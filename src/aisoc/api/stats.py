"""Live telemetry for the mission-control dashboard.

Aggregates recent activity from the Wazuh archives into a compact JSON blob the
dashboard polls: event-rate time series, event-type mix, a live event feed, and
sensor/model health. Read-only; safe to call frequently.
"""

from datetime import datetime, timezone
from pathlib import Path

from aisoc.ingestion import IndexerClient
from aisoc.ingestion.indexer_client import ARCHIVES_INDEX

MODEL_PATH = Path("models/process_if.joblib")
SYSMON = "Microsoft-Windows-Sysmon/Operational"
EID_LABEL = {
    "1": "process", "3": "network", "22": "dns", "11": "file",
    "13": "registry", "8": "remotethread", "5": "procterm", "2": "filetime",
}


def _detail(source: dict) -> str:
    ed = source.get("data", {}).get("win", {}).get("eventdata", {})
    val = ed.get("image") or ed.get("destinationIp") or ed.get("queryName") or ed.get("targetFilename") or ""
    if "\\" in val:
        val = val.split("\\")[-1]
    return val[:44]


def gather() -> dict:
    c = IndexerClient()
    out: dict = {"ok": True}

    try:
        # events/min, last 60 min (all events)
        r = c.raw_search(ARCHIVES_INDEX, {
            "size": 0, "query": {"range": {"timestamp": {"gte": "now-60m"}}},
            "aggs": {"pm": {"date_histogram": {"field": "timestamp", "fixed_interval": "1m"}}},
        })
        out["events_per_min"] = [b["doc_count"] for b in r["aggregations"]["pm"]["buckets"]]

        # event-type mix, last 30 min (Sysmon)
        r2 = c.raw_search(ARCHIVES_INDEX, {
            "size": 0,
            "query": {"bool": {"must": [
                {"match": {"data.win.system.channel": SYSMON}},
                {"range": {"timestamp": {"gte": "now-30m"}}}]}},
            "aggs": {"eid": {"terms": {"field": "data.win.system.eventID", "size": 12}}},
        })
        mix = {}
        for b in r2["aggregations"]["eid"]["buckets"]:
            mix[EID_LABEL.get(b["key"], f"eid{b['key']}")] = b["doc_count"]
        out["event_types"] = mix

        # live event feed (last 20 Sysmon events)
        r3 = c.raw_search(ARCHIVES_INDEX, {
            "size": 20, "sort": [{"timestamp": "desc"}],
            "query": {"match": {"data.win.system.channel": SYSMON}},
        })
        feed = []
        for h in r3["hits"]["hits"]:
            s = h["_source"]
            eid = s.get("data", {}).get("win", {}).get("system", {}).get("eventID", "")
            feed.append({"time": s["timestamp"][11:19], "type": EID_LABEL.get(eid, eid), "detail": _detail(s)})
        out["feed"] = feed

        # collecting? (events in last 5 min) + freshness
        r4 = c.raw_search(ARCHIVES_INDEX, {
            "size": 1, "sort": [{"timestamp": "desc"}],
            "query": {"term": {"data.win.system.eventID": "1"}},
        })
        if r4["hits"]["hits"]:
            last = r4["hits"]["hits"][0]["_source"]["timestamp"]
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds()
            out["last_event_sec"] = int(age)
            out["collecting"] = age < 300
        else:
            out["last_event_sec"] = None
            out["collecting"] = False
    except Exception as exc:
        out["ok"] = False
        out["error"] = str(exc)

    out["indexer_status"] = c.cluster_status()
    if MODEL_PATH.exists():
        out["model"] = {"trained": True, "mtime": int(MODEL_PATH.stat().st_mtime)}
    else:
        out["model"] = {"trained": False}
    return out
