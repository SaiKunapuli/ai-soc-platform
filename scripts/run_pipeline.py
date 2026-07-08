"""Run the full detection pipeline over a time range on REAL data.

    ingest (Sysmon + Wazuh rule alerts)
      -> features
      -> anomaly score (saved model)
      -> per-host baseline percentile
      -> fusion (alert policy)
      -> EnrichedAlerts written to the store

Usage:
    python scripts/run_pipeline.py                 # last 6 hours
    python scripts/run_pipeline.py --hours 12

This proves Phases 2->3->4->5 connect on live data. Detection quality depends on
the model; the wiring is what this validates.
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.api.store import AlertStore
from aisoc.config import settings
from aisoc.detection.baseline import BaselineStore
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.enrichment import alert_fusion as af
from aisoc.enrichment.schemas import MitreTechnique, MlDetection, RuleAlert
from aisoc.features import combined
from aisoc.features.windows import assign_windows
from aisoc.ingestion import IndexerClient

MODEL_PATH = Path("models/process_if.joblib")


def _rule_alerts_by_window(raw: pd.DataFrame) -> dict[tuple, list[RuleAlert]]:
    """Group Wazuh rule alerts into (host, window_start) buckets as RuleAlert objects."""
    if raw.empty:
        return {}
    raw = assign_windows(raw)
    out: dict[tuple, list[RuleAlert]] = {}
    for _, r in raw.iterrows():
        host = r.get("agent.name", "unknown")
        mitre = []
        ids = r.get("rule.mitre.id")
        if isinstance(ids, list):
            techs = r.get("rule.mitre.technique") or [""] * len(ids)
            tacs = r.get("rule.mitre.tactic") or [""] * len(ids)
            mitre = [
                MitreTechnique(technique_id=str(i), name=str(t), tactic=str(ta))
                for i, t, ta in zip(ids, techs, tacs)
            ]
        alert = RuleAlert(
            rule_id=str(r.get("rule.id", "?")),
            description=str(r.get("rule.description", "")),
            level=int(r.get("rule.level", 0) or 0),
            timestamp=r["window_start"].to_pydatetime(),
            mitre=mitre,
        )
        out.setdefault((host, r["window_start"]), []).append(alert)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6.0)
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    if not MODEL_PATH.exists():
        raise SystemExit("no model — run scripts/train_model.py first")
    detector = AnomalyDetector.load(MODEL_PATH)

    client = IndexerClient()
    proc = client.fetch_sysmon_process_events(start, end)
    net = client.fetch_sysmon_network_events(start, end)
    dns = client.fetch_sysmon_dns_events(start, end)
    if proc.empty and net.empty:
        raise SystemExit("no Sysmon events in range")
    features = combined.build(proc, net, dns)
    print(f"{len(features)} feature windows over the last {args.hours}h")

    # score + per-host baseline percentile against ACCUMULATED history (BaselineStore),
    # not just this batch — so a window is ranked against everything the host has done.
    # Compute all percentiles against current history first, then append the new scores.
    features = features.reset_index(drop=True)
    features["score"] = detector.score(features[combined.FEATURE_COLUMNS])
    baseline = BaselineStore()
    features["pct"] = [
        baseline.percentile(row["host"], row["score"]) for _, row in features.iterrows()
    ]
    for host, grp in features.groupby("host"):
        baseline.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))

    rules = _rule_alerts_by_window(client.fetch_rule_alerts(start, end, min_level=1))

    window_delta = timedelta(minutes=settings.window_minutes)
    records = []
    for _, row in features.iterrows():
        ws = pd.to_datetime(row["window_start"], utc=True).to_pydatetime()
        ml = MlDetection(
            anomaly_score=float(row["score"]),
            baseline_percentile=float(row["pct"]),
            top_features=detector.top_contributing_features(row),
            feature_snapshot={c: float(row[c]) for c in combined.FEATURE_COLUMNS},
        )
        records.append(
            {
                "host": row["host"],
                "window_start": ws,
                "window_end": ws + window_delta,
                "rule_alerts": rules.get((row["host"], row["window_start"]), []),
                "ml_detection": ml,
            }
        )

    alerts = af.fuse_stream(records)
    store = AlertStore()
    for a in alerts:
        store.save_alert(a)

    print(f"emitted {len(alerts)} EnrichedAlert(s) -> store")
    for a in alerts:
        sev = a.severity.value if a.severity else "?"
        print(f"  [{sev:<8}] {a.window_start:%H:%M}  {a.detected_behavior[:60]}")
    if not alerts:
        print("  (no window crossed the alert policy — expected if nothing anomalous+corroborated)")


if __name__ == "__main__":
    main()
