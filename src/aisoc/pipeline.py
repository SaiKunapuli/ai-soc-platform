"""Shared detection pipeline — importable from any script or module.

This is the core detection chain extracted from run_pipeline.py so it can be
reused by the self-learning pipeline, test harnesses, and other tools without
code duplication.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.config import settings
from aisoc.detection.baseline import BaselineStore
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.enrichment import alert_fusion as af
from aisoc.enrichment.schemas import EnrichedAlert, MitreTechnique, MlDetection, RuleAlert
from aisoc.features import combined
from aisoc.features.process_history import ProcessHistoryStore
from aisoc.features.windows import assign_windows
from aisoc.ingestion import IndexerClient

DEFAULT_MODEL_PATH = Path("models/process_if.joblib")


def rule_alerts_by_window(raw: pd.DataFrame) -> dict[tuple, list[RuleAlert]]:
    """Group Wazuh rule alerts into (host, window_start) buckets."""
    if raw.empty:
        return {}
    raw = assign_windows(raw)
    out: dict[tuple, list[RuleAlert]] = {}
    for _, r in raw.iterrows():
        host = r.get("agent.name", "unknown")
        mitre: list[MitreTechnique] = []
        ids = r.get("rule.mitre.id")
        if isinstance(ids, list):
            techs = r.get("rule.mitre.technique") or [""] * len(ids)
            tacs = r.get("rule.mitre.tactic") or [""] * len(ids)
            mitre = [
                MitreTechnique(technique_id=str(i), name=str(t), tactic=str(ta))
                for i, t, ta in zip(ids, techs, tacs)
            ]
        alert_rule = RuleAlert(
            rule_id=str(r.get("rule.id", "?")),
            description=str(r.get("rule.description", "")),
            level=int(r.get("rule.level", 0) or 0),
            timestamp=r["window_start"].to_pydatetime(),
            mitre=mitre,
        )
        out.setdefault((host, r["window_start"]), []).append(alert_rule)
    return out


def run_detection(
    hours: float = 6.0, *, model_path: Path | None = None
) -> list[EnrichedAlert]:
    """Run the full detection chain and return alerts (without saving).

    Args:
        hours: Lookback window in hours from now.
        model_path: Path to the trained model. Defaults to models/process_if.joblib.

    Returns:
        List of EnrichedAlert objects emitted by the fusion layer.
    """
    mp = model_path or DEFAULT_MODEL_PATH
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    if not mp.exists():
        raise SystemExit("no model -- run scripts/train_model.py first")
    detector = AnomalyDetector.load(mp)

    client = IndexerClient()
    proc = client.fetch_sysmon_process_events(start, end)
    net = client.fetch_sysmon_network_events(start, end)
    dns = client.fetch_sysmon_dns_events(start, end)
    auth = client.fetch_windows_logon_events(start, end)
    pax = client.fetch_sysmon_process_access_events(start, end)
    reg = client.fetch_sysmon_registry_events(start, end)
    img = client.fetch_sysmon_image_load_events(start, end)
    if proc.empty and net.empty:
        raise SystemExit("no Sysmon events in range")

    proc_history = ProcessHistoryStore()
    features = combined.build(
        proc, net, dns, auth,
        process_access_events=pax, registry_events=reg, image_load_events=img,
        process_history=proc_history,
    )

    features = features.reset_index(drop=True)
    features["score"] = detector.score(features[combined.FEATURE_COLUMNS])
    baseline = BaselineStore()
    features["pct"] = [
        baseline.percentile(row["host"], row["score"])
        for _, row in features.iterrows()
    ]
    for host, grp in features.groupby("host"):
        baseline.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))

    rules = rule_alerts_by_window(client.fetch_rule_alerts(start, end, min_level=1))

    window_delta = timedelta(minutes=settings.window_minutes)
    records: list[dict] = []
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

    return af.fuse_stream(records)
