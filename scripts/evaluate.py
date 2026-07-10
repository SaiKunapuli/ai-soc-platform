"""Evaluate the trained model against labeled attack windows.

Pulls a time range spanning the labeled attacks (+ surrounding normal activity),
scores every window with the saved model, marks which windows overlap an Atomic
Red Team run, and reports detection metrics.

Usage:
    python scripts/evaluate.py                 # covers all labels + 6h baseline
    python scripts/evaluate.py --pct 90        # looser alert threshold

CAVEAT: for an honest number the model must be trained on baseline data that does
NOT include the attack windows. With the current tiny lab dataset train/test
overlap is likely, so treat these as a methodology demo until the real baseline
(trained attack-free) is in.
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.detection.evaluate import evaluate, format_report
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features import combined
from aisoc.features.windows import label_windows
from aisoc.ingestion import IndexerClient

MODEL_PATH = Path("models/process_if.joblib")
LABELS_PATH = Path("simulations/labels.csv")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pct", type=float, default=95.0, help="alert threshold percentile")
    ap.add_argument("--baseline-hours", type=float, default=6.0,
                    help="hours of normal context to pull before the earliest label")
    args = ap.parse_args()

    if not MODEL_PATH.exists():
        raise SystemExit("no model — run scripts/train_model.py first")
    labels = pd.read_csv(LABELS_PATH)
    if labels.empty:
        raise SystemExit("no labels — run some Atomic Red Team tests first")

    start = pd.to_datetime(labels["start_utc"], utc=True).min() - timedelta(hours=args.baseline_hours)
    end = datetime.now(timezone.utc)

    detector = AnomalyDetector.load(MODEL_PATH)
    client = IndexerClient()
    proc = client.fetch_sysmon_process_events(start.to_pydatetime(), end)
    net = client.fetch_sysmon_network_events(start.to_pydatetime(), end)
    dns = client.fetch_sysmon_dns_events(start.to_pydatetime(), end)
    pax = client.fetch_sysmon_process_access_events(start.to_pydatetime(), end)
    reg = client.fetch_sysmon_registry_events(start.to_pydatetime(), end)
    img = client.fetch_sysmon_image_load_events(start.to_pydatetime(), end)
    if proc.empty and net.empty:
        raise SystemExit("no Sysmon events in range")

    features = combined.build(
        proc, net, dns, process_access_events=pax, registry_events=reg, image_load_events=img
    )
    features["score"] = detector.score(features[combined.FEATURE_COLUMNS])
    is_attack = label_windows(features, labels)

    metrics = evaluate(features["score"], is_attack, threshold_pct=args.pct)
    print(f"\nEvaluation over {start:%Y-%m-%d %H:%M} -> {end:%H:%M} UTC")
    print("-" * 52)
    print(format_report(metrics))
    if metrics.get("attack_windows"):
        print("\nlabeled attack windows and their scores:")
        hit = features[is_attack].sort_values("window_start")
        for _, r in hit.iterrows():
            print(f"  {pd.to_datetime(r['window_start']):%m-%d %H:%M}  score={r['score']:.3f}")


if __name__ == "__main__":
    main()
