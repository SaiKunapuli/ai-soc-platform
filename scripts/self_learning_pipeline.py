"""Self-learning detection pipeline: detect -> auto-classify -> learn.

Runs the full detection chain (imported from run_pipeline), auto-classifies
new alerts using conservative heuristics, injects feedback, and periodically
retrains the model -- all without requiring a human analyst to label every alert.

The learning loop:
  1. Pull recent events -> build features -> score -> fuse -> alerts
  2. For each alert, apply auto-classification rules
  3. Inject auto-feedback for classified alerts
  4. Record behavior patterns for future recognition
  5. If enough new feedback accumulated, retrain the model

Usage:
    python scripts/self_learning_pipeline.py              # last 6 hours
    python scripts/self_learning_pipeline.py --hours 12   # longer window
    python scripts/self_learning_pipeline.py --no-retrain # classify only
    python scripts/self_learning_pipeline.py --dry-run    # show what would happen

Set RETRAIN_THRESHOLD via env AISOC_RETRAIN_THRESHOLD (default 10).
"""

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.api.store import AlertStore
from aisoc.detection.baseline import BaselineStore
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.enrichment.auto_feedback import BehaviorTracker, auto_classify
from aisoc.enrichment.schemas import EnrichedAlert
from aisoc.features import combined
from aisoc.features.process_history import ProcessHistoryStore
from aisoc.features.windows import label_windows
from aisoc.ingestion import IndexerClient
from aisoc.pipeline import run_detection

MODEL_PATH = Path("models/process_if.joblib")
LABELS_PATH = Path("simulations/labels.csv")
RETRAIN_THRESHOLD = int(os.getenv("AISOC_RETRAIN_THRESHOLD", "10"))


# ── Self-learning loop ─────────────────────────────────────────────────


def _retrain_model(days: float = 7.0) -> None:
    """Retrain the model incorporating all auto + human feedback."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    alert_store = AlertStore()
    feedback = alert_store.all_feedback()
    tp_exclusions: list[dict] = []

    if feedback:
        for alert_id, verdict in feedback.items():
            if verdict != "true_positive":
                continue
            alert = alert_store.get_alert(alert_id)
            if alert is None:
                continue
            tp_exclusions.append({
                "start_utc": alert.window_start.isoformat(),
                "end_utc": alert.window_end.isoformat(),
                "host": alert.host,
                "technique_id": "FEEDBACK",
                "test_number": 0,
                "notes": f"analyst verdict: {verdict}",
            })

    client = IndexerClient()
    proc = client.fetch_sysmon_process_events(start, end)
    net = client.fetch_sysmon_network_events(start, end)
    dns = client.fetch_sysmon_dns_events(start, end)
    auth = client.fetch_windows_logon_events(start, end)
    pax = client.fetch_sysmon_process_access_events(start, end)
    reg = client.fetch_sysmon_registry_events(start, end)
    img = client.fetch_sysmon_image_load_events(start, end)

    proc_history = ProcessHistoryStore()
    proc_history.reset()
    features = combined.build(
        proc, net, dns, auth,
        process_access_events=pax, registry_events=reg, image_load_events=img,
        process_history=proc_history,
    )

    exclusions = pd.DataFrame(columns=["start_utc", "end_utc", "host"])
    if LABELS_PATH.exists():
        labels_df = pd.read_csv(LABELS_PATH)
        if not labels_df.empty and "start_utc" in labels_df.columns:
            exclusions = pd.concat([
                exclusions,
                labels_df[["start_utc", "end_utc", "host"]],
            ])
    if tp_exclusions:
        fb_df = pd.DataFrame(tp_exclusions)
        exclusions = pd.concat([exclusions, fb_df[["start_utc", "end_utc", "host"]]])

    if not exclusions.empty:
        is_excluded = label_windows(features, exclusions)
        n = int(is_excluded.sum())
        if n:
            features = features[~is_excluded]

    detector = AnomalyDetector().fit(features[combined.FEATURE_COLUMNS])
    detector.save(MODEL_PATH)

    baseline = BaselineStore()
    baseline.reset()
    scored = features.copy()
    scored["score"] = detector.score(scored[combined.FEATURE_COLUMNS])
    for host, grp in scored.groupby("host"):
        baseline.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))

    tp_count = sum(1 for v in feedback.values() if v == "true_positive")
    benign_count = sum(1 for v in feedback.values() if v in ("benign", "false_positive"))
    print(f"  retrained: {len(features)} windows ({tp_count} TP excl, {benign_count} benign kept)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Self-learning pipeline: detect, auto-classify, and retrain"
    )
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--no-retrain", action="store_true",
                    help="skip retraining even if threshold is met")
    ap.add_argument("--force-retrain", action="store_true",
                    help="retrain regardless of feedback count")
    ap.add_argument("--retrain-days", type=float, default=7.0,
                    help="lookback days for retraining")
    ap.add_argument("--dry-run", action="store_true",
                    help="show auto-classifications without saving")
    args = ap.parse_args()

    # ── 1. Run detection (imported from run_pipeline) ──────────────────
    print(f"running detection over last {args.hours}h ...")
    alerts: list[EnrichedAlert] = run_detection(args.hours)
    print(f"  {len(alerts)} alert(s) emitted by fusion")

    if not alerts:
        print("  (no alerts -- nothing to classify)")
        return

    # ── 2. Auto-classify ───────────────────────────────────────────────
    tracker = BehaviorTracker()
    store = AlertStore()

    # Sync human TP feedback into tracker so we never auto-override a
    # human-confirmed attack
    human_feedback = store.all_feedback()
    for alert_id, verdict in human_feedback.items():
        if verdict == "true_positive":
            human_alert = store.get_alert(alert_id)
            if human_alert:
                tracker.record_human_tp(
                    human_alert.host, human_alert.detected_behavior
                )

    classified = 0
    for alert in alerts:
        # Stable id so re-runs upsert
        alert.alert_id = f"{alert.host}:{alert.window_start.isoformat()}"
        store.save_alert(alert)

        # Record pattern (count increments BEFORE auto_classify checks it)
        tracker.record_alert(alert.host, alert.detected_behavior)

        # Auto-classify: returns (verdict, rule_name) or None
        result = auto_classify(alert, tracker)
        if result is None:
            continue

        verdict, rule_name = result

        if not args.dry_run:
            store.save_feedback(alert.alert_id, verdict)
            tracker.log_auto_feedback(alert.alert_id, verdict, rule_name)

        classified += 1
        ws = alert.window_start.strftime("%H:%M")
        print(
            f"  auto-{verdict:<7} [{ws}] {rule_name:<22}  "
            f"{alert.detected_behavior[:60]}"
        )

    print(f"  auto-classified: {classified}/{len(alerts)} alerts")

    if args.dry_run:
        print("\n[dry run -- no feedback saved, no retrain]")
        return

    # ── 3. Decide whether to retrain ───────────────────────────────────
    new_feedback = tracker.auto_feedback_count()
    should_retrain = (
        not args.no_retrain
        and (args.force_retrain or new_feedback >= RETRAIN_THRESHOLD)
    )

    if should_retrain:
        print(f"\nauto-feedback accumulated: {new_feedback} (threshold: {RETRAIN_THRESHOLD})")
        print("retraining model ...")
        _retrain_model(days=args.retrain_days)
        tracker.reset()
        print("self-learning cycle complete.")
    else:
        remaining = RETRAIN_THRESHOLD - new_feedback
        print(f"\nauto-feedback: {new_feedback}/{RETRAIN_THRESHOLD} "
              f"({remaining} more needed before retrain)")


if __name__ == "__main__":
    main()
