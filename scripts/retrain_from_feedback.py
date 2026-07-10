"""Retrain the anomaly detector incorporating analyst feedback.

Reads verdicts from the AlertStore feedback table and folds them into training:
  - true_positive alerts → their windows are excluded from training (real attacks)
  - false_positive / benign alerts → already in the training set by default

Combined with simulations/labels.csv attack windows, this produces an increasingly
clean baseline as the feedback table grows. Over weeks of operation the model
adapts: the analyst's verdicts teach it what "normal" really looks like.

Usage:
    python scripts/retrain_from_feedback.py              # full retrain (7-day lookback)
    python scripts/retrain_from_feedback.py --days 14    # longer lookback
    python scripts/retrain_from_feedback.py --dry-run    # show what would change
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.api.store import AlertStore
from aisoc.detection.baseline import BaselineStore
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features import combined
from aisoc.features.process_history import ProcessHistoryStore
from aisoc.features.windows import label_windows
from aisoc.ingestion import IndexerClient

MODEL_PATH = Path("models/process_if.joblib")
LABELS_PATH = Path("simulations/labels.csv")


def _feedback_exclusions(store: AlertStore) -> pd.DataFrame:
    """Build an exclusion DataFrame from TP analyst verdicts.

    Each row mirrors labels.csv: [start_utc, end_utc, host, technique_id, ...].
    Only true_positive verdicts become exclusions — those are real attacks the
    model must not learn.
    """
    feedback = store.all_feedback()
    rows: list[dict] = []
    for alert_id, verdict in feedback.items():
        if verdict != "true_positive":
            continue
        alert = store.get_alert(alert_id)
        if alert is None:
            print(f"  (skipping {alert_id[:8]}... — alert no longer in store)")
            continue
        rows.append(
            {
                "start_utc": alert.window_start.isoformat(),
                "end_utc": alert.window_end.isoformat(),
                "host": alert.host,
                "technique_id": "FEEDBACK",
                "test_number": 0,
                "notes": f"analyst verdict: {verdict} | {alert.detected_behavior[:80]}",
            }
        )
    return pd.DataFrame(rows)


def _print_summary(
    feedback: dict[str, str],
    labels: pd.DataFrame,
    fb_exclusions: pd.DataFrame,
    feature_count: int,
    excluded_labels: int,
    excluded_feedback: int,
    final_count: int,
    dry_run: bool,
) -> None:
    tp = sum(1 for v in feedback.values() if v == "true_positive")
    fp = sum(1 for v in feedback.values() if v == "false_positive")
    bn = sum(1 for v in feedback.values() if v == "benign")

    tag = " [DRY RUN — model NOT saved]" if dry_run else ""
    print(f"\n{'─' * 56}")
    print(f"Adaptive Retrain Report{tag}")
    print(f"{'─' * 56}")
    print(f"  Analyst feedback:    {len(feedback)} verdicts ({tp} TP, {fp} FP, {bn} benign)")
    print(f"  Attack labels:       {len(labels)} windows in labels.csv")
    print(f"  Feedback exclusions: {len(fb_exclusions)} windows from TP verdicts")
    print(f"  Feature windows:     {feature_count} total")
    print(f"  Excluded (labels):   {excluded_labels}")
    print(f"  Excluded (feedback): {excluded_feedback}")
    print(f"  Training set:        {final_count} clean windows")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Retrain the anomaly detector with analyst feedback"
    )
    ap.add_argument("--days", type=float, default=7.0, help="lookback window in days")
    ap.add_argument("--out", type=Path, default=MODEL_PATH)
    ap.add_argument("--dry-run", action="store_true", help="show what would change without retraining")
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)

    # ── 1. Gather feedback ──────────────────────────────────────────────
    alert_store = AlertStore()
    feedback = alert_store.all_feedback()
    if not feedback:
        print("No analyst feedback recorded — falling back to labels-only training.")
        print("Run: python scripts/train_model.py --days {:.0f}".format(args.days))
        return

    fb_exclusions = _feedback_exclusions(alert_store)

    # ── 2. Build combined exclusion table ───────────────────────────────
    # Start with labels.csv; append TP feedback windows.
    exclusions = pd.DataFrame(columns=["start_utc", "end_utc", "host"])
    labels_df = pd.DataFrame()
    if LABELS_PATH.exists():
        labels_df = pd.read_csv(LABELS_PATH)
        if not labels_df.empty:
            if "start_utc" not in labels_df.columns:
                print("  WARNING: labels.csv missing 'start_utc' column — skipping")
            else:
                exclusions = pd.concat([exclusions, labels_df[["start_utc", "end_utc", "host"]]])

    fb_rows = fb_exclusions[["start_utc", "end_utc", "host"]] if not fb_exclusions.empty else pd.DataFrame()
    if not fb_rows.empty:
        exclusions = pd.concat([exclusions, fb_rows], ignore_index=True)

    # ── 3. Pull events and build features ───────────────────────────────
    client = IndexerClient()
    print(f"pulling events since {start.date()} ...")
    proc = client.fetch_sysmon_process_events(start, end)
    net = client.fetch_sysmon_network_events(start, end)
    dns = client.fetch_sysmon_dns_events(start, end)
    auth = client.fetch_windows_logon_events(start, end)
    print(f"  {len(proc)} process, {len(net)} network, {len(dns)} DNS, {len(auth)} auth events")

    if proc.empty and net.empty:
        raise SystemExit("no events — is the agent shipping and archives enabled?")

    proc_history = ProcessHistoryStore()
    proc_history.reset()  # fresh baseline on retrain
    features = combined.build(proc, net, dns, auth, process_history=proc_history)
    feature_count = len(features)

    # ── 4. Exclude attack windows ───────────────────────────────────────
    excluded_labels = 0
    excluded_feedback = 0

    if not exclusions.empty:
        # Mark windows that overlap any exclusion (label or TP feedback)
        is_excluded = label_windows(features, exclusions)
        # Count feedback-only exclusions by comparing with labels-only
        if not labels_df.empty and "start_utc" in labels_df.columns:
            is_label = label_windows(features, labels_df)
            excluded_labels = int(is_label.sum())
            # Feedback-only: windows excluded by combined that aren't excluded by labels alone
            excluded_feedback = int((is_excluded & ~is_label).sum())
        else:
            excluded_feedback = int(is_excluded.sum())

        n = int(is_excluded.sum())
        if n:
            print(f"  excluding {n} attack window(s) from training "
                  f"({excluded_labels} labels, {excluded_feedback} feedback)")
        features = features[~is_excluded]

    # ── 5. Summary ──────────────────────────────────────────────────────
    final_count = len(features)
    _print_summary(feedback, labels_df, fb_exclusions, feature_count,
                   excluded_labels, excluded_feedback, final_count, args.dry_run)

    if final_count < 5:
        print("  WARNING: very few training windows — model will be trivial")

    if args.dry_run:
        print("\nDry run complete. Remove --dry-run to retrain.")
        return

    # ── 6. Train and save ───────────────────────────────────────────────
    detector = AnomalyDetector().fit(features[combined.FEATURE_COLUMNS])
    detector.save(args.out)
    print(f"\nsaved model -> {args.out}")

    # ── 7. Reseed baseline store ────────────────────────────────────────
    baseline = BaselineStore()
    baseline.reset()
    scored = features.copy()
    scored["score"] = detector.score(scored[combined.FEATURE_COLUMNS])
    for host, grp in scored.groupby("host"):
        baseline.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))
    print(f"baseline store reseeded with {len(scored)} window scores")
    print("retrain complete — the model now incorporates analyst feedback.")


if __name__ == "__main__":
    main()
