"""Train the Isolation Forest on baseline process behavior and save it.

Pulls Sysmon process-creation events from the Wazuh archives over a lookback
window, builds per-(host, window) features, fits the detector, and saves it.

Usage:
    python scripts/train_model.py                # default 7-day lookback
    python scripts/train_model.py --days 1       # shorter (early lab)

NOTE: until ~1 week of normal usage has accumulated, the model is only good for
proving the pipeline wiring — not for trustworthy detection. Retrain when the
baseline is ready.
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from aisoc.detection.baseline import BaselineStore
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features import combined
from aisoc.features.process_history import ProcessHistoryStore
from aisoc.features.windows import label_windows
from aisoc.ingestion import IndexerClient

MODEL_PATH = Path("models/process_if.joblib")
LABELS_PATH = Path("simulations/labels.csv")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=float, default=7.0, help="lookback window in days")
    ap.add_argument("--out", type=Path, default=MODEL_PATH)
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)

    client = IndexerClient()
    print(f"pulling Sysmon process + network + DNS + auth events since {start.date()} ...")
    proc = client.fetch_sysmon_process_events(start, end)
    net = client.fetch_sysmon_network_events(start, end)
    dns = client.fetch_sysmon_dns_events(start, end)
    auth = client.fetch_windows_logon_events(start, end)
    pax = client.fetch_sysmon_process_access_events(start, end)
    reg = client.fetch_sysmon_registry_events(start, end)
    img = client.fetch_sysmon_image_load_events(start, end)
    print(f"  {len(proc)} process, {len(net)} network, {len(dns)} DNS, {len(auth)} auth, "
          f"{len(pax)} proc-access, {len(reg)} registry, {len(img)} image-load events")
    if proc.empty and net.empty:
        raise SystemExit("no events — is the agent shipping and archives enabled?")

    proc_history = ProcessHistoryStore()
    proc_history.reset()  # fresh baseline on retrain
    features = combined.build(
        proc, net, dns, auth,
        process_access_events=pax, registry_events=reg, image_load_events=img,
        process_history=proc_history,
    )
    print(f"  {len(features)} (host, window) feature rows x {len(combined.FEATURE_COLUMNS)} features")

    # Exclude labeled attack windows so the baseline is clean by construction —
    # the model must learn "normal", not the attacks we plan to detect.
    if LABELS_PATH.exists():
        labels = pd.read_csv(LABELS_PATH)
        if not labels.empty:
            is_attack = label_windows(features, labels)
            n = int(is_attack.sum())
            if n:
                print(f"  excluding {n} labeled attack window(s) from training")
            features = features[~is_attack]

    if len(features) < 5:
        print("  WARNING: very few windows — model will be trivial (wiring test only)")

    detector = AnomalyDetector().fit(features[combined.FEATURE_COLUMNS])
    detector.save(args.out)
    print(f"saved model -> {args.out}")

    # Bootstrap the per-entity baseline store with this model's scores on the
    # clean baseline windows, so the pipeline has meaningful percentiles from run 1.
    # Reset first: old scores came from the previous model.
    store = BaselineStore()
    store.reset()
    scored = features.copy()
    scored["score"] = detector.score(scored[combined.FEATURE_COLUMNS])
    for host, grp in scored.groupby("host"):
        store.record_many(host, zip(grp["window_start"].astype(str), grp["score"]))
    print(f"baseline store seeded with {len(scored)} window scores")


if __name__ == "__main__":
    main()
