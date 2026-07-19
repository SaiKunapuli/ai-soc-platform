"""Honest detection scorecard: recall AND false-positive rate across alert
thresholds, over Mordor attack windows (plus whatever benign windows the captures
contain).

"15/15 techniques detected" is a recall number — it says nothing about how many
benign windows we'd alarm on to get there. This runner reports the full confusion
breakdown, the false-positive rate, and a threshold sweep so the recall/false-alarm
trade-off is explicit, and writes a JSON scorecard so runs can be compared as the
model and features change.

By default the detector is trained on the benign windows only (attack windows
excluded) so attack windows are never in the training set. Pass --model to score
against an already-trained detector instead (e.g. the live-host baseline once it
is solid — the more honest test, since the attacks are then genuinely unseen).

Run as a module so the scripts/ package resolves:
    python -m scripts.scorecard --data-dir ~/mordor_data
    python -m scripts.scorecard --data-dir ~/mordor_data --model models/process_if.joblib
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from aisoc.detection.evaluate import evaluate, format_report, format_sweep, sweep
from aisoc.detection.isolation_forest import AnomalyDetector
from aisoc.features import combined
from aisoc.features.windows import label_windows
from scripts.load_mordor_data import (
    _build_labels,
    _collect_json_files,
    _load_all_events,
    _load_dns_events,
    _load_image_load_events,
    _load_network_events,
    _load_process_access_events,
    _load_process_events,
    _load_registry_events,
)


def build_frames(
    data_dir: Path, scenario_filter: str | None = None
) -> tuple[pd.DataFrame, pd.Series, int]:
    """Load Mordor files -> (feature windows, is_attack mask, scenario count)."""
    json_files = _collect_json_files(data_dir, scenario_filter)
    if not json_files:
        raise SystemExit(f"No Mordor .json files found in {data_dir}")
    by_eid = _load_all_events(json_files)
    features = combined.build(
        _load_process_events(by_eid),
        _load_network_events(by_eid),
        _load_dns_events(by_eid),
        process_access_events=_load_process_access_events(by_eid),
        registry_events=_load_registry_events(by_eid),
        image_load_events=_load_image_load_events(by_eid),
    )
    labels = _build_labels(json_files, data_dir)
    if labels.empty:
        is_attack = pd.Series(False, index=features.index)
    else:
        is_attack = label_windows(features, labels)
    return features, is_attack, len(json_files)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, required=True,
                    help="directory of extracted Mordor JSON files")
    ap.add_argument("--scenario", default=None, help="filter scenarios (glob)")
    ap.add_argument("--model", type=Path, default=None,
                    help="score against this saved model instead of training on benign")
    ap.add_argument("--out", type=Path, default=Path("reports"),
                    help="directory to write the JSON scorecard into")
    args = ap.parse_args()

    if not args.data_dir.is_dir():
        raise SystemExit(f"Not a directory: {args.data_dir}")

    features, is_attack, n_scen = build_frames(args.data_dir, args.scenario)
    n_attack = int(is_attack.sum())
    n_benign = int((~is_attack).sum())
    print(f"{len(features)} windows from {n_scen} scenarios: "
          f"{n_attack} attack, {n_benign} benign")

    # -- Fit or load the detector -----------------------------------------
    if args.model:
        if not args.model.exists():
            raise SystemExit(f"No model at {args.model}")
        detector = AnomalyDetector.load(args.model)
        trained_on = f"loaded {args.model.name}"
    else:
        benign = features[~is_attack]
        train_df = benign if len(benign) >= 5 else features
        if len(benign) < 5:
            print("WARNING: <5 benign windows — training on all windows and FPR is "
                  "not meaningful here. Mordor is attack-heavy; use --model with a "
                  "real live-host baseline for a trustworthy false-positive number.")
        detector = AnomalyDetector().fit(train_df[combined.FEATURE_COLUMNS])
        trained_on = f"benign-only ({len(train_df)} windows)"

    features = features.copy()
    features["score"] = detector.score(features[combined.FEATURE_COLUMNS])

    # -- Report -----------------------------------------------------------
    headline = evaluate(features["score"], is_attack, threshold_pct=95)
    rows = sweep(features["score"], is_attack)

    print(f"\n{'=' * 56}")
    print(f"DETECTION SCORECARD  (detector: {trained_on})")
    print(f"{'=' * 56}")
    print(format_report(headline))
    print(f"\nthreshold sweep (recall vs false-positive trade-off):")
    print(format_sweep(rows))

    # -- Persist for trend tracking ---------------------------------------
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "generated_utc": stamp,
        "data_dir": str(args.data_dir),
        "scenarios": n_scen,
        "windows": len(features),
        "attack_windows": n_attack,
        "benign_windows": n_benign,
        "detector": trained_on,
        "headline_95pct": headline,
        "sweep": rows,
    }
    out_path = args.out / f"scorecard_{stamp}.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nsaved scorecard -> {out_path}")


if __name__ == "__main__":
    main()
