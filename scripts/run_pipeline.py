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

from aisoc.api.store import AlertStore
from aisoc.pipeline import run_detection


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6.0)
    args = ap.parse_args()

    alerts = run_detection(args.hours)
    print(f"{len(alerts)} alert(s) emitted by fusion over the last {args.hours}h")

    store = AlertStore()
    for a in alerts:
        a.alert_id = f"{a.host}:{a.window_start.isoformat()}"
        store.save_alert(a)

    for a in alerts:
        sev = a.severity.value if a.severity else "?"
        print(f"  [{sev:<8}] {a.window_start:%H:%M}  {a.detected_behavior[:60]}")
    if not alerts:
        print("  (no window crossed the alert policy)")


if __name__ == "__main__":
    main()
