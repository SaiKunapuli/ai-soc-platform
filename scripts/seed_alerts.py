"""Seed the alert store with sample alerts so the API/dashboard have content
before the ML pipeline produces real ones. Idempotent (INSERT OR REPLACE).

Usage: python scripts/seed_alerts.py
"""

from aisoc.api.store import AlertStore
from aisoc.copilot.sample_alert import all_samples


def main() -> None:
    store = AlertStore()
    for i, alert in enumerate(all_samples()):
        alert.alert_id = f"seed-{i}"  # stable id so re-seeding replaces, not duplicates
        store.save_alert(alert)
    alerts = store.list_alerts()
    print(f"seeded {len(alerts)} alerts:")
    for a in alerts:
        sev = a.severity.value if a.severity else "?"
        print(f"  [{sev:<8}] {a.host}  {a.detected_behavior}")


if __name__ == "__main__":
    main()
