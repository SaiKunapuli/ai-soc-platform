"""Tests for the adaptive retraining feedback loop."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from scripts.retrain_from_feedback import _feedback_exclusions

# Import is conditional — the script is in scripts/, not the package
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


class TestFeedbackExclusions:
    def test_empty_feedback_returns_empty(self, tmp_path):
        from aisoc.api.store import AlertStore

        store = AlertStore(tmp_path / "alerts.db")
        result = _feedback_exclusions(store)
        assert result.empty

    def test_only_false_positives_returns_empty(self, tmp_path):
        from aisoc.api.store import AlertStore

        store = AlertStore(tmp_path / "alerts.db")
        store.save_feedback("alert-1", "false_positive")
        store.save_feedback("alert-2", "benign")
        result = _feedback_exclusions(store)
        assert result.empty

    def test_true_positive_creates_exclusion(self, tmp_path):
        from aisoc.api.store import AlertStore
        from aisoc.enrichment.schemas import EnrichedAlert

        store = AlertStore(tmp_path / "alerts.db")
        now = datetime.now(timezone.utc)
        ws = now - timedelta(hours=1)
        alert = EnrichedAlert(
            alert_id="alert-tp-1",
            host="desktop-1",
            window_start=ws,
            window_end=ws + timedelta(minutes=10),
            detected_behavior="suspicious PowerShell execution",
            severity="high",
        )
        store.save_alert(alert)
        store.save_feedback("alert-tp-1", "true_positive")

        result = _feedback_exclusions(store)
        assert len(result) == 1
        assert result.iloc[0]["start_utc"] == ws.isoformat()
        assert result.iloc[0]["host"] == "desktop-1"
        assert result.iloc[0]["technique_id"] == "FEEDBACK"

    def test_missing_alert_is_skipped(self, tmp_path):
        from aisoc.api.store import AlertStore

        store = AlertStore(tmp_path / "alerts.db")
        # Feedback for an alert that doesn't exist in the store
        store.save_feedback("nonexistent-alert", "true_positive")
        result = _feedback_exclusions(store)
        assert result.empty

    def test_mixed_verdicts_only_returns_tp(self, tmp_path):
        from aisoc.api.store import AlertStore
        from aisoc.enrichment.schemas import EnrichedAlert

        store = AlertStore(tmp_path / "alerts.db")
        now = datetime.now(timezone.utc)

        for i, (vid, verdict) in enumerate(
            [("tp", "true_positive"), ("fp", "false_positive"), ("tp2", "true_positive")]
        ):
            ws = now - timedelta(hours=i + 1)
            alert = EnrichedAlert(
                alert_id=f"alert-{vid}",
                host="desktop-1",
                window_start=ws,
                window_end=ws + timedelta(minutes=10),
                detected_behavior=f"test alert {vid}",
                severity="medium",
            )
            store.save_alert(alert)
            store.save_feedback(f"alert-{vid}", verdict)

        result = _feedback_exclusions(store)
        assert len(result) == 2  # only the two TPs
        notes = set(result["notes"])
        assert any("tp" in n for n in notes)
        assert not any("fp" in n for n in notes)

    def test_exclusion_columns_match_labels_format(self, tmp_path):
        """Exclusion rows must have the columns label_windows() expects."""
        from aisoc.api.store import AlertStore
        from aisoc.enrichment.schemas import EnrichedAlert

        store = AlertStore(tmp_path / "alerts.db")
        now = datetime.now(timezone.utc)
        ws = now - timedelta(hours=1)
        alert = EnrichedAlert(
            alert_id="alert-1",
            host="desktop-1",
            window_start=ws,
            window_end=ws + timedelta(minutes=10),
            detected_behavior="test",
            severity="high",
        )
        store.save_alert(alert)
        store.save_feedback("alert-1", "true_positive")

        result = _feedback_exclusions(store)
        for col in ["start_utc", "end_utc", "host"]:
            assert col in result.columns
        # Verify overlap detection works: the exclusion window should overlap
        # a feature window that contains ws
        features = pd.DataFrame(
            [{"host": "desktop-1", "window_start": ws}]
        )
        from aisoc.features.windows import label_windows

        overlaps = label_windows(features, result)
        assert bool(overlaps.iloc[0]) is True
