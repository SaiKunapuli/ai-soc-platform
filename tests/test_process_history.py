"""Tests for ProcessHistoryStore and process feature extraction with persistent history."""

import pandas as pd

from aisoc.features import process_features as pf
from aisoc.features.process_history import ProcessHistoryStore


def _make_events(host: str, images: list[str]) -> pd.DataFrame:
    """Minimal process-creation events with timestamps staggered by 1 minute."""
    rows = []
    for i, img in enumerate(images):
        rows.append(
            {
                "timestamp": f"2026-07-09T10:{i:02d}:00Z",
                pf.COL_HOST: host,
                pf.COL_IMAGE: f"C:\\Windows\\System32\\{img}",
                pf.COL_PARENT: "C:\\Windows\\System32\\svchost.exe",
                pf.COL_CMDLINE: f"{img} --flag",
            }
        )
    return pd.DataFrame(rows)


class TestProcessHistoryStore:
    def test_empty_store_returns_zero_counts(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        assert store.image_count("host1", "cmd.exe") == 0
        assert store.host_max_count("host1") == 0
        assert store.is_new_pair("host1", "svchost.exe", "cmd.exe") is True

    def test_record_batch_persists(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        events = _make_events("desktop-1", ["cmd.exe", "cmd.exe", "powershell.exe"])
        # Add image_name/parent_name columns that record_batch needs
        events["image_name"] = events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        events["parent_name"] = events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]

        store.record_batch(events)
        assert store.image_count("desktop-1", "cmd.exe") == 2
        assert store.image_count("desktop-1", "powershell.exe") == 1
        assert store.image_count("desktop-1", "nonexistent.exe") == 0

    def test_record_batch_accumulates(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        events1 = _make_events("desktop-1", ["cmd.exe"])
        events2 = _make_events("desktop-1", ["cmd.exe", "cmd.exe"])
        for events in [events1, events2]:
            events["image_name"] = events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
            events["parent_name"] = events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]
            store.record_batch(events)
        assert store.image_count("desktop-1", "cmd.exe") == 3

    def test_parent_child_pair_dedup(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        events = _make_events("desktop-1", ["cmd.exe", "powershell.exe"])
        events["image_name"] = events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        events["parent_name"] = events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]

        store.record_batch(events)
        assert store.is_new_pair("desktop-1", "svchost.exe", "cmd.exe") is False
        assert store.is_new_pair("desktop-1", "svchost.exe", "powershell.exe") is False
        assert store.is_new_pair("desktop-1", "explorer.exe", "cmd.exe") is True

    def test_reset_clears_all(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        events = _make_events("desktop-1", ["cmd.exe"])
        events["image_name"] = events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        events["parent_name"] = events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]
        store.record_batch(events)

        store.reset()
        assert store.image_count("desktop-1", "cmd.exe") == 0
        assert store.is_new_pair("desktop-1", "svchost.exe", "cmd.exe") is True

    def test_host_image_counts(self, tmp_path):
        store = ProcessHistoryStore(tmp_path / "history.db")
        events = _make_events("desktop-1", ["cmd.exe", "cmd.exe", "explorer.exe"])
        events["image_name"] = events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        events["parent_name"] = events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]
        store.record_batch(events)

        counts = store.host_image_counts("desktop-1")
        assert counts["cmd.exe"] == 2
        assert counts["explorer.exe"] == 1


class TestExtractWithHistory:
    def test_history_makes_rare_proc_lower_for_common_process(self, tmp_path):
        """A process seen 100 times in history should be less rare than one seen once."""
        store = ProcessHistoryStore(tmp_path / "history.db")
        # Seed history: cmd.exe seen many times, explorer.exe seen once
        hist_events = _make_events("desktop-1", ["cmd.exe"] * 100 + ["explorer.exe"])
        hist_events["image_name"] = hist_events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        hist_events["parent_name"] = hist_events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]
        store.record_batch(hist_events)

        # New batch: 1 cmd.exe (should be common/rare≈0), 1 rareproc.exe (should be rare≈1)
        batch = _make_events("desktop-1", ["cmd.exe", "rareproc.exe"])
        result = pf.extract(batch, history=store)
        assert len(result) == 1
        # With history of 100 cmd.exe, rare_proc_score should be very low
        assert result.iloc[0]["rare_proc_score"] < 0.5

    def test_history_detects_new_parent_child_pairs(self, tmp_path):
        """A pair already in history should not count as new."""
        store = ProcessHistoryStore(tmp_path / "history.db")
        hist_events = _make_events("desktop-1", ["cmd.exe"])
        hist_events["image_name"] = hist_events[pf.COL_IMAGE].str.lower().str.split("\\").str[-1]
        hist_events["parent_name"] = hist_events[pf.COL_PARENT].str.lower().str.split("\\").str[-1]
        store.record_batch(hist_events)

        # New batch: cmd.exe (known pair), powershell.exe (new pair)
        batch = _make_events("desktop-1", ["cmd.exe", "powershell.exe"])
        result = pf.extract(batch, history=store)
        assert len(result) == 1
        # Only powershell.exe should be a new parent-child pair
        assert result.iloc[0]["new_parent_child"] == 1

    def test_without_history_uses_batch_mode(self):
        """Without history, falls back to batch-level computation."""
        events = _make_events("desktop-1", ["cmd.exe", "cmd.exe", "powershell.exe"])
        result = pf.extract(events)  # no history
        assert len(result) == 1
        assert result.iloc[0]["new_parent_child"] > 0
