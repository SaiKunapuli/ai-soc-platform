"""Tests for the Mordor/OTRF adapter — field mapping, parsing, labels."""

import json
from pathlib import Path

import pandas as pd

from scripts.load_mordor_data import (
    _build_labels,
    _collect_json_files,
    _extract_technique_from_path,
    _load_all_events,
    _load_dns_events,
    _load_network_events,
    _load_process_events,
    _read_json,
    COL_IMAGE,
    COL_PARENT,
    COL_CMDLINE,
    COL_DEST_IP,
    COL_DEST_PORT,
    COL_QUERY,
)


# ── Helpers ─────────────────────────────────────────────────────────────


def _make_mordor_json(tmp_path: Path, name: str, events: list[dict]) -> Path:
    """Write a Mordor-format JSON file to a temp directory."""
    p = tmp_path / name
    p.write_text(json.dumps(events), encoding="utf-8")
    return p


# ── Tests ───────────────────────────────────────────────────────────────


class TestReadJson:
    def test_array_format(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [{"EventID": 1}, {"EventID": 3}])
        result = _read_json(p)
        assert len(result) == 2

    def test_object_wrapped(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", {"events": [{"EventID": 1}]})
        result = _read_json(p)
        assert len(result) == 1

    def test_corrupt_json_returns_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not valid json {{{", encoding="utf-8")
        result = _read_json(p)
        assert result == []

    def test_unknown_shape_returns_empty(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", {"foo": "bar"})
        result = _read_json(p)
        assert result == []


class TestLoadByEid:
    def test_single_pass_splits_by_event_id(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [
            {"EventID": 1, "Image": "cmd.exe", "UtcTime": "2020-01-01T10:00:00Z"},
            {"EventID": 3, "DestinationIp": "10.0.0.1", "UtcTime": "2020-01-01T10:01:00Z"},
            {"EventID": 22, "QueryName": "evil.com", "UtcTime": "2020-01-01T10:02:00Z"},
        ])
        by_eid = _load_all_events([p])
        assert len(by_eid[1]) == 1
        assert len(by_eid[3]) == 1
        assert len(by_eid[22]) == 1

    def test_process_events_have_correct_columns(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [
            {"EventID": 1, "Image": "cmd.exe", "ParentImage": "explorer.exe",
             "CommandLine": "cmd /c dir", "Computer": "DESKTOP-01",
             "UtcTime": "2020-01-01T10:00:00Z"},
        ])
        by_eid = _load_all_events([p])
        df = _load_process_events(by_eid)
        assert len(df) == 1
        assert df[COL_IMAGE].iloc[0] == "cmd.exe"
        assert df[COL_PARENT].iloc[0] == "explorer.exe"
        assert df[COL_CMDLINE].iloc[0] == "cmd /c dir"

    def test_network_events_have_correct_columns(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [
            {"EventID": 3, "DestinationIp": "10.0.0.1", "DestinationPort": 443,
             "UtcTime": "2020-01-01T10:01:00Z"},
        ])
        by_eid = _load_all_events([p])
        df = _load_network_events(by_eid)
        assert len(df) == 1
        assert df[COL_DEST_IP].iloc[0] == "10.0.0.1"
        assert df[COL_DEST_PORT].iloc[0] == "443"

    def test_dns_events_have_correct_columns(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [
            {"EventID": 22, "QueryName": "evil.com",
             "UtcTime": "2020-01-01T10:02:00Z"},
        ])
        by_eid = _load_all_events([p])
        df = _load_dns_events(by_eid)
        assert len(df) == 1
        assert df[COL_QUERY].iloc[0] == "evil.com"

    def test_empty_file_handled(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [])
        by_eid = _load_all_events([p])
        assert by_eid == {}


class TestMitreExtraction:
    def test_extracts_from_path_with_underscore(self, tmp_path):
        p = tmp_path / "T1059_001.json"
        p.write_text("[]")
        result = _extract_technique_from_path(p, tmp_path)
        assert result == "T1059.001"

    def test_extracts_from_path_with_dot(self, tmp_path):
        p = tmp_path / "scenario_T1059.001_events.json"
        p.write_text("[]")
        result = _extract_technique_from_path(p, tmp_path)
        assert result == "T1059.001"

    def test_extracts_from_directory_path(self, tmp_path):
        d = tmp_path / "credential_access" / "host"
        d.mkdir(parents=True)
        p = d / "covenant_t1003_001.json"
        p.write_text("[]")
        result = _extract_technique_from_path(p, tmp_path)
        assert result == "T1003.001"

    def test_no_match_returns_none(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [])
        result = _extract_technique_from_path(p, tmp_path)
        assert result is None


class TestBuildLabels:
    def test_creates_label_from_event_timestamps(self, tmp_path):
        p = _make_mordor_json(tmp_path, "t1059_scenario.json", [
            {"EventID": 1, "UtcTime": "2020-01-01T10:00:00Z", "Image": "cmd.exe"},
            {"EventID": 1, "UtcTime": "2020-01-01T10:02:00Z", "Image": "powershell.exe"},
        ])
        labels = _build_labels([p], tmp_path)
        assert len(labels) == 1
        assert "T1059" in str(labels["technique_id"].iloc[0])
        # Window should start before first event and end after last event
        start = pd.to_datetime(labels["start_utc"].iloc[0])
        end = pd.to_datetime(labels["end_utc"].iloc[0])
        assert start < pd.Timestamp("2020-01-01T10:00:00Z")
        assert end > pd.Timestamp("2020-01-01T10:02:00Z")

    def test_file_without_timestamps_is_skipped(self, tmp_path):
        p = _make_mordor_json(tmp_path, "test.json", [
            {"EventID": 1, "Image": "cmd.exe"},  # no UtcTime
        ])
        labels = _build_labels([p], tmp_path)
        assert labels.empty


class TestCollectFiles:
    def test_finds_json_files_recursively(self, tmp_path):
        d = tmp_path / "sub"
        d.mkdir()
        (tmp_path / "a.json").write_text("[]")
        (d / "b.json").write_text("[]")
        files = _collect_json_files(tmp_path, None)
        assert len(files) == 2

    def test_scenario_filter_works(self, tmp_path):
        (tmp_path / "covenant_wmi.json").write_text("[]")
        (tmp_path / "empire_ps.json").write_text("[]")
        files = _collect_json_files(tmp_path, "wmi*")
        assert len(files) == 1
        assert "wmi" in str(files[0]).lower()
