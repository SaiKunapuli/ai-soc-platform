"""Tests for auth feature extraction and integration into combined feature vector."""

import pandas as pd
import pytest

from aisoc.features import auth_features as af
from aisoc.features import combined


def make_logon_row(host, user, ip, ws, eid, ts):
    """Minimal synthetic Windows logon event row."""
    return {
        "timestamp": ts,
        "agent.name": host,
        "data.win.eventdata.targetUserName": user,
        "data.win.eventdata.ipAddress": ip,
        "data.win.eventdata.workstationName": ws,
        "data.win.system.eventID": eid,
    }


class TestAuthExtract:
    def test_empty_returns_empty_frame(self):
        result = af.extract(pd.DataFrame())
        assert result.empty
        assert set(af.FEATURE_COLUMNS) <= set(result.columns)

    def test_empty_input_returns_columns(self):
        result = af.extract(None)
        assert result.empty
        assert "host" in result.columns
        assert "user" in result.columns

    def test_extract_per_user_window(self):
        events = pd.DataFrame([
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:00:00Z"),
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:05:00Z"),
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-2", "4625", "2026-07-09T10:07:00Z"),
        ])
        result = af.extract(events)
        assert len(result) == 1  # one (host, user, window)
        row = result.iloc[0]
        assert row["login_count"] == 2
        assert row["failed_count"] == 1
        assert row["failed_ratio"] == pytest.approx(1 / 3)
        assert row["distinct_source_ips"] == 1
        assert row["distinct_hosts"] == 2

    def test_new_source_ip_tracks_first_seen(self):
        events = pd.DataFrame([
            make_logon_row("desktop-1", "bob", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:01:00Z"),
            make_logon_row("desktop-1", "bob", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:02:00Z"),  # same IP
            make_logon_row("desktop-1", "bob", "10.0.0.2", "ws-1", "4624", "2026-07-09T10:03:00Z"),  # new IP
        ])
        result = af.extract(events)
        assert len(result) == 1
        assert result.iloc[0]["new_source_ip"] == 2  # two distinct IPs, both new

    def test_multiple_users_separate_rows(self):
        events = pd.DataFrame([
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:00:00Z"),
            make_logon_row("desktop-1", "bob",   "10.0.0.2", "ws-1", "4625", "2026-07-09T10:01:00Z"),
        ])
        result = af.extract(events)
        assert len(result) == 2


class TestCombinedWithAuth:
    def test_auth_features_appear_in_combined(self):
        proc_events = pd.DataFrame([
            {
                "timestamp": "2026-07-09T10:00:00Z",
                "agent.name": "desktop-1",
                "data.win.eventdata.image": r"C:\Windows\System32\cmd.exe",
                "data.win.eventdata.parentImage": r"C:\Windows\explorer.exe",
                "data.win.eventdata.commandLine": "cmd.exe /c dir",
            }
        ])
        auth_events = pd.DataFrame([
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:05:00Z"),
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-2", "4625", "2026-07-09T10:07:00Z"),
        ])

        result = combined.build(proc_events, auth_events=auth_events)
        assert len(result) == 1
        for col in af.FEATURE_COLUMNS:
            assert col in result.columns
        assert result.iloc[0]["login_count"] == 1
        assert result.iloc[0]["failed_count"] == 1

    def test_no_auth_events_gives_zero_features(self):
        proc_events = pd.DataFrame([
            {
                "timestamp": "2026-07-09T10:00:00Z",
                "agent.name": "desktop-1",
                "data.win.eventdata.image": r"C:\Windows\System32\cmd.exe",
                "data.win.eventdata.parentImage": r"C:\Windows\explorer.exe",
                "data.win.eventdata.commandLine": "cmd.exe /c dir",
            }
        ])
        result = combined.build(proc_events)
        assert len(result) == 1
        for col in af.FEATURE_COLUMNS:
            assert col in result.columns
            assert result.iloc[0][col] == 0.0

    def test_auth_only_windows_merge_correctly(self):
        """Windows with only auth activity (no process/network) still get a row."""
        auth_events = pd.DataFrame([
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:05:00Z"),
        ])
        result = combined.build(pd.DataFrame(), auth_events=auth_events)
        assert len(result) == 1
        assert result.iloc[0]["host"] == "desktop-1"
        assert result.iloc[0]["login_count"] == 1
        assert result.iloc[0]["proc_count"] == 0.0  # no process events

    def test_feature_columns_match_expected_order(self):
        # Just verify auth features are in the combined list
        for col in af.FEATURE_COLUMNS:
            assert col in combined.FEATURE_COLUMNS

    def test_distinct_ips_dedupe_across_users(self):
        """When two users on the same host share an IP, distinct_source_ips
        should count it once at the host level, not twice (sum of per-user nunique)."""
        auth_events = pd.DataFrame([
            make_logon_row("desktop-1", "alice", "10.0.0.1", "ws-1", "4624", "2026-07-09T10:05:00Z"),
            make_logon_row("desktop-1", "bob",   "10.0.0.1", "ws-1", "4624", "2026-07-09T10:06:00Z"),
            make_logon_row("desktop-1", "alice", "10.0.0.2", "ws-1", "4624", "2026-07-09T10:07:00Z"),
        ])
        result = combined.build(pd.DataFrame(), auth_events=auth_events)
        assert len(result) == 1
        # 3 distinct IPs total: 10.0.0.1 (shared), 10.0.0.2 (alice only)
        # Correct: 2. Wrong (old sum-of-nunique): 2(alice) + 1(bob) = 3
        assert result.iloc[0]["distinct_source_ips"] == 2
