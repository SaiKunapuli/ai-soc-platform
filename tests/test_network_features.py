"""Network feature extraction on synthetic Sysmon EID-3 / EID-22 events."""

import pandas as pd

from aisoc.features import network_features as nf


def net_event(ts: str, dip: str, dport: str) -> dict:
    return {"timestamp": ts, nf.COL_HOST: "DESKTOP-01",
            nf.COL_DEST_IP: dip, nf.COL_DEST_PORT: dport}


def dns_event(ts: str, query: str) -> dict:
    return {"timestamp": ts, nf.COL_HOST: "DESKTOP-01", nf.COL_QUERY: query}


def test_is_external_ip() -> None:
    assert nf.is_external_ip("104.18.13.46")
    assert not nf.is_external_ip("10.0.0.75")       # private
    assert not nf.is_external_ip("127.0.0.1")       # loopback
    assert not nf.is_external_ip("192.168.1.1")     # private
    assert nf.is_external_ip("::ffff:34.231.87.187")  # v4-mapped public


def test_dga_domain_scores_higher_than_normal() -> None:
    assert nf.domain_entropy("x7f3k9qz2m4vw8.com") > nf.domain_entropy("google.com")


def test_network_features_per_window() -> None:
    net = pd.DataFrame([
        net_event("2026-07-06T10:01:00Z", "104.18.13.46", "443"),   # external
        net_event("2026-07-06T10:02:00Z", "10.0.0.5", "445"),       # internal
        net_event("2026-07-06T10:03:00Z", "8.8.8.8", "53"),         # external
    ])
    dns = pd.DataFrame([
        dns_event("2026-07-06T10:01:30Z", "google.com"),
        dns_event("2026-07-06T10:02:30Z", "x7f3k9qz2m4vw8plq.net"),  # DGA-like
    ])
    feats = nf.extract(net, dns)
    assert len(feats) == 1
    row = feats.iloc[0]
    assert row["net_conn_count"] == 3
    assert row["distinct_dest_ips"] == 3
    assert row["external_conn_count"] == 2
    assert row["distinct_dest_ports"] == 3
    assert row["dns_query_count"] == 2
    assert row["distinct_domains"] == 2
    assert row["max_dns_entropy"] > 3.0  # the DGA-like domain lifts it


def test_extract_without_dns() -> None:
    net = pd.DataFrame([net_event("2026-07-06T10:01:00Z", "8.8.8.8", "443")])
    feats = nf.extract(net)
    assert set(nf.FEATURE_COLUMNS) <= set(feats.columns)
    assert feats.iloc[0]["dns_query_count"] == 0  # no DNS events -> zero-filled
