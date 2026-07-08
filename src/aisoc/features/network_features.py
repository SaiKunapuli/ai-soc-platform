"""Network-behavior features from Sysmon EID 3 (network connection) + EID 22 (DNS query).

Second feature family — complements process behavior with the network dimension
(C2 beacons, data exfil, DGA domains). Sysmon does NOT record byte volumes, so
these are connection- and DNS-shaped, not flow-volume, features. Per (host, window):

- net_conn_count        outbound network connections
- distinct_dest_ips     unique destination IPs (fan-out: scanning / C2 spread)
- external_conn_count   connections to non-private destinations
- distinct_dest_ports   unique destination ports (port sweeping)
- dns_query_count       DNS queries
- distinct_domains      unique domains queried
- max_dns_entropy       highest domain-name entropy (DGA / random C2 domains spike)
"""

import ipaddress

import pandas as pd

from aisoc.features.process_features import command_line_entropy as _entropy
from aisoc.features.windows import assign_windows

COL_HOST = "agent.name"
COL_DEST_IP = "data.win.eventdata.destinationIp"
COL_DEST_PORT = "data.win.eventdata.destinationPort"
COL_QUERY = "data.win.eventdata.queryName"

FEATURE_COLUMNS = [
    "net_conn_count",
    "distinct_dest_ips",
    "external_conn_count",
    "distinct_dest_ports",
    "dns_query_count",
    "distinct_domains",
    "max_dns_entropy",
]


def is_external_ip(ip: str) -> bool:
    """True for a routable public address (not private/loopback/link-local/etc.)."""
    try:
        a = ipaddress.ip_address(str(ip).replace("::ffff:", ""))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def domain_entropy(domain: str) -> float:
    """Shannon entropy of a domain name — DGA/random domains score high."""
    return _entropy(str(domain))


def _network_part(events: pd.DataFrame) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame(columns=["host", "window_start", "net_conn_count",
                                     "distinct_dest_ips", "external_conn_count", "distinct_dest_ports"])
    ev = assign_windows(events)
    for col in (COL_DEST_IP, COL_DEST_PORT):
        if col not in ev:
            ev[col] = ""
        ev[col] = ev[col].fillna("").astype(str)
    ev["is_external"] = ev[COL_DEST_IP].map(is_external_ip)
    g = ev.groupby([COL_HOST, "window_start"])
    out = pd.DataFrame(
        {
            "net_conn_count": g.size(),
            "distinct_dest_ips": g[COL_DEST_IP].nunique(),
            "external_conn_count": g["is_external"].sum(),
            "distinct_dest_ports": g[COL_DEST_PORT].nunique(),
        }
    ).reset_index()
    return out.rename(columns={COL_HOST: "host"})


def _dns_part(events: pd.DataFrame) -> pd.DataFrame:
    if events is None or events.empty:
        return pd.DataFrame(columns=["host", "window_start", "dns_query_count",
                                     "distinct_domains", "max_dns_entropy"])
    ev = assign_windows(events)
    if COL_QUERY not in ev:
        ev[COL_QUERY] = ""
    ev[COL_QUERY] = ev[COL_QUERY].fillna("").astype(str)
    ev["dom_entropy"] = ev[COL_QUERY].map(domain_entropy)
    g = ev.groupby([COL_HOST, "window_start"])
    out = pd.DataFrame(
        {
            "dns_query_count": g.size(),
            "distinct_domains": g[COL_QUERY].nunique(),
            "max_dns_entropy": g["dom_entropy"].max(),
        }
    ).reset_index()
    return out.rename(columns={COL_HOST: "host"})


def extract(network_events: pd.DataFrame, dns_events: pd.DataFrame | None = None) -> pd.DataFrame:
    """EID-3 (+ optional EID-22) events → one feature row per (host, window)."""
    net = _network_part(network_events)
    dns = _dns_part(dns_events)
    merged = net.merge(dns, on=["host", "window_start"], how="outer")
    for col in FEATURE_COLUMNS:
        if col not in merged:
            merged[col] = 0.0
    merged[FEATURE_COLUMNS] = merged[FEATURE_COLUMNS].fillna(0.0)
    return merged[["host", "window_start"] + FEATURE_COLUMNS]
