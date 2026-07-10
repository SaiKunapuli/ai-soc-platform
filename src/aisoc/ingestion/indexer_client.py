"""Client for the Wazuh Indexer (OpenSearch fork — NOT Elasticsearch).

Two index patterns matter:
- ``wazuh-alerts-*``   events that matched a Wazuh rule
- ``wazuh-archives-*`` ALL events (requires logall_json; see docker/README.md).
  The ML layer baselines are built from archives, not alerts.

Pagination: uses the OpenSearch scroll API when results exceed the page size.
A busy day of archives easily exceeds the default 10k hits, and the scroll API
retrieves the full result set without the 10k hard cap of a single search.
"""

from datetime import datetime
from typing import Any

import pandas as pd
from opensearchpy import OpenSearch

from aisoc.config import settings

ALERTS_INDEX = "wazuh-alerts-*"
ARCHIVES_INDEX = "wazuh-archives-*"
SCROLL_KEEPALIVE = "2m"
PAGE_SIZE = 5_000


class IndexerClient:
    def __init__(self) -> None:
        self._client = OpenSearch(
            hosts=[settings.indexer_url],
            http_auth=(settings.indexer_user, settings.indexer_password),
            verify_certs=settings.indexer_verify_certs,
            ssl_show_warn=False,
        )

    def ping(self) -> bool:
        return self._client.ping()

    def raw_search(self, index: str, body: dict) -> dict:
        """Run a raw query (e.g. aggregations) and return the full response."""
        return self._client.search(index=index, body=body)

    def cluster_status(self) -> str:
        """green / yellow / red, or 'unknown' if unreachable."""
        try:
            return self._client.cluster.health()["status"]
        except Exception:
            return "unknown"

    def fetch_events(
        self,
        index: str,
        start: datetime,
        end: datetime,
        query: dict[str, Any] | None = None,
        size: int = PAGE_SIZE,
    ) -> pd.DataFrame:
        """Fetch events in [start, end) as a flat DataFrame.

        Uses the OpenSearch scroll API to retrieve beyond the 10k default limit.
        For a week of baseline archive data, a single search with size=10_000 can
        silently truncate results. The scroll API pages through the full result set.
        """
        must: list[dict[str, Any]] = [
            {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}
        ]
        if query:
            must.append(query)
        body = {"query": {"bool": {"must": must}}, "size": size, "sort": [{"timestamp": "asc"}]}

        response = self._client.search(index=index, body=body, scroll=SCROLL_KEEPALIVE)
        scroll_id = response.get("_scroll_id")
        hits = [hit["_source"] for hit in response["hits"]["hits"]]

        pages = 0
        while scroll_id and pages < 200:
            response = self._client.scroll(scroll_id=scroll_id, scroll=SCROLL_KEEPALIVE)
            batch = response["hits"]["hits"]
            if not batch:
                break
            hits.extend(hit["_source"] for hit in batch)
            scroll_id = response.get("_scroll_id")
            pages += 1

        # Release server-side scroll resources
        if scroll_id:
            try:
                self._client.clear_scroll(scroll_id=scroll_id)
            except Exception:
                # Best-effort cleanup; scroll contexts auto-expire anyway
                pass

        return pd.json_normalize(hits)

    def fetch_sysmon_process_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon Event ID 1 (process creation) from the archives — Phase 2's raw material."""
        query = {
            "bool": {
                "must": [
                    {"match": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
                    {"term": {"data.win.system.eventID": "1"}},
                ]
            }
        }
        return self.fetch_events(ARCHIVES_INDEX, start, end, query=query)

    def _fetch_sysmon_eid(self, eid: str, start: datetime, end: datetime) -> pd.DataFrame:
        query = {
            "bool": {
                "must": [
                    {"match": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
                    {"term": {"data.win.system.eventID": eid}},
                ]
            }
        }
        return self.fetch_events(ARCHIVES_INDEX, start, end, query=query)

    def fetch_sysmon_network_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon Event ID 3 (network connection) from the archives."""
        return self._fetch_sysmon_eid("3", start, end)

    def fetch_sysmon_dns_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon Event ID 22 (DNS query) from the archives."""
        return self._fetch_sysmon_eid("22", start, end)

    def fetch_sysmon_process_access_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon Event ID 10 (process access) from the archives.

        The primary signal for credential access (opening lsass.exe memory) and
        process injection. Powers the process_access_features module.
        """
        return self._fetch_sysmon_eid("10", start, end)

    def fetch_sysmon_registry_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon EID 12 (key create/delete) + 13 (value set) — persistence signal."""
        query = {
            "bool": {
                "must": [
                    {"match": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
                    {"terms": {"data.win.system.eventID": ["12", "13"]}},
                ]
            }
        }
        return self.fetch_events(ARCHIVES_INDEX, start, end, query=query)

    def fetch_sysmon_image_load_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Sysmon EID 7 (image/DLL load) — unsigned-module / DLL-hijack signal."""
        return self._fetch_sysmon_eid("7", start, end)

    def fetch_windows_logon_events(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Windows Security logon events (EID 4624 success + 4625 failure) from archives.

        These power the auth_features module (Phase 2.5): login patterns, brute-force
        signals, lateral movement via distinct workstations.

        Graceful: returns an empty DataFrame if Wazuh isn't collecting Windows Security
        logs (the pipeline treats absent auth events as all-zero features).
        """
        query = {
            "bool": {
                "must": [
                    {"match": {"data.win.system.channel": "Security"}},
                    {"terms": {"data.win.system.eventID": ["4624", "4625"]}},
                ]
            }
        }
        return self.fetch_events(ARCHIVES_INDEX, start, end, query=query)

    def fetch_rule_alerts(self, start: datetime, end: datetime, min_level: int = 5) -> pd.DataFrame:
        """Wazuh rule alerts for the enrichment layer (level >= min_level)."""
        query = {"range": {"rule.level": {"gte": min_level}}}
        return self.fetch_events(ALERTS_INDEX, start, end, query=query)
