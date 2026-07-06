"""Client for the Wazuh Indexer (OpenSearch fork — NOT Elasticsearch).

Two index patterns matter:
- ``wazuh-alerts-*``   events that matched a Wazuh rule
- ``wazuh-archives-*`` ALL events (requires logall_json; see docker/README.md).
  The ML layer baselines are built from archives, not alerts.
"""

from datetime import datetime
from typing import Any

import pandas as pd
from opensearchpy import OpenSearch

from aisoc.config import settings

ALERTS_INDEX = "wazuh-alerts-*"
ARCHIVES_INDEX = "wazuh-archives-*"


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

    def fetch_events(
        self,
        index: str,
        start: datetime,
        end: datetime,
        query: dict[str, Any] | None = None,
        size: int = 10_000,
    ) -> pd.DataFrame:
        """Fetch events in [start, end) as a flat DataFrame.

        TODO(phase 2): use the scroll/PIT API instead of a single search —
        one busy day of archives exceeds 10k events easily.
        """
        must: list[dict[str, Any]] = [
            {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}}
        ]
        if query:
            must.append(query)
        body = {"query": {"bool": {"must": must}}, "size": size, "sort": [{"timestamp": "asc"}]}
        response = self._client.search(index=index, body=body)
        hits = [hit["_source"] for hit in response["hits"]["hits"]]
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

    def fetch_rule_alerts(self, start: datetime, end: datetime, min_level: int = 5) -> pd.DataFrame:
        """Wazuh rule alerts for the enrichment layer (level >= min_level)."""
        query = {"range": {"rule.level": {"gte": min_level}}}
        return self.fetch_events(ALERTS_INDEX, start, end, query=query)
