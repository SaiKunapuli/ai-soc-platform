"""Layer 1–2: pull alerts and raw archive events out of the Wazuh Indexer."""

from aisoc.ingestion.indexer_client import IndexerClient

__all__ = ["IndexerClient"]
