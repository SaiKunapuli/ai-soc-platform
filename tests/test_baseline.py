"""BaselineStore tests (temp DB, no network)."""

from aisoc.detection.baseline import NEUTRAL_PERCENTILE, BaselineStore


def test_empty_entity_is_neutral(tmp_path) -> None:
    store = BaselineStore(tmp_path / "b.db")
    assert store.percentile("HOST", 0.9) == NEUTRAL_PERCENTILE


def test_percentile_reflects_history(tmp_path) -> None:
    store = BaselineStore(tmp_path / "b.db")
    store.record_many("HOST", [(f"w{i}", i / 100) for i in range(100)])  # 0.00..0.99
    # a score above all history ranks near the top
    assert store.percentile("HOST", 1.0) == 100.0
    # median-ish score ranks near the middle
    assert 45 <= store.percentile("HOST", 0.50) <= 55
    # a score below all history ranks at the bottom
    assert store.percentile("HOST", -1.0) == 0.0


def test_entities_are_isolated(tmp_path) -> None:
    store = BaselineStore(tmp_path / "b.db")
    store.record_many("A", [(f"w{i}", 0.1) for i in range(10)])
    assert store.count("A") == 10
    assert store.count("B") == 0
    assert store.percentile("B", 0.1) == NEUTRAL_PERCENTILE


def test_reset_clears(tmp_path) -> None:
    store = BaselineStore(tmp_path / "b.db")
    store.record_many("A", [(f"w{i}", 0.1) for i in range(5)])
    store.reset()
    assert store.count("A") == 0
