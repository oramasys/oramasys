"""Unit regressions for benchmark workload construction, not C6 measurements."""
from pathlib import Path

from benchmark_revocation_availability import Feed


def test_refresh_snapshot_stays_within_configured_feed_size(tmp_path: Path) -> None:
    """Refreshing a 2-event cell never grows beyond its declared workload."""
    feed = Feed(tmp_path, 2)
    assert len(feed.snapshot()[1]) == 2
    assert len(feed.snapshot()[1]) == 2
