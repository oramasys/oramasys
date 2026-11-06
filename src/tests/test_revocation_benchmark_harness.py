"""Unit regressions for benchmark workload construction, not C6 measurements."""
from pathlib import Path

from benchmark_revocation_availability import Feed
import benchmark_revocation_availability as benchmark


def test_refresh_snapshot_stays_within_configured_feed_size(tmp_path: Path) -> None:
    """Refreshing a 2-event cell never grows beyond its declared workload."""
    feed = Feed(tmp_path, 2)
    assert len(feed.snapshot()[1]) == 2
    assert len(feed.snapshot()[1]) == 2


def test_snapshot_failure_is_counted() -> None:
    """A snapshot construction failure is reported as a failed refresh."""
    class BrokenFeed:
        """Feed whose snapshot construction fails."""

        def snapshot(self) -> object:
            """Simulate a producer failure."""
            raise OSError("snapshot failed")

    failures: dict[str, int] = {}
    benchmark.refresh_once(BrokenFeed(), object(), [], failures)
    assert failures == {"OSError": 1}
