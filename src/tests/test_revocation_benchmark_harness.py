"""Unit regressions for benchmark workload construction, not C6 measurements."""
from pathlib import Path

from benchmark_revocation_availability import Feed
import benchmark_revocation_availability as benchmark
import pytest


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


def test_refresh_thread_timeout_is_not_success() -> None:
    """A still-running refresher cannot be reported as a completed cell."""
    class StuckThread:
        """Represent a refresher that does not stop."""

        def join(self, timeout: float) -> None:
            """Return without stopping."""

        def is_alive(self) -> bool:
            """Report that the refresher remains active."""
            return True

    with pytest.raises(RuntimeError, match="refresher did not stop"):
        benchmark.join_refresher(StuckThread())
