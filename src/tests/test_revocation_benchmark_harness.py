"""Unit regressions for benchmark workload construction, not C6 measurements."""
from pathlib import Path
import importlib
from types import ModuleType

import pytest


@pytest.fixture
def benchmark(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the standalone script and its sibling adapter without global path changes."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts"))
    return importlib.import_module("benchmark_revocation_availability")


def test_refresh_snapshot_stays_within_configured_feed_size(tmp_path: Path, benchmark: ModuleType) -> None:
    """Refreshing a 2-event cell never grows beyond its declared workload."""
    feed = benchmark.Feed(tmp_path, 2)
    assert len(feed.snapshot()[1]) == 2
    assert len(feed.snapshot()[1]) == 2


def test_snapshot_failure_is_counted(benchmark: ModuleType) -> None:
    """A snapshot construction failure is reported as a failed refresh."""
    class BrokenFeed:
        """Feed whose snapshot construction fails."""

        def snapshot(self) -> object:
            """Simulate a producer failure."""
            raise OSError("snapshot failed")

    failures: dict[str, int] = {}
    benchmark.refresh_once(BrokenFeed(), object(), [], failures)
    assert failures == {"OSError": 1}


def test_refresh_thread_timeout_is_not_success(benchmark: ModuleType) -> None:
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
