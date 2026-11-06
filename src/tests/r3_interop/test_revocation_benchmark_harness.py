"""Unit regressions for benchmark workload construction, not C6 measurements."""
from pathlib import Path
import importlib
from types import ModuleType
from types import SimpleNamespace

import pytest


@pytest.fixture
def benchmark(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the standalone script and its sibling adapter without global path changes."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3] / "scripts"))
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


def test_fd_preflight_refuses_before_store_setup(benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """An insufficient soft limit refuses before creating any producer or store."""
    fake = SimpleNamespace(RLIMIT_NOFILE=7, RLIM_INFINITY=-1, getrlimit=lambda _: (1024, 1024))
    monkeypatch.setattr(benchmark, "resource", fake, raising=False)

    def unexpected(*args: object, **kwargs: object) -> None:
        """Fail if setup starts before the capacity check."""
        pytest.fail("setup started before descriptor preflight")

    monkeypatch.setattr(benchmark, "Feed", unexpected)
    with pytest.raises(RuntimeError, match=r"required.*available"):
        benchmark.measure(events=256, senders=8, sends=300, send_interval=0,
                          refresh_interval=15, refresher="separate", retries=0)


@pytest.mark.parametrize("limit", [100000, -1])
def test_fd_preflight_accepts_sufficient_or_infinite_limit(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch, limit: int,
) -> None:
    """A sufficient or unlimited soft limit passes without changing it."""
    fake = SimpleNamespace(RLIMIT_NOFILE=7, RLIM_INFINITY=-1, getrlimit=lambda _: (limit, limit))
    monkeypatch.setattr(benchmark, "resource", fake, raising=False)
    assert benchmark.fd_preflight(8, 300)["status"] == "checked"


def test_fd_preflight_reports_unsupported(benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Platforms without resource explicitly report that capacity was not checked."""
    monkeypatch.setattr(benchmark, "resource", None, raising=False)
    assert benchmark.fd_preflight(8, 300)["status"] == "not_checked"
