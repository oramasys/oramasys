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
    module = importlib.import_module("benchmark_revocation_availability")
    # Unit-level workload tests are not physical runtime qualifications.
    monkeypatch.setattr(module, "require_c6_runtime", lambda: {"sqlite_version": "unit-test-stub"})
    return module


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


def test_schedule_does_not_drift_after_slow_send(benchmark: ModuleType) -> None:
    """Absolute schedules do not add prior service time to the next arrival."""
    assert benchmark.scheduled_at(10.0, 2, 0.2) == 10.4


def test_runtime_refusal_precedes_database_setup(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed real-runtime preflight cannot start workload database construction."""
    def refuse() -> dict[str, object]:
        """Represent an unsupported embedded library, not a slow workload."""
        raise RuntimeError("SQLite runtime refused")

    def unexpected(*args: object, **kwargs: object) -> None:
        """Catch accidental DB setup before the gate."""
        pytest.fail("Feed constructed before runtime gate")

    monkeypatch.setattr(benchmark, "require_c6_runtime", refuse)
    monkeypatch.setattr(benchmark, "Feed", unexpected)
    with pytest.raises(RuntimeError, match="SQLite runtime refused"):
        benchmark.measure(events=0, senders=1, sends=1, send_interval=0,
                          refresh_interval=0, refresher="separate", retries=0)


def test_zero_error_confidence_bound(benchmark: ModuleType) -> None:
    """A 2400-sample success cannot establish a 0.1-percent population bound."""
    assert benchmark.final_error_upper_bound(0, 2400) > 0.001
    assert benchmark.final_error_upper_bound(0, 2400) < 0.0013
    assert benchmark.final_error_upper_bound(10, 10) == 1.0
    assert benchmark.final_error_upper_bound(1, 10) == pytest.approx(0.3941633)


def test_confidence_bound_rejects_invalid_counts(benchmark: ModuleType) -> None:
    """A malformed denominator must not produce a qualification statistic."""
    with pytest.raises(ValueError):
        benchmark.final_error_upper_bound(2, 1)


def test_diagnostics_do_not_include_exception_messages(benchmark: ModuleType) -> None:
    """Synthetic secret text is not included in exception diagnostics."""
    error = OSError("synthetic-private-value")
    assert benchmark.safe_error(error) == {"class": "OSError"}


def test_percentiles_use_nearest_rank(benchmark: ModuleType) -> None:
    """Small samples must use the documented nearest-rank definition."""
    assert benchmark.percentile([1.0, 2.0], 0.5) == 1.0


def test_every_send_is_recorded_without_overwriting_evidence(benchmark: ModuleType, tmp_path: Path) -> None:
    """A tiny real inert cell produces byte-readable, unique per-send records."""
    import json

    path = tmp_path / "samples.jsonl"
    result = benchmark.measure(events=1, senders=1, sends=2, send_interval=0,
                               refresh_interval=0, refresher="separate", retries=2, sample_path=path)
    samples = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(samples) == result["scheduled_sends"] == result["sends"] == 2
    assert {(sample["sender"], sample["sequence"]) for sample in samples} == {(0, 0), (0, 1)}
    assert all(sample["finished_s"] >= sample["started_s"] >= sample["scheduled_s"] for sample in samples)
    assert result["final_error_count"] == 0
    assert result["runtime"]["sqlite_version"]
    assert result["cold_cache_lock_spans"]


def test_terminal_failures_stay_in_measured_population(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Terminal refusals are neither retried nor mislabeled as first-try unavailability."""
    from orama.graph.final_boundary import FinalBoundaryRefused

    calls: list[int] = []

    def refuse(*args: object, **kwargs: object) -> None:
        """Refuse an inert send as a terminal policy decision."""
        calls.append(1)
        raise FinalBoundaryRefused("effects_disabled", terminal=True)

    monkeypatch.setattr(benchmark.SealedInertDriver, "send", refuse)
    result = benchmark.measure(events=0, senders=1, sends=2, send_interval=0,
                               refresh_interval=0, refresher="separate", retries=2)
    assert len(calls) == 2
    assert result["final_error_count"] == 2
    assert result["first_try_unavailable_count"] == 0
    assert result["send_latency"]["p95_ms"] is None
    assert result["scheduled_latency"]["p95_ms"] is not None


def test_failed_refresh_has_schedule_and_failure_evidence(benchmark: ModuleType) -> None:
    """Snapshot failures cannot vanish from the refresh stage population."""
    class BrokenFeed:
        """Refuse snapshot construction before the adapter starts."""

        def snapshot(self) -> object:
            """Inject a synthetic failure without exposing its message."""
            raise OSError("synthetic-private-message")

    stages: list[dict[str, object]] = []
    benchmark.refresh_once(BrokenFeed(), object(), [], {}, stages, scheduled=0.0, sequence=7)
    assert len(stages) == 1
    assert stages[0]["sequence"] == 7
    assert stages[0]["scheduled_monotonic_s"] == 0.0
    assert stages[0]["queue_s"] >= 0
    assert stages[0]["outcome"] == "failed"
    assert "synthetic-private-message" not in str(stages)
