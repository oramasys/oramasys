"""Unit tests for circuit breaker state machine (orama.graph.circuit_breaker).

Contract:
- class CircuitBreaker(clock: Callable[[], float], threshold: int = 5,
                       probe_interval: float = 15.0, alert_after: float = 120.0)
- States: "closed", "open", "half_open" via .state
- allow() -> bool:
    closed -> True
    open -> False until probe_interval seconds passed since opening / last probe;
            then transitions to half_open and returns True for exactly ONE probe;
            further calls while probe is outstanding return False
- record_failure():
    in closed: threshold-th consecutive failure opens breaker
    in half_open: 1 failure reopens it and restarts probe_interval
- record_success(): resets failure count and closes breaker from any state
- record_signed_refusal(): NOT a failure; does not count, does not open, does not reset
- alert_due() -> bool: True when continuously non-closed for >= alert_after seconds
- Constructor argument validation: negative, zero (where applicable), or non-finite (nan, inf) raises ValueError
"""

from __future__ import annotations


import pytest

from orama.graph.circuit_breaker import CircuitBreaker


class FakeClock:
    """Injected fake clock with manually controlled monotonic time."""

    def __init__(self, initial: float = 1000.0) -> None:
        """Start the fake clock at ``initial`` seconds."""
        self.now = initial

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the fake time forward by ``seconds``."""
        self.now += seconds


def test_initial_state_is_closed() -> None:
    """New CircuitBreaker starts closed with allow() True and alert_due() False."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock)
    assert cb.state == "closed"
    assert cb.allow() is True
    assert cb.alert_due() is False


def test_consecutive_failures_trip_at_threshold() -> None:
    """Exactly the threshold-th (5th) consecutive failure trips closed to open."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5)

    for i in range(4):
        cb.record_failure()
        assert cb.state == "closed"
        assert cb.allow() is True

    # 5th failure trips to open
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False


def test_probe_interval_boundary_exact_15s() -> None:
    """Probe boundary: 14.999s stays open/False, 15.0s transitions to half_open and allows 1 probe."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5, probe_interval=15.0)

    # Trip to open at t=1000.0
    for _ in range(5):
        cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False

    # Advance to 14.999s -> still open, disallowed
    clock.advance(14.999)
    assert cb.state == "open"
    assert cb.allow() is False

    # Advance 0.001s to exactly 15.0s -> transitions to half_open, allows ONE probe
    clock.advance(0.001)
    assert cb.allow() is True
    assert cb.state == "half_open"

    # Further allow() calls while probe is outstanding return False
    assert cb.allow() is False
    assert cb.allow() is False


def test_half_open_failure_reopens_and_restarts_interval() -> None:
    """A failure during half_open returns to open and restarts probe_interval."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5, probe_interval=15.0)

    # Trip to open
    for _ in range(5):
        cb.record_failure()

    # Reach half-open and dispatch probe
    clock.advance(15.0)
    assert cb.allow() is True
    assert cb.state == "half_open"


def test_unresolved_half_open_probe_expires_and_allows_one_replacement() -> None:
    """A lost probe is replaced only after its interval, without resetting the open duration."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=1, probe_interval=15.0, alert_after=30.0)
    cb.record_failure()
    clock.advance(15.0)
    assert cb.allow() is True
    assert cb.state == "half_open"
    assert cb.allow() is False

    clock.advance(14.999)
    assert cb.allow() is False
    clock.advance(0.001)
    assert cb.allow() is True
    assert cb.state == "half_open"
    assert cb.allow() is False
    assert cb.alert_due() is True

    # Probe fails -> reopens
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False

    # Interval restarted: 14.999s after reopen is still blocked
    clock.advance(14.999)
    assert cb.state == "open"
    assert cb.allow() is False

    # 15.0s after reopen allows next probe
    clock.advance(0.001)
    assert cb.allow() is True
    assert cb.state == "half_open"


def test_success_resets_and_closes_from_any_state() -> None:
    """record_success resets count and transitions to closed from open or half_open."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5)

    # 1. Reset from half_open
    for _ in range(5):
        cb.record_failure()
    clock.advance(15.0)
    assert cb.allow() is True  # now half_open
    cb.record_success()
    assert cb.state == "closed"
    assert cb.allow() is True

    # 2. Reset from open directly
    for _ in range(5):
        cb.record_failure()
    assert cb.state == "open"
    cb.record_success()
    assert cb.state == "closed"
    assert cb.allow() is True


def test_signed_refusal_is_not_a_failure_and_does_not_reset() -> None:
    """Signed refusal neither counts as failure nor resets accumulated failures."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5)

    # 4 failures accumulated
    for _ in range(4):
        cb.record_failure()
    assert cb.state == "closed"

    # Signed refusal occurs: must NOT reset count to 0 and must NOT trip
    cb.record_signed_refusal()
    assert cb.state == "closed"
    assert cb.allow() is True

    # Next failure is the 5th -> must trip to open
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False


def test_alert_due_boundary_exact_120s() -> None:
    """alert_due is True only after continuously non-closed for >= alert_after (120s)."""
    clock = FakeClock(1000.0)
    cb = CircuitBreaker(clock=clock, threshold=5, alert_after=120.0)

    # In closed state -> alert never due
    clock.advance(200.0)
    assert cb.alert_due() is False

    # Trip to open at t=1200.0
    for _ in range(5):
        cb.record_failure()
    assert cb.state == "open"
    assert cb.alert_due() is False

    # Advance 119.999s -> alert not due yet
    clock.advance(119.999)
    assert cb.alert_due() is False

    # Advance to exactly 120.0s -> alert due
    clock.advance(0.001)
    assert cb.alert_due() is True

    # Continues to be due while non-closed
    clock.advance(30.0)
    assert cb.alert_due() is True

    # Closing resets alert timer
    cb.record_success()
    assert cb.state == "closed"
    assert cb.alert_due() is False


@pytest.mark.parametrize(
    ("threshold", "probe_interval", "alert_after"),
    [
        (0, 15.0, 120.0),  # threshold zero
        (-1, 15.0, 120.0),  # threshold negative
        (5, 0.0, 120.0),  # probe_interval zero
        (5, -1.0, 120.0),  # probe_interval negative
        (5, 15.0, 0.0),  # alert_after zero
        (5, 15.0, -1.0),  # alert_after negative
        (5, float("nan"), 120.0),  # nan
        (5, 15.0, float("nan")),  # nan
        (5, float("inf"), 120.0),  # inf
        (5, 15.0, float("inf")),  # inf
    ],
)
def test_invalid_constructor_parameters_raise_value_error(
    threshold: int, probe_interval: float, alert_after: float
) -> None:
    """Non-positive or non-finite constructor arguments raise ValueError."""
    clock = FakeClock(1000.0)
    with pytest.raises(ValueError):
        CircuitBreaker(
            clock=clock,
            threshold=threshold,
            probe_interval=probe_interval,
            alert_after=alert_after,
        )


def test_circuit_breaker_complete_state_machine_sequence() -> None:
    """Full lifecycle: closed -> open -> half_open -> reopen -> half_open -> closed."""
    clock = FakeClock(0.0)
    cb = CircuitBreaker(clock=clock, threshold=3, probe_interval=10.0, alert_after=50.0)

    # 1. Closed: 2 failures + 1 signed refusal
    cb.record_failure()
    cb.record_signed_refusal()
    cb.record_failure()
    assert cb.state == "closed"

    # 2. 3rd failure trips to open at t=0.0
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow() is False

    # 3. Wait 10s -> half_open
    clock.advance(10.0)
    assert cb.allow() is True
    assert cb.state == "half_open"

    # 4. Probe fails -> back to open at t=10.0
    cb.record_failure()
    assert cb.state == "open"

    # 5. Wait 10s -> half_open again at t=20.0
    clock.advance(10.0)
    assert cb.allow() is True
    assert cb.state == "half_open"

    # 6. Still non-closed at t=50.0 (30s later) -> alert trips (50s non-closed)
    clock.advance(30.0)
    assert cb.alert_due() is True

    # 7. Probe succeeds -> resets to closed, alert cleared
    cb.record_success()
    assert cb.state == "closed"
    assert cb.allow() is True
    assert cb.alert_due() is False
