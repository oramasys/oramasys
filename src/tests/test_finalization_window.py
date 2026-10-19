"""Unit tests for finalization window and deadline accounting (orama.graph.finalization_window).

Contract:
- MIN_FINALIZATION_WINDOW_SECONDS = 15.0
- class Deadline(expires_monotonic: float, clock: Callable[[], float]):
    remaining() -> float (never negative)
    expired() -> bool (true when remaining() == 0)
- may_request_finalization(deadline: Deadline) -> bool (true only when deadline.remaining() >= 15.0)
- deadline_from_permit(now_monotonic: float, issued_remaining_seconds: float, clock) -> Deadline
    expires at now_monotonic + issued_remaining_seconds
    negative or non-finite (nan, inf, -inf) raises ValueError
"""

from __future__ import annotations


import pytest

from orama.graph.finalization_window import (
    MIN_FINALIZATION_WINDOW_SECONDS,
    Deadline,
    deadline_from_permit,
    may_request_finalization,
)


class FakeClock:
    """Injected fake clock with manually controlled monotonic time."""

    def __init__(self, initial: float = 100.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_min_finalization_window_constant() -> None:
    """MIN_FINALIZATION_WINDOW_SECONDS is exactly 15.0 seconds."""
    assert MIN_FINALIZATION_WINDOW_SECONDS == 15.0


def test_deadline_remaining_and_expired() -> None:
    """Deadline calculates remaining time without going negative and flags expired at 0."""
    clock = FakeClock(100.0)
    dl = Deadline(expires_monotonic=120.0, clock=clock)

    assert dl.remaining() == 20.0
    assert not dl.expired()

    clock.advance(15.0)  # now 115.0
    assert dl.remaining() == 5.0
    assert not dl.expired()

    clock.advance(5.0)  # now 120.0 (exact expiry)
    assert dl.remaining() == 0.0
    assert dl.expired()

    clock.advance(10.0)  # now 130.0 (past expiry)
    assert dl.remaining() == 0.0  # never negative
    assert dl.expired()


def test_may_request_finalization_boundary_15s() -> None:
    """Boundary test: exactly 15.0s allows request, 14.999s refuses."""
    clock = FakeClock(100.0)

    # Exactly 15.0 seconds remaining -> allowed
    dl_exact = Deadline(expires_monotonic=115.0, clock=clock)
    assert dl_exact.remaining() == 15.0
    assert may_request_finalization(dl_exact) is True

    # 15.001 seconds remaining -> allowed
    dl_above = Deadline(expires_monotonic=115.001, clock=clock)
    assert may_request_finalization(dl_above) is True

    # 14.999 seconds remaining -> refused
    dl_below = Deadline(expires_monotonic=114.999, clock=clock)
    assert dl_below.remaining() == pytest.approx(14.999)  # float-safe; the decision below is exact
    assert may_request_finalization(dl_below) is False

    # 0.0 seconds remaining -> refused
    dl_zero = Deadline(expires_monotonic=100.0, clock=clock)
    assert may_request_finalization(dl_zero) is False


def test_deadline_from_permit_valid_calculation() -> None:
    """deadline_from_permit sets expires_monotonic to now_monotonic + issued_remaining_seconds."""
    clock = FakeClock(50.0)
    dl = deadline_from_permit(now_monotonic=50.0, issued_remaining_seconds=30.0, clock=clock)

    assert dl.remaining() == 30.0
    assert not dl.expired()
    assert may_request_finalization(dl) is True


@pytest.mark.parametrize(
    "invalid_remaining",
    [
        -0.001,
        -1.0,
        -100.0,
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_deadline_from_permit_invalid_arguments_raise_value_error(
    invalid_remaining: float,
) -> None:
    """Negative or non-finite issued_remaining_seconds raises ValueError."""
    clock = FakeClock(50.0)
    with pytest.raises(ValueError):
        deadline_from_permit(now_monotonic=50.0, issued_remaining_seconds=invalid_remaining, clock=clock)


def test_deadline_lifecycle_sequence() -> None:
    """Sequence test: tracking deadline from creation through window boundary to terminal expiry."""
    clock = FakeClock(0.0)
    dl = deadline_from_permit(now_monotonic=0.0, issued_remaining_seconds=20.0, clock=clock)

    # Initial state: 20s remaining, finalization permitted
    assert dl.remaining() == 20.0
    assert may_request_finalization(dl) is True
    assert not dl.expired()

    # Advance 5.0s -> 15.0s remaining, finalization still permitted at exact boundary
    clock.advance(5.0)
    assert dl.remaining() == 15.0
    assert may_request_finalization(dl) is True
    assert not dl.expired()

    # Advance 0.001s -> 14.999s remaining, finalization now refused
    clock.advance(0.001)
    assert dl.remaining() == pytest.approx(14.999)  # float-safe; the refusal below is the boundary
    assert may_request_finalization(dl) is False
    assert not dl.expired()

    # Advance past expiry -> 0.0 remaining, expired True
    clock.advance(20.0)
    assert dl.remaining() == 0.0
    assert dl.expired()
    assert may_request_finalization(dl) is False
