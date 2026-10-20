"""E1 C2 deadline accounting and the minimum finalization window (consumer side, pure).

Deadlines run on an injected monotonic clock. A finalization is requested only while at least the
minimum window remains, so a slow issuer cannot hand over a finalization that is dead on arrival.
The 15-second value is a starting value, not a safety boundary: any value keeps the behaviour fail
closed. The durable UTC high-water check across restarts lives in the attempt store.
"""
from __future__ import annotations

import math
from collections.abc import Callable
from typing import Final

MIN_FINALIZATION_WINDOW_SECONDS: Final = 15.0


class Deadline:
    """An absolute monotonic deadline read against an injected clock."""

    def __init__(self, expires_monotonic: float, clock: Callable[[], float]) -> None:
        """Store the absolute monotonic expiry and the injected clock."""
        if not isinstance(expires_monotonic, (int, float)) or not math.isfinite(expires_monotonic):
            raise ValueError("expires_monotonic must be finite")
        self._expires = float(expires_monotonic)
        self._clock = clock

    def remaining(self) -> float:
        """Return the seconds left, never negative."""
        return max(0.0, self._expires - self._clock())

    def expired(self) -> bool:
        """Return True once no time remains."""
        return self.remaining() == 0.0


def may_request_finalization(deadline: Deadline) -> bool:
    """Return True only while at least the minimum window remains (exactly 15.0 s allowed)."""
    return deadline.remaining() >= MIN_FINALIZATION_WINDOW_SECONDS


def deadline_from_permit(
    now_monotonic: float, issued_remaining_seconds: float, clock: Callable[[], float]
) -> Deadline:
    """Return the deadline ``issued_remaining_seconds`` after ``now_monotonic``."""
    if (
        not isinstance(issued_remaining_seconds, (int, float))
        or isinstance(issued_remaining_seconds, bool)
        or not math.isfinite(issued_remaining_seconds)
        or issued_remaining_seconds < 0
    ):
        raise ValueError("issued_remaining_seconds must be finite and non-negative")
    return Deadline(now_monotonic + issued_remaining_seconds, clock)
