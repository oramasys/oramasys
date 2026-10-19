"""E1 C2 consumer-local circuit breaker per issuer and consumer scope (pure, operational).

It only shortens a refusal: it never relaxes a check and carries no safety guarantee. It opens after
a run of consecutive authenticated transport-or-verification failures, admits one half-open probe per
interval, and closes only on an authenticated, usable response. A signed issuer refusal is not a
failure. The numbers are starting values, not safety boundaries.
"""
from __future__ import annotations

import math
from collections.abc import Callable
from typing import Final, Literal

State = Literal["closed", "open", "half_open"]
DEFAULT_THRESHOLD: Final = 5
DEFAULT_PROBE_INTERVAL_SECONDS: Final = 15.0
DEFAULT_ALERT_AFTER_SECONDS: Final = 120.0


def _positive_finite(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)


class CircuitBreaker:
    """Closed, open and half-open states over an injected monotonic clock."""

    def __init__(
        self,
        clock: Callable[[], float],
        threshold: int = DEFAULT_THRESHOLD,
        probe_interval: float = DEFAULT_PROBE_INTERVAL_SECONDS,
        alert_after: float = DEFAULT_ALERT_AFTER_SECONDS,
    ) -> None:
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise ValueError("threshold must be a positive integer")
        self._clock = clock
        self._threshold = threshold
        self._probe_interval = _positive_finite("probe_interval", probe_interval)
        self._alert_after = _positive_finite("alert_after", alert_after)
        self.state: State = "closed"
        self._failures = 0
        self._opened_at = 0.0
        self._non_closed_since: float | None = None

    def allow(self) -> bool:
        """Return whether a call may proceed; admit exactly one probe per elapsed interval."""
        if self.state == "closed":
            return True
        if self.state == "open" and self._clock() - self._opened_at >= self._probe_interval:
            self.state = "half_open"
            return True
        return False

    def record_failure(self) -> None:
        """Count an authenticated transport-or-verification failure."""
        if self.state == "half_open":
            self._open()
            return
        if self.state == "open":
            return
        self._failures += 1
        if self._failures >= self._threshold:
            self._open()

    def record_success(self) -> None:
        """An authenticated, usable response resets the count and closes the breaker."""
        self.state = "closed"
        self._failures = 0
        self._non_closed_since = None

    def record_signed_refusal(self) -> None:
        """A signed issuer refusal is not a failure: nothing is counted, opened or reset."""

    def alert_due(self) -> bool:
        """Return True once the breaker has been continuously non-closed for the alert interval."""
        if self._non_closed_since is None:
            return False
        return self._clock() - self._non_closed_since >= self._alert_after

    def _open(self) -> None:
        now = self._clock()
        self.state = "open"
        self._opened_at = now
        if self._non_closed_since is None:
            self._non_closed_since = now
