"""E1 C2 issuer-call gate: one place that decides whether to call the issuer at all (pure).

It combines the circuit breaker and the deadline. A refusal here is the consumer-side status
``dispatch.issuer_unavailable``: it is not one of the issuer's closed ``permit.*`` refusals, it is never
reported as valid or as pending-as-success, and it never relaxes a check. Non-effect operations never
consult it. Recovery calls (reconciliation, abort, abandon) are allowed after the deadline under their own
bounded timeouts and are not decided here.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

from orama.graph.circuit_breaker import CircuitBreaker
from orama.graph.finalization_window import Deadline, may_request_finalization

ISSUER_UNAVAILABLE_STATUS: Final = "dispatch.issuer_unavailable"
BACKOFF_BASE_SECONDS: Final = 0.5
BACKOFF_CAP_SECONDS: Final = 4.0


@dataclass(frozen=True)
class CallDecision:
    """Whether an issuer call may proceed; ``status`` and ``reason`` explain a refusal."""

    allowed: bool
    status: str | None = None
    reason: str | None = None


def _refuse(reason: str) -> CallDecision:
    """Build the visible issuer-unavailable refusal for ``reason``."""
    return CallDecision(False, ISSUER_UNAVAILABLE_STATUS, reason)


def decide_issuer_call(
    breaker: CircuitBreaker, deadline: Deadline, *, finalization: bool
) -> CallDecision:
    """Decide an admission or finalization call: deadline first, then the window, then the breaker."""
    if deadline.expired():
        return _refuse("deadline_expired")
    if finalization and not may_request_finalization(deadline):
        return _refuse("finalization_window_too_short")
    if not breaker.allow():
        return _refuse("circuit_open")
    return CallDecision(True)


def next_retry_delay(
    failures: int,
    remaining: float,
    *,
    base: float = BACKOFF_BASE_SECONDS,
    cap: float = BACKOFF_CAP_SECONDS,
) -> float | None:
    """Return the bounded exponential backoff before an identical retry, or None if no time is left.

    Retries are identical requests; the delay never exceeds ``cap`` and never overruns ``remaining``.
    """
    for name, value in (("remaining", remaining), ("base", base), ("cap", cap)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{name} must be finite")
    if isinstance(failures, bool) or not isinstance(failures, int) or failures < 0:
        raise ValueError("failures must be a non-negative integer")
    if base <= 0 or cap <= 0 or remaining < 0:
        raise ValueError("base and cap must be positive and remaining non-negative")
    delay = min(cap, base * (2 ** min(failures, 32)))
    return delay if delay <= remaining else None
