"""E1 C2 catch-up envelope validation (consumer side, pure).

The issuer's finalization response carries the issuer-signed events above the request's
``consumer_acked_through`` up to the finalization's ``R_f``. The envelope itself is not covered by the
finalization signature, so the consumer checks its shape and contiguity before it ingests a single
event; each event is then verified like any stream event. This module performs no I/O.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

MAX_CATCHUP_EVENTS: Final = 64
_ENVELOPE_KEYS: Final = frozenset({"from_version", "through_version", "events"})


class CatchupRefused(Exception):
    """An envelope was refused; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str) -> None:
        """Record the stable machine-readable refusal reason."""
        super().__init__(reason)
        self.reason = reason


def _is_int(value: object) -> bool:
    """Return True for a real integer; a bool does not count as one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _event_version(event: object) -> int:
    """Return the integer version of one envelope event, or refuse it as malformed."""
    if not isinstance(event, Mapping) or not _is_int(event.get("version")):
        raise CatchupRefused("catchup_malformed")
    return int(event["version"])


def validate_catchup(
    envelope: object,
    *,
    requested_acked_through: int,
    r_f: int,
    max_events: int = MAX_CATCHUP_EVENTS,
) -> list[dict[str, Any]]:
    """Return the envelope's events unchanged, or raise ``CatchupRefused``.

    Order of checks: ``catchup_malformed``, ``catchup_too_large``, ``catchup_range``, ``catchup_gap``.
    An empty envelope is valid only when the consumer is already at ``r_f``.
    """
    if not isinstance(envelope, Mapping) or set(envelope) != _ENVELOPE_KEYS:
        raise CatchupRefused("catchup_malformed")
    from_version, through_version, events = (
        envelope["from_version"], envelope["through_version"], envelope["events"],
    )
    if not _is_int(from_version) or not _is_int(through_version) or not isinstance(events, list):
        raise CatchupRefused("catchup_malformed")
    # Refuse an oversized envelope before inspecting its unbounded contents.
    # Once the bound holds, validating every version shape preserves the documented
    # malformed-before-range precedence without turning validation into a DoS vector.
    if len(events) > max_events:
        raise CatchupRefused("catchup_too_large")
    versions = [_event_version(event) for event in events]
    if events:
        in_range = (
            from_version == requested_acked_through + 1
            and through_version == r_f
            and from_version <= through_version
        )
    else:
        in_range = (
            requested_acked_through == r_f and from_version == r_f + 1 and through_version == r_f
        )
    if not in_range:
        raise CatchupRefused("catchup_range")
    for index, version in enumerate(versions):
        if version != from_version + index:
            raise CatchupRefused("catchup_gap")
    if versions and versions[-1] != through_version:
        raise CatchupRefused("catchup_gap")
    return events
