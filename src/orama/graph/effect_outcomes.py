"""E1 effect outcomes: the only three settlement dispositions and the only legal transitions.

A dispatched effect is ``unknown`` the moment it is authorized: local records can show that a
send may have started, never that a provider applied or refused it. ``unknown`` leaves that state
only through an explicit, evidence-backed settlement to ``confirmed`` or ``failed``; both are
terminal. There is no transition back to ``unknown`` and no automatic retry of an ``unknown``
effect. This module is pure: it holds no state and performs no I/O.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Final


class EffectOutcome(StrEnum):
    """The closed set of effect settlement dispositions."""

    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNKNOWN = "unknown"


OUTCOMES: Final[frozenset[str]] = frozenset(item.value for item in EffectOutcome)
_FINAL: Final[frozenset[str]] = frozenset({EffectOutcome.CONFIRMED, EffectOutcome.FAILED})


class OutcomeRefused(Exception):
    """An outcome write or a send was refused; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def check_transition(current: str, new: str, evidence_ref: str | None) -> None:
    """Raise ``OutcomeRefused`` unless ``current`` -> ``new`` is a legal, evidenced settlement."""
    if current not in OUTCOMES or new not in OUTCOMES:
        raise OutcomeRefused("outcome_unknown_value")
    if current in _FINAL:
        raise OutcomeRefused("outcome_terminal")
    if new not in _FINAL:
        raise OutcomeRefused("outcome_not_final")
    if not isinstance(evidence_ref, str) or not evidence_ref.strip():
        raise OutcomeRefused("evidence_required")
