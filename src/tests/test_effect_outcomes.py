"""Unit tests for outcome transition state machine (orama.graph.effect_outcomes).

Contract:
- EffectOutcome: StrEnum with CONFIRMED='confirmed', FAILED='failed', UNKNOWN='unknown'.
- OUTCOMES: frozenset of {'confirmed', 'failed', 'unknown'}.
- OutcomeRefused: Exception with attribute .reason (str) set from the first constructor arg.
- check_transition(current: str, new: str, evidence_ref: str | None) -> None
  Raises OutcomeRefused with reasons in strict precedence:
    1. 'outcome_unknown_value' if current or new not in OUTCOMES
    2. 'outcome_terminal' if current in ('confirmed', 'failed')
    3. 'outcome_not_final' if new == 'unknown'
    4. 'evidence_required' if evidence_ref is None, not a str, or empty/whitespace
  Otherwise returns None (valid transitions: unknown -> confirmed, unknown -> failed).
"""

from __future__ import annotations

import pytest

from orama.graph.effect_outcomes import (
    OUTCOMES,
    EffectOutcome,
    OutcomeRefused,
    check_transition,
)


def test_effect_outcome_enum_values() -> None:
    """EffectOutcome enum defines exactly CONFIRMED, FAILED, and UNKNOWN values."""
    assert EffectOutcome.CONFIRMED.value == "confirmed"
    assert EffectOutcome.FAILED.value == "failed"
    assert EffectOutcome.UNKNOWN.value == "unknown"
    assert len(EffectOutcome) == 3


def test_outcomes_frozenset_definition() -> None:
    """OUTCOMES is a frozenset containing exactly the three outcome string values."""
    assert OUTCOMES == frozenset({"confirmed", "failed", "unknown"})


def test_outcome_refused_exception_reason_attribute() -> None:
    """OutcomeRefused exposes the reason string passed at instantiation."""
    err = OutcomeRefused("evidence_required")
    assert err.reason == "evidence_required"
    assert str(err) == "evidence_required"


@pytest.mark.parametrize("target_outcome", ["confirmed", "failed"])
def test_valid_transitions_from_unknown(target_outcome: str) -> None:
    """Valid transitions from unknown to confirmed or failed with non-blank evidence return None."""
    result = check_transition("unknown", target_outcome, evidence_ref="ev-doc-7788")
    assert result is None


@pytest.mark.parametrize("target_outcome", [EffectOutcome.CONFIRMED, EffectOutcome.FAILED])
def test_valid_transitions_using_enum_members(target_outcome: EffectOutcome) -> None:
    """Valid transitions accept StrEnum instances directly and return None."""
    result = check_transition(EffectOutcome.UNKNOWN, target_outcome, evidence_ref="ev-receipt-9900")
    assert result is None


@pytest.mark.parametrize(
    ("current", "new"),
    [
        ("pending", "confirmed"),
        ("unknown", "in_progress"),
        ("invalid", "invalid"),
        ("", "confirmed"),
        ("unknown", ""),
        ("CONFIRMED", "failed"),
    ],
)
def test_refuse_unknown_outcome_value(current: str, new: str) -> None:
    """Refuse transitions where either current or new outcome is not a recognized member of OUTCOMES."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition(current, new, evidence_ref="ev-123")
    assert exc_info.value.reason == "outcome_unknown_value"


@pytest.mark.parametrize("terminal_state", ["confirmed", "failed"])
@pytest.mark.parametrize("destination_state", ["confirmed", "failed", "unknown"])
def test_refuse_transition_from_terminal_outcome(
    terminal_state: str, destination_state: str
) -> None:
    """Refuse any transition attempt out of confirmed or failed terminal state."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition(terminal_state, destination_state, evidence_ref="ev-123")
    assert exc_info.value.reason == "outcome_terminal"


def test_refuse_transition_to_unknown_as_not_final() -> None:
    """Refuse transitions where destination is unknown (not final)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("unknown", "unknown", evidence_ref="ev-123")
    assert exc_info.value.reason == "outcome_not_final"


@pytest.mark.parametrize(
    "invalid_evidence",
    [
        None,
        "",
        "   ",
        "\t\n",
        7,
        12.34,
        b"raw_bytes",
        ["item"],
        {"doc": "ref"},
    ],
)
@pytest.mark.parametrize("new_state", ["confirmed", "failed"])
def test_refuse_missing_or_invalid_evidence(
    invalid_evidence: object, new_state: str
) -> None:
    """Refuse transitions to confirmed/failed when evidence_ref is None, non-string, or whitespace."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("unknown", new_state, evidence_ref=invalid_evidence)  # type: ignore[arg-type]
    assert exc_info.value.reason == "evidence_required"


def test_precedence_unknown_value_beats_terminal() -> None:
    """Precedence 1 (unknown_value) takes priority over Precedence 2 (terminal)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("confirmed", "unrecognized_state", evidence_ref=None)
    assert exc_info.value.reason == "outcome_unknown_value"


def test_precedence_unknown_value_beats_not_final() -> None:
    """Precedence 1 (unknown_value) takes priority over Precedence 3 (not_final)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("unrecognized_state", "unknown", evidence_ref="ev-123")
    assert exc_info.value.reason == "outcome_unknown_value"


def test_precedence_unknown_value_beats_evidence_required() -> None:
    """Precedence 1 (unknown_value) takes priority over Precedence 4 (evidence_required)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("bogus", "confirmed", evidence_ref=None)
    assert exc_info.value.reason == "outcome_unknown_value"


def test_precedence_terminal_beats_not_final() -> None:
    """Precedence 2 (terminal) takes priority over Precedence 3 (not_final)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("confirmed", "unknown", evidence_ref="ev-123")
    assert exc_info.value.reason == "outcome_terminal"


def test_precedence_terminal_beats_evidence_required() -> None:
    """Precedence 2 (terminal) takes priority over Precedence 4 (evidence_required)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("failed", "failed", evidence_ref=None)
    assert exc_info.value.reason == "outcome_terminal"


def test_precedence_not_final_beats_evidence_required() -> None:
    """Precedence 3 (not_final) takes priority over Precedence 4 (evidence_required)."""
    with pytest.raises(OutcomeRefused) as exc_info:
        check_transition("unknown", "unknown", evidence_ref=None)
    assert exc_info.value.reason == "outcome_not_final"


def test_check_transition_is_pure_and_returns_none_on_success() -> None:
    """A valid check returns None and a refused check leaves the inputs unchanged."""
    evidence = "ev-pure-1"
    assert check_transition("unknown", "confirmed", evidence) is None
    assert evidence == "ev-pure-1"
    with pytest.raises(OutcomeRefused):
        check_transition("confirmed", "failed", evidence)
    assert check_transition("unknown", "failed", evidence) is None
