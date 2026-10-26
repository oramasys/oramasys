"""Final-boundary re-verification: bound to the full tuple, refused before dispatch (DRAFT)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.final_boundary import (
    TERMINAL_REASONS,
    FinalBoundaryBinding,
    FinalBoundaryRefused,
    authorize_final_boundary,
)
from orama.graph.inert_effect_driver import InertEffectDriver
from tests.test_dispatch_attempts import ATTEMPT, GRANT, ISSUER, NOW, Harness
from tests.test_effect_fencing import Operator
from tests.test_effect_seam import LIVE_UNTIL, SCOPE
from tests.test_inert_effect_integration import inert_harness

TARGET = "inert://simulation"


class Approvals:
    """Approval-verifier double recording every binding it is asked about."""

    def __init__(self, answer=True) -> None:
        """Script the answer: a bool, a non-bool, or an exception instance to raise."""
        self.answer, self.seen = answer, []

    def verify(self, binding: FinalBoundaryBinding):
        """Record the binding and answer as scripted."""
        self.seen.append(binding)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def binding(**changes) -> FinalBoundaryBinding:
    """Return the exact tuple the inert harness authorized."""
    fields = dict(
        attempt_id=ATTEMPT, principal=SCOPE.principal, operation_digest="sha256:" + SCOPE.operation_digest,
        target=TARGET, epoch=5, expires_at=LIVE_UNTIL,
    )
    fields.update(changes)
    return FinalBoundaryBinding(**fields)


def run(h: Harness, *, effects=lambda: True, approvals=None, revocations="default", b=None, now=NOW):
    """Run the final boundary against the harness store."""
    return authorize_final_boundary(
        h.store, b or binding(), effects_allowed=effects,
        approval_verifier=approvals if approvals is not None else Approvals(),
        revocations=h.revocations if revocations == "default" else revocations,
        issuer_id=ISSUER, now=now,
    )


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    """An authorized inert attempt (epoch 5, expiry one hour after NOW)."""
    harness = inert_harness(tmp_path)
    yield harness
    harness.store.close()


def untouched(h: Harness) -> None:
    """Assert that nothing was dispatched and the outbox is still the pristine authorized row."""
    row = h.store.outbox_row(ATTEMPT)
    assert row["send_started"] == 0 and row["outcome"] == "unknown" and row["outcome_evidence"] is None


# ------------------------------------------------------------------- happy path


def test_exact_tuple_with_every_gate_open_passes_once_and_does_not_dispatch(h: Harness) -> None:
    """The verifier is asked about the exact binding; passing does not itself send anything."""
    approvals = Approvals()
    run(h, approvals=approvals)
    assert approvals.seen == [binding()]
    assert h.store.terminal_refusal(ATTEMPT) is None
    untouched(h)


def test_binding_is_validated_at_construction() -> None:
    """Blank, naive or mistyped binding fields cannot be built."""
    with pytest.raises(ValueError):
        binding(principal=" ")
    with pytest.raises(ValueError):
        binding(epoch=True)
    with pytest.raises(ValueError):
        binding(epoch=0)
    with pytest.raises(ValueError):
        binding(expires_at=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        binding(target="")


def test_an_equivalent_instant_in_another_timezone_still_matches(h: Harness) -> None:
    """Expiry is compared as an instant, not as text."""
    plus8 = timezone(timedelta(hours=8))
    run(h, b=binding(expires_at=LIVE_UNTIL.astimezone(plus8)))


# ----------------------------------------------- any changed field refuses, unrecorded


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"principal": "someone-else"}, "principal_mismatch"),
        ({"operation_digest": "sha256:" + "f" * 64}, "operation_digest_mismatch"),
        ({"target": "inert://other"}, "target_mismatch"),
        ({"epoch": 6}, "epoch_mismatch"),
        ({"epoch": 4}, "epoch_mismatch"),
        ({"expires_at": LIVE_UNTIL + timedelta(seconds=1)}, "expiry_mismatch"),
        ({"expires_at": LIVE_UNTIL - timedelta(seconds=1)}, "expiry_mismatch"),
    ],
    ids=["principal", "digest", "target", "epoch-up", "epoch-down", "expiry-later", "expiry-earlier"],
)
def test_a_changed_field_is_a_different_attempt_and_refuses_without_burning_the_original(
    h: Harness, changes: dict, reason: str
) -> None:
    """Post-approval substitution refuses; the verifier is never asked; the real attempt survives."""
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, approvals=approvals, b=binding(**changes))
    assert excinfo.value.reason == reason and not excinfo.value.terminal
    assert approvals.seen == []
    assert h.store.terminal_refusal(ATTEMPT) is None
    untouched(h)
    run(h)  # the genuine tuple still passes: a tampered request cannot burn it


def test_a_different_attempt_id_is_not_authorized(h: Harness) -> None:
    """An unknown attempt identity is refused and nothing is recorded."""
    with pytest.raises(FinalBoundaryRefused, match="attempt_not_authorized"):
        run(h, b=binding(attempt_id="attempt-other"))


def test_an_attempt_that_never_authorized_cannot_pass(tmp_path: Path) -> None:
    """A prepared-but-unauthorized attempt has no durable authorization to re-verify."""
    h = inert_harness(tmp_path, authorize_attempt=False)
    try:
        with pytest.raises(FinalBoundaryRefused, match="attempt_not_authorized"):
            run(h)
    finally:
        h.store.close()


# ------------------------------------------------------- refusal before dispatch


@pytest.mark.parametrize(
    "effects",
    [None, lambda: False, lambda: None, lambda: 1, lambda: "yes", lambda: (_ for _ in ()).throw(RuntimeError())],
    ids=["absent", "false", "none", "int", "text", "raises"],
)
def test_effects_deny_refuses_before_dispatch_and_is_terminal(h: Harness, effects) -> None:
    """The effects bit is deny unless exactly True; the verifier is not even consulted."""
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, effects=effects, approvals=approvals)
    assert excinfo.value.reason == "effects_denied" and excinfo.value.terminal
    assert approvals.seen == []
    assert h.store.terminal_refusal(ATTEMPT).reason == "effects_denied"
    untouched(h)


def test_effects_deny_stays_terminal_even_after_effects_are_later_allowed(h: Harness) -> None:
    """Replay returns the same refusal; the attempt cannot be revived, and the old driver agrees."""
    with pytest.raises(FinalBoundaryRefused):
        run(h, effects=lambda: False)
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as again:
        run(h, effects=lambda: True, approvals=approvals)
    assert again.value.reason == "effects_denied" and again.value.terminal
    assert approvals.seen == []
    with pytest.raises(OutcomeRefused, match="attempt_refused"):
        InertEffectDriver(h.store).send(ATTEMPT)
    untouched(h)


@pytest.mark.parametrize(
    ("approvals", "reason"),
    [
        (None, "approval_verifier_missing"),
        (Approvals(False), "approval_not_verified"),
        (Approvals(None), "approval_not_verified"),
        (Approvals(1), "approval_not_verified"),
        (Approvals(RuntimeError("phylax down")), "approval_verifier_unavailable"),
    ],
    ids=["missing", "false", "none", "int", "unavailable"],
)
def test_missing_unconvinced_or_unavailable_verifier_refuses_before_dispatch(
    h: Harness, approvals, reason: str
) -> None:
    """No permit verifier, a negative answer or an outage never degrades to verify-later."""
    if approvals is None:
        with pytest.raises(FinalBoundaryRefused) as excinfo:
            authorize_final_boundary(
                h.store, binding(), effects_allowed=lambda: True, approval_verifier=None,
                revocations=h.revocations, issuer_id=ISSUER, now=NOW,
            )
    else:
        with pytest.raises(FinalBoundaryRefused) as excinfo:
            run(h, approvals=approvals)
    assert excinfo.value.reason == reason and excinfo.value.terminal
    assert h.store.terminal_refusal(ATTEMPT).reason == reason
    untouched(h)


class Down:
    """Revocation view that is unavailable."""

    def revoked(self, *, grant_id: str, issuer_id: str):
        """Raise as an outage would."""
        raise RuntimeError("down")


@pytest.mark.parametrize("view", [None, Down()], ids=["absent", "raises"])
def test_an_unavailable_revocation_view_refuses(h: Harness, view) -> None:
    """Without a working revocation view the boundary cannot prove non-revocation, so it refuses."""
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, revocations=view, approvals=approvals)
    assert excinfo.value.reason == "approval_verifier_unavailable" and excinfo.value.terminal
    assert approvals.seen == []
    assert h.store.terminal_refusal(ATTEMPT).reason == "approval_verifier_unavailable"


def test_a_revoked_grant_refuses_future_dispatch(h: Harness) -> None:
    """A revocation seen by the injected port refuses before the approval verifier is asked."""
    h.revocations.revoked_grants.add(GRANT)
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, approvals=approvals)
    assert excinfo.value.reason == "grant_revoked" and excinfo.value.terminal
    assert approvals.seen == []
    untouched(h)


def test_a_non_boolean_revocation_answer_is_not_a_pass(h: Harness) -> None:
    """Only exactly False means not revoked."""
    class Odd:
        """Revocation view that answers None."""

        def revoked(self, *, grant_id: str, issuer_id: str):
            """Answer something that is not a bool."""
            return None

    with pytest.raises(FinalBoundaryRefused, match="grant_revoked"):
        run(h, revocations=Odd())


def test_locally_recorded_revocation_facts_refuse(h: Harness, monkeypatch) -> None:
    """A durable revocation fact recorded from acknowledged events refuses as well."""
    monkeypatch.setattr(h.store, "revocation_refusal", lambda attempt_id, issuer_id: "cascade_listed")
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h)
    assert excinfo.value.reason == "cascade_listed" and excinfo.value.terminal
    assert "cascade_listed" in TERMINAL_REASONS


def test_a_stale_fencing_epoch_refuses_at_the_boundary(h: Harness) -> None:
    """The epoch moved after authorization, so the stamped attempt is stale and terminal."""
    h.store.advance_fencing_epoch(6, operator=Operator(), now=NOW)
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, approvals=approvals)
    assert excinfo.value.reason == "epoch_stale" and excinfo.value.terminal
    assert approvals.seen == []
    assert h.store.terminal_refusal(ATTEMPT).reason == "epoch_stale"
    untouched(h)


@pytest.mark.parametrize("delta", [0, 1, 3600])
def test_an_expired_binding_refuses_at_and_after_the_expiry_instant(h: Harness, delta: int) -> None:
    """Expiry is strict: at the expiry instant the approval is already dead."""
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h, now=LIVE_UNTIL + timedelta(seconds=delta))
    assert excinfo.value.reason == "expired" and excinfo.value.terminal


def test_just_before_expiry_still_passes(h: Harness) -> None:
    """One microsecond before the expiry the boundary still holds."""
    run(h, now=LIVE_UNTIL - timedelta(microseconds=1))


# ----------------------------------------- unknown is preserved, never rolled back


def test_revocation_after_dispatch_never_rewrites_an_unknown_outcome(h: Harness) -> None:
    """Work already in doubt stays unknown; revocation refuses future dispatch only."""
    h.store.begin_send(ATTEMPT, inert_only=True, now=NOW)
    h.revocations.revoked_grants.add(GRANT)
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        run(h)
    assert excinfo.value.reason == "send_already_started" and not excinfo.value.terminal
    row = h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (1, "unknown", None)
    assert h.store.terminal_refusal(ATTEMPT) is None
    with pytest.raises(OutcomeRefused):
        h.store.record_outcome(ATTEMPT, "unknown", None)


def test_a_terminal_refusal_cannot_be_recorded_over_by_a_different_reason(h: Harness) -> None:
    """The first terminal refusal wins; a later boundary reports it, not a new reason."""
    with pytest.raises(FinalBoundaryRefused):
        run(h, effects=lambda: False)
    with pytest.raises(FinalBoundaryRefused) as second:
        run(h, approvals=Approvals(False))
    assert second.value.reason == "effects_denied"


def test_no_approval_check_precedes_the_durable_facts(h: Harness) -> None:
    """A binding for a sent attempt never reaches the verifier."""
    h.store.begin_send(ATTEMPT, inert_only=True, now=NOW)
    approvals = Approvals()
    with pytest.raises(FinalBoundaryRefused):
        run(h, approvals=approvals)
    assert approvals.seen == []
