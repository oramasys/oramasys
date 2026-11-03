"""Optional public-trust hooks cannot replace grant authority or silently degrade."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from orama.graph.final_boundary import FinalBoundaryBinding, FinalBoundaryRefused, RevocationUnavailable
from tests.test_dispatch_attempts import ATTEMPT
from tests.test_effect_grant_composition import bound_harness, sealed
from tests.test_final_boundary import Approvals


@pytest.mark.parametrize("result", [False, None, 1, "yes"])
def test_transactional_approval_requires_exact_true(tmp_path: Path, result: Any) -> None:
    """A valid preflight approval cannot make a later non-boolean check authoritative."""
    b = bound_harness(tmp_path)

    class ChangingApproval(Approvals):
        """Pass preflight while returning a scripted transactional answer."""

        def prepare_recheck(self, binding: FinalBoundaryBinding) -> Callable[[], Any]:
            """Snapshot outside the store and return only a local decision."""
            return lambda: result

    try:
        with pytest.raises(FinalBoundaryRefused) as caught:
            b.composer.send(sealed(b, approvals=ChangingApproval()), ATTEMPT,
                            authenticated_principal="principal-1")
        assert caught.value.reason == "approval_not_verified"
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert b.h.store.approval_state(ATTEMPT) == "granted"
    finally:
        b.h.store.close()


@pytest.mark.parametrize("prepare", [None, 1, lambda binding: None])
def test_present_but_broken_transactional_hook_fails_closed(tmp_path: Path, prepare: Any) -> None:
    """Malformed optional hooks do not fall back to a successful legacy preflight."""
    b = bound_harness(tmp_path)
    approval = Approvals()
    setattr(approval, "prepare_recheck", prepare)
    try:
        with pytest.raises(FinalBoundaryRefused) as caught:
            b.composer.send(sealed(b, approvals=approval), ATTEMPT,
                            authenticated_principal="principal-1")
        assert caught.value.reason == "approval_verifier_unavailable"
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert b.h.store.approval_state(ATTEMPT) == "granted"
    finally:
        b.h.store.close()


def test_declared_hook_descriptor_failure_does_not_degrade_to_legacy(tmp_path: Path) -> None:
    """AttributeError inside a declared hook is unavailability, not an absent extension."""
    b = bound_harness(tmp_path)

    class BrokenApproval(Approvals):
        """Pass preflight while failing to resolve its declared transactional extension."""

        @property
        def prepare_recheck(self) -> Any:
            """Model a broken public-trust backend property."""
            raise AttributeError("unavailable hook backend")

    try:
        with pytest.raises(FinalBoundaryRefused) as caught:
            b.composer.send(sealed(b, approvals=BrokenApproval()), ATTEMPT,
                            authenticated_principal="principal-1")
        assert caught.value.reason == "approval_verifier_unavailable"
        assert b.h.store.approval_state(ATTEMPT) == "granted"
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert b.h.store.receipt(ATTEMPT) is None
    finally:
        b.h.store.close()


def test_retryable_transactional_recheck_does_not_burn_the_attempt(tmp_path: Path) -> None:
    """A feed outage leaves the attempt usable once the feed recovers."""
    b = bound_harness(tmp_path)
    unavailable = True

    class FeedRefreshingApproval(Approvals):
        """Pass preflight, then report a retryable feed refresh at the send boundary."""

        def prepare_recheck(self, binding: FinalBoundaryBinding) -> Callable[[], bool]:
            """Return a callback that models a feed becoming temporarily unavailable."""
            def recheck() -> bool:
                """Report a transient outage until the trusted feed recovers."""
                if unavailable:
                    raise RevocationUnavailable("refresh in progress")
                return True

            return recheck

    try:
        driver = sealed(b, approvals=FeedRefreshingApproval())
        with pytest.raises(FinalBoundaryRefused) as caught:
            b.composer.send(driver, ATTEMPT,
                            authenticated_principal="principal-1")
        assert caught.value.reason == "approval_verifier_unavailable" and not caught.value.terminal
        assert b.h.store.terminal_refusal(ATTEMPT) is None
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert b.h.store.approval_state(ATTEMPT) == "granted"
        unavailable = False
        receipt = b.composer.send(driver, ATTEMPT, authenticated_principal="principal-1")
        assert receipt.outcome == "confirmed"
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 1
        assert b.h.store.approval_state(ATTEMPT) == "consumed"
        assert b.composer.send(driver, ATTEMPT, authenticated_principal="principal-1") == receipt
    finally:
        b.h.store.close()
