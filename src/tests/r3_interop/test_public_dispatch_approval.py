"""Public-only approval composition preserves the inert, exact-attempt boundary."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

from tests.test_dispatch_attempts import ATTEMPT, GRANT, ISSUER, KEY, NOW, VECTORS
from tests.test_effect_grant_composition import bound_harness, final_binding
from orama.graph.final_boundary import FinalBoundaryRefused
from orama.graph.sealed_inert_driver import SealedInertDriver


def load_adapter() -> ModuleType:
    """Load the optional composition module without making it a core dependency."""
    path = Path(__file__).parents[3] / "scripts/public_dispatch_approval.py"
    spec = importlib.util.spec_from_file_location("public_dispatch_approval", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_retained_chain_verifies_under_only_the_expected_issuer(tmp_path: Path) -> None:
    """Real permit signatures plus the trusted grant port prove only one inert binding."""
    module = load_adapter()
    public = bytes.fromhex(VECTORS["public_key"])
    b = bound_harness(tmp_path)
    try:
        signatures = module.IssuerDispatchVerifier(
            ISSUER, lambda issuer, key: public if (issuer, key) == (ISSUER, KEY) else None,
        )
        verifier = module.RetainedApprovalVerifier(
            b.h.store, signatures=signatures, composer=b.composer,
            revocations=b.h.revocations, clock=lambda: NOW,
        )
        assert verifier.verify(final_binding()) is True
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        b.h.revocations.revoked_grants.add(GRANT)
        assert verifier.verify(final_binding()) is False
    finally:
        b.h.store.close()


@pytest.mark.parametrize("change", [
    {"attempt_id": "other"}, {"principal": "other"},
    {"operation_digest": "sha256:" + "f" * 64}, {"target": "inert://other"},
    {"epoch": 6}, {"expires_at": NOW + timedelta(hours=2)},
])
def test_approval_refuses_any_changed_binding(tmp_path: Path, change: dict[str, object]) -> None:
    """A valid signed chain cannot authenticate a caller-supplied replacement tuple."""
    module = load_adapter()
    b = bound_harness(tmp_path)
    try:
        verifier = module.RetainedApprovalVerifier(
            b.h.store,
            signatures=module.IssuerDispatchVerifier(
                ISSUER, lambda issuer, key: bytes.fromhex(VECTORS["public_key"]),
            ),
            composer=b.composer, revocations=b.h.revocations, clock=lambda: NOW,
        )
        assert verifier.verify(replace(final_binding(), **change)) is False
    finally:
        b.h.store.close()


def test_missing_trust_or_expired_chain_never_verifies(tmp_path: Path) -> None:
    """Unknown issuer keys and expired permit authority do not become approvals."""
    module = load_adapter()
    b = bound_harness(tmp_path)
    try:
        for resolver, clock in (
            (lambda issuer, key: None, lambda: NOW),
            (lambda issuer, key: bytes.fromhex(VECTORS["public_key"]),
             lambda: NOW + timedelta(minutes=2)),
        ):
            verifier = module.RetainedApprovalVerifier(
                b.h.store, signatures=module.IssuerDispatchVerifier(ISSUER, resolver),
                composer=b.composer, revocations=b.h.revocations, clock=clock,
            )
            assert verifier.verify(final_binding()) is False
    finally:
        b.h.store.close()


def test_current_issuer_key_and_grant_trust_are_rechecked(tmp_path: Path) -> None:
    """A previously valid chain cannot survive a removed key or revoked grant port."""
    module = load_adapter()
    b = bound_harness(tmp_path)
    keys = {(ISSUER, KEY): bytes.fromhex(VECTORS["public_key"])}
    try:
        verifier = module.RetainedApprovalVerifier(
            b.h.store,
            signatures=module.IssuerDispatchVerifier(ISSUER, lambda issuer, key: keys.get((issuer, key))),
            composer=b.composer, revocations=b.h.revocations, clock=lambda: NOW,
        )
        assert verifier.verify(final_binding()) is True
        keys.clear()
        assert verifier.verify(final_binding()) is False
        keys[(ISSUER, KEY)] = bytes.fromhex(VECTORS["public_key"])
        b.verifier.revoked = True
        assert verifier.verify(final_binding()) is False
    finally:
        b.h.store.close()


def test_another_issuer_cannot_reuse_a_trusted_key_identifier(tmp_path: Path) -> None:
    """Even a cryptographically valid signature cannot select its own issuer trust domain."""
    module = load_adapter()
    b = bound_harness(tmp_path)
    try:
        verifier = module.RetainedApprovalVerifier(
            b.h.store,
            signatures=module.IssuerDispatchVerifier("other-issuer", lambda issuer, key: bytes.fromhex(VECTORS["public_key"])),
            composer=b.composer, revocations=b.h.revocations, clock=lambda: NOW,
        )
        assert verifier.verify(final_binding()) is False
    finally:
        b.h.store.close()


def test_key_removal_at_send_transaction_does_not_consume_or_send(tmp_path: Path) -> None:
    """Key trust lost after preflight must refuse at the atomic send boundary."""
    module = load_adapter()
    b = bound_harness(tmp_path)
    keys = {(ISSUER, KEY): bytes.fromhex(VECTORS["public_key"])}
    ticks = 0

    def clock() -> datetime:
        """Remove trust exactly when the send transaction checks its fresh time."""
        nonlocal ticks
        ticks += 1
        if ticks == 2:
            keys.clear()
        return NOW

    verifier = module.RetainedApprovalVerifier(
        b.h.store,
        signatures=module.IssuerDispatchVerifier(ISSUER, lambda issuer, key: keys.get((issuer, key))),
        composer=b.composer, revocations=b.h.revocations, clock=lambda: NOW,
    )
    driver = SealedInertDriver(
        b.h.store, effects_allowed=lambda: True, approval_verifier=verifier,
        revocations=b.h.revocations, issuer_id=ISSUER, clock=clock,
    )
    try:
        with pytest.raises(FinalBoundaryRefused) as caught:
            b.composer.send(driver, ATTEMPT, authenticated_principal="principal-1")
        assert caught.value.reason == "approval_not_verified"
        assert b.h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert b.h.store.approval_state(ATTEMPT) == "granted"
    finally:
        b.h.store.close()
