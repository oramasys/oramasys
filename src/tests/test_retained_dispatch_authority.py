"""Retained signed dispatch authority remains an inert audit prerequisite."""

from __future__ import annotations

from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import AuthorizationRefused, SqliteAttemptStore
from tests.test_dispatch_attempts import (
    ATTEMPT,
    EXPECTED,
    GRANT,
    ISSUER,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    vector_flow,
)


def _authorize(tmp_path: Path) -> tuple[SqliteAttemptStore, FakeVerifier, dict[str, object], dict[str, object]]:
    """Authorize one complete vector flow through the normal dispatch transaction."""
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    verifier = FakeVerifier()
    flow = vector_flow()
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    store.ingest_events(ISSUER, flow.chain[: flow.permit["revocation_version"]], verifier)
    store.authorize_dispatch(
        ATTEMPT,
        flow.permit,
        flow.fin,
        NOW,
        verifier=verifier,
        gates=FakeGates(),
        revocations=FakeRevocations(),
        issuer_id=ISSUER,
        expected=EXPECTED,
    )
    return store, verifier, flow.permit, flow.fin


def test_authorization_atomically_retains_reverifiable_signed_wires(tmp_path: Path) -> None:
    """A committed authorization retains its exact signed permit and finalization wires."""
    store, verifier, permit, fin = _authorize(tmp_path)
    try:
        retained = store.retained_dispatch_authority(ATTEMPT)
        assert retained is not None
        assert retained.issuer_id == ISSUER
        assert retained.grant_id == permit["grant_id"]
        assert retained.permit == permit
        assert retained.finalization == fin
        assert retained.reverify(verifier) is True
    finally:
        store.close()


def test_refused_authorization_retains_no_partial_authority(tmp_path: Path) -> None:
    """A failed authorization cannot leave signed evidence that looks committed."""
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    flow = vector_flow()
    store._create_attempt(ATTEMPT, GRANT, RESERVATION)
    try:
        with pytest.raises(AuthorizationRefused):
            store.authorize_dispatch(
                ATTEMPT,
                flow.permit,
                flow.fin,
                NOW,
                verifier=FakeVerifier(),
                gates=FakeGates(),
                revocations=FakeRevocations(),
                issuer_id=ISSUER,
                expected=EXPECTED,
            )
        assert store.retained_dispatch_authority(ATTEMPT) is None
    finally:
        store.close()


def test_retained_authority_survives_reopen_as_read_only_evidence(tmp_path: Path) -> None:
    """A restart preserves signed evidence without exposing mutable stored mappings."""
    store, verifier, _permit, _fin = _authorize(tmp_path)
    path = tmp_path / "attempts.sqlite"
    store.close()
    reopened = SqliteAttemptStore(path)
    try:
        retained = reopened.retained_dispatch_authority(ATTEMPT)
        assert retained is not None
        assert retained.reverify(verifier) is True
        with pytest.raises(TypeError):
            retained.permit["grant_id"] = "replacement"  # type: ignore[index]
    finally:
        reopened.close()
