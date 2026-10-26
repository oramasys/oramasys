"""Trusted effect-grant composition refuses unverified or misbound authority."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def test_verified_effect_grant_can_create_only_its_bound_attempt(tmp_path):
    """A trusted v2 projection is checked before durable attempt creation."""
    from orama.graph.dispatch_attempts import SqliteAttemptStore
    from orama.graph.effect_grant_composition import (
        EffectGrantRefused,
        TrustedEffectGrantComposer,
        VerifiedEffectGrant,
    )

    now = datetime.now(UTC)
    grant = VerifiedEffectGrant(
        grant_id="effect-grant-1",
        principal="principal-1",
        run_id="run-1",
        operation_id="operation-1",
        request_digest="a" * 64,
        effect_class="inert.simulation",
        use_limit=1,
        ledger_store_id="ledger-1",
        consumer_lease_epoch=3,
        second_approval_ref="approval-1",
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        payload_digest="b" * 64,
        verifier_id="phylax-verify-1",
    )

    class Verifier:
        """Project fixed verified facts for isolated consumer-binding tests."""
        def verify(self, wire: bytes) -> VerifiedEffectGrant:
            """Accept only the fixture wire and return its bound projection."""
            assert wire == b"trusted-effect-grant"
            return grant

    store = SqliteAttemptStore(tmp_path / "attempts.sqlite")
    composer = TrustedEffectGrantComposer(Verifier())
    composer.create_attempt(
        store,
        attempt_id="attempt-1",
        reservation_id="reservation-1",
        wire=b"trusted-effect-grant",
        principal="principal-1",
        run_id="run-1",
        operation_id="operation-1",
        request_digest="a" * 64,
        effect_class="inert.simulation",
        ledger_store_id="ledger-1",
        consumer_lease_epoch=3,
    )
    assert store.get_attempt("attempt-1").grant_id == "effect-grant-1"

    with pytest.raises(EffectGrantRefused, match="grant.schema_unsupported"):
        composer.create_attempt(
            store,
            attempt_id="attempt-2",
            reservation_id="reservation-2",
            wire=b"trusted-effect-grant",
            principal="principal-1",
            run_id="run-1",
            operation_id="operation-1",
            request_digest="c" * 64,
            effect_class="inert.simulation",
            ledger_store_id="ledger-1",
            consumer_lease_epoch=3,
        )
    assert store.get_attempt("attempt-2") is None
