"""Trusted effect-grant composition: verify-and-bind only; every send passes the final boundary."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import AttemptStateError, SqliteAttemptStore
from orama.graph.effect_grant_composition import (
    BINDING_MISMATCH,
    PRINCIPAL_MISMATCH,
    EffectGrantRefused,
    FinalBoundaryPorts,
    FinalBoundarySender,
    TrustedEffectGrantComposer,
    VerifiedEffectGrant,
)
from orama.graph.effect_receipts import attempt_ref_for
from orama.graph.final_boundary import FinalBoundaryBinding, FinalBoundaryRefused
from orama.graph.inert_effect_driver import InertEffectDriver
from orama.graph.sealed_inert_driver import INERT_EVIDENCE, SealedInertDriver
from tests.test_dispatch_attempts import (
    ATTEMPT,
    GRANT,
    ISSUER,
    NOW,
    RESERVATION,
    FakeGates,
    FakeRevocations,
    FakeVerifier,
    Harness,
    ready,
    vector_flow,
)
from tests.test_effect_fencing import Operator
from tests.test_effect_seam import LIVE_UNTIL, SCOPE, authorize
from tests.test_final_boundary import Approvals

PRINCIPAL = "principal-1"
WIRE = b"trusted-effect-grant"
INERT = "inert://simulation"
PERMIT = vector_flow().permit


def test_verified_effect_grant_can_create_only_its_bound_attempt(tmp_path):
    """A trusted v2 projection is checked before durable attempt creation."""
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

    # A request-bound fact that differs is now its own internal code (it used to reuse
    # grant.schema_unsupported); it still maps to the public deny.malformed_grant.
    with pytest.raises(EffectGrantRefused, match=BINDING_MISMATCH):
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
    with pytest.raises(EffectGrantRefused, match=PRINCIPAL_MISMATCH):
        composer.create_attempt(
            store, attempt_id="attempt-3", reservation_id="reservation-3",
            wire=b"trusted-effect-grant", principal="principal-2", run_id="run-1",
            operation_id="operation-1", request_digest="a" * 64, effect_class="inert.simulation",
            ledger_store_id="ledger-1", consumer_lease_epoch=3,
        )
    assert store.get_attempt("attempt-3") is None
    store.close()


# ------------------------------------------------------------ canonical send path


class Revoked(Exception):
    """A foreign verifier refusal carrying a closed reason, as Phylax raises it."""

    def __init__(self, reason: str) -> None:
        """Store the closed reason the composer normalizes."""
        super().__init__(reason)
        self.reason = reason


class FixedVerifier:
    """Effect-grant verifier double: returns one projection until told the grant is revoked."""

    def __init__(self, projection: VerifiedEffectGrant) -> None:
        """Hold the projection and start unrevoked."""
        self.projection, self.revoked, self.calls = projection, False, 0

    def verify(self, wire: bytes) -> VerifiedEffectGrant:
        """Count the call; refuse a revoked grant, otherwise return the projection."""
        self.calls += 1
        assert wire == WIRE
        if self.revoked:
            raise Revoked("grant.revoked")
        return self.projection


def projection(principal: str = PRINCIPAL, **changes) -> VerifiedEffectGrant:
    """Return the verified facts that bind the vendored vector permit's attempt."""
    fields = dict(
        grant_id=GRANT, principal=principal, run_id="run-1", operation_id=PERMIT["operation_id"],
        request_digest=PERMIT["request_digest"], effect_class="inert.simulation", use_limit=1,
        ledger_store_id=PERMIT["ledger_store_id"], consumer_lease_epoch=1, second_approval_ref="",
        issued_at=NOW - timedelta(seconds=10), expires_at=NOW + timedelta(hours=1),
        payload_digest=PERMIT["grant_payload_digest"], verifier_id="phylax-verify-1",
    )
    fields.update(changes)
    return VerifiedEffectGrant(**fields)


def final_binding(principal: str = PRINCIPAL) -> FinalBoundaryBinding:
    """Return the final-boundary tuple the bound harness authorizes (epoch 5)."""
    return FinalBoundaryBinding(
        attempt_id=ATTEMPT, principal=principal, operation_digest="sha256:" + SCOPE.operation_digest,
        target=INERT, epoch=5, expires_at=LIVE_UNTIL,
    )


@dataclass
class Bound:
    """A composer-bound, authorized inert attempt plus the composer and its verifier."""

    h: Harness
    composer: TrustedEffectGrantComposer
    verifier: FixedVerifier


def bound_harness(
    tmp_path: Path, *, principal: str = PRINCIPAL, grant: VerifiedEffectGrant | None = None,
    authorize_attempt: bool = True, approve: bool = True,
) -> Bound:
    """Create the attempt through the composer, then reserve, authorize and approve it."""
    path = tmp_path / "bound.sqlite"
    store = SqliteAttemptStore(path, governed=True)
    verifier = FixedVerifier(grant or projection(principal))
    composer = TrustedEffectGrantComposer(verifier, clock=lambda: NOW)
    composer.create_attempt(
        store, attempt_id=ATTEMPT, reservation_id=RESERVATION, wire=WIRE, principal=principal,
        run_id="run-1", operation_id=PERMIT["operation_id"], request_digest=PERMIT["request_digest"],
        effect_class=verifier.projection.effect_class, ledger_store_id=PERMIT["ledger_store_id"],
        consumer_lease_epoch=1,
    )
    scope = replace(SCOPE, principal=principal, destination=INERT)
    store.propose("bound-proposal", scope, NOW)
    store.reserve(RESERVATION, "bound-proposal", scope, LIVE_UNTIL, NOW)
    h = Harness(store, path, FakeVerifier(), FakeGates(), FakeRevocations())
    ready(h, vector_flow())
    if authorize_attempt:
        authorize(h, scope)
        if approve:
            store.grant_effect_approval(final_binding(principal), approver=Operator(), now=NOW)
    return Bound(h, composer, verifier)


class Simulation:
    """Inert simulation double that counts its calls."""

    def __init__(self) -> None:
        """Start with no calls."""
        self.calls = 0

    def __call__(self, envelope) -> str:
        """Count the call and return the inert evidence label."""
        self.calls += 1
        return INERT_EVIDENCE


def sealed(b: Bound, *, effects=lambda: True, approvals=None, sim=None) -> SealedInertDriver:
    """Build the sealed final-boundary driver over the bound store with the given gates."""
    return SealedInertDriver(
        b.h.store, effects_allowed=effects,
        approval_verifier=approvals if approvals is not None else Approvals(),
        revocations=b.h.revocations, issuer_id=ISSUER, simulation=sim or Simulation(),
        clock=lambda: NOW,
    )


def untouched(b: Bound) -> None:
    """Assert nothing was dispatched and the authorized outbox row is pristine."""
    row = b.h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (0, "unknown", None)
    assert b.h.store.receipt(ATTEMPT) is None


@pytest.fixture
def bound(tmp_path: Path) -> Bound:
    """A composer-bound attempt, authorized and approved for the final boundary."""
    b = bound_harness(tmp_path)
    yield b
    b.h.store.close()


def test_the_composed_send_passes_the_final_boundary_and_settles_once(bound: Bound) -> None:
    """The canonical sender asks the final boundary, consumes the approval and writes a receipt."""
    approvals, sim = Approvals(), Simulation()
    sender = FinalBoundarySender(bound.composer, sealed(bound, approvals=approvals, sim=sim))
    receipt = sender(ATTEMPT, PRINCIPAL)
    assert receipt.outcome == "confirmed" and receipt.attempt_ref == attempt_ref_for(ATTEMPT)
    assert approvals.seen == [final_binding()] and sim.calls == 1
    assert bound.h.store.approval_state(ATTEMPT) == "consumed"
    row = bound.h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (1, "confirmed", INERT_EVIDENCE)
    # The signed grant was verified before the boundary and again inside the send transaction.
    assert bound.verifier.calls == 3  # create_attempt, pre-check, in-transaction recheck
    assert sender(ATTEMPT, PRINCIPAL) == receipt and sim.calls == 1  # exact replay, no dispatch


def test_effects_denied_at_the_final_boundary_never_sends(bound: Bound) -> None:
    """Without the effects switch the boundary refuses terminally and nothing is dispatched."""
    sim = Simulation()
    with pytest.raises(FinalBoundaryRefused, match="effects_denied"):
        bound.composer.send(sealed(bound, effects=None, sim=sim), ATTEMPT, authenticated_principal=PRINCIPAL)
    assert sim.calls == 0
    untouched(bound)
    assert bound.h.store.terminal_refusal(ATTEMPT).reason == "effects_denied"


def test_no_human_approval_no_send(tmp_path: Path) -> None:
    """The single-use approval is required by the canonical path too."""
    b = bound_harness(tmp_path, approve=False)
    try:
        sim = Simulation()
        with pytest.raises(FinalBoundaryRefused, match="approval_missing"):
            b.composer.send(sealed(b, sim=sim), ATTEMPT, authenticated_principal=PRINCIPAL)
        assert sim.calls == 0
        untouched(b)
    finally:
        b.h.store.close()


def test_another_caller_is_refused_before_the_boundary(bound: Bound) -> None:
    """The authenticated caller must be the principal bound to the attempt."""
    approvals = Approvals()
    with pytest.raises(EffectGrantRefused, match=PRINCIPAL_MISMATCH):
        bound.composer.send(sealed(bound, approvals=approvals), ATTEMPT, authenticated_principal="mallory")
    assert approvals.seen == []
    untouched(bound)
    assert bound.h.store.terminal_refusal(ATTEMPT) is None


def test_the_plain_inert_driver_is_not_a_send_path(bound: Bound) -> None:
    """Only the sealed final-boundary driver can be handed to the composer or the sender."""
    plain = InertEffectDriver(bound.h.store, clock=lambda: NOW)
    with pytest.raises(TypeError):
        bound.composer.send(plain, ATTEMPT, authenticated_principal=PRINCIPAL)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FinalBoundarySender(bound.composer, plain)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FinalBoundarySender(object(), sealed(bound))  # type: ignore[arg-type]
    untouched(bound)


def test_a_signed_grant_revoked_during_the_boundary_stops_the_send_in_its_transaction(
    bound: Bound,
) -> None:
    """The signed grant is verified again inside the send transaction: a late revocation wins."""

    class RevokingApprovals(Approvals):
        """Approval verifier during which the signed grant is revoked at its issuer."""

        def verify(self, binding):
            """Revoke the signed grant after the composer's pre-check, then approve."""
            bound.verifier.revoked = True
            return super().verify(binding)

    sim = Simulation()
    with pytest.raises(EffectGrantRefused, match="grant.revoked"):
        bound.composer.send(
            sealed(bound, approvals=RevokingApprovals(), sim=sim), ATTEMPT,
            authenticated_principal=PRINCIPAL,
        )
    assert sim.calls == 0
    untouched(bound)
    assert bound.h.store.approval_state(ATTEMPT) == "granted"
    assert bound.h.store._db.execute("SELECT count(*) FROM send_envelopes").fetchone() == (0,)


def test_an_unauthorized_attempt_is_refused_without_recording(tmp_path: Path) -> None:
    """A bound but never-authorized attempt has no final-boundary tuple to send."""
    b = bound_harness(tmp_path, authorize_attempt=False)
    try:
        with pytest.raises(FinalBoundaryRefused, match="attempt_not_authorized"):
            b.composer.send(sealed(b), ATTEMPT, authenticated_principal=PRINCIPAL)
        assert b.h.store.terminal_refusal(ATTEMPT) is None
    finally:
        b.h.store.close()


def test_an_expired_or_non_inert_grant_refuses(tmp_path: Path) -> None:
    """Grant expiry and a non-inert effect class are refused before the boundary."""
    expired = bound_harness(tmp_path / "expired")
    real = bound_harness(tmp_path / "real", grant=projection(effect_class="external.effect"))
    try:
        late = TrustedEffectGrantComposer(expired.verifier, clock=lambda: NOW + timedelta(hours=2))
        with pytest.raises(EffectGrantRefused, match="grant.expired"):
            late.send(sealed(expired), ATTEMPT, authenticated_principal=PRINCIPAL)
        with pytest.raises(EffectGrantRefused, match=BINDING_MISMATCH):
            real.composer.send(sealed(real), ATTEMPT, authenticated_principal=PRINCIPAL)
        untouched(expired)
        untouched(real)
    finally:
        expired.h.store.close()
        real.h.store.close()


def test_a_verified_grant_that_no_longer_matches_the_binding_refuses(bound: Bound) -> None:
    """A different grant identity or principal behind the same wire is a binding mismatch."""
    bound.verifier.projection = projection(grant_id="grant-other")
    with pytest.raises(EffectGrantRefused, match=BINDING_MISMATCH):
        bound.composer.send(sealed(bound), ATTEMPT, authenticated_principal=PRINCIPAL)
    bound.verifier.projection = projection(principal="principal-2")
    with pytest.raises(EffectGrantRefused, match=PRINCIPAL_MISMATCH):
        bound.composer.send(sealed(bound), ATTEMPT, authenticated_principal=PRINCIPAL)
    untouched(bound)


def test_an_attempt_without_a_grant_binding_cannot_be_sent(tmp_path: Path) -> None:
    """Legacy attempts with no verified binding refuse; nothing is invented for them."""
    from tests.test_inert_effect_integration import inert_harness

    h = inert_harness(tmp_path)
    try:
        composer = TrustedEffectGrantComposer(FixedVerifier(projection()), clock=lambda: NOW)
        driver = SealedInertDriver(
            h.store, effects_allowed=lambda: True, approval_verifier=Approvals(),
            revocations=h.revocations, issuer_id=ISSUER, clock=lambda: NOW,
        )
        with pytest.raises(Exception, match="effect_grant_binding_missing"):
            composer.send(driver, ATTEMPT, authenticated_principal=SCOPE.principal)
        assert h.store.outbox_row(ATTEMPT)["send_started"] == 0
    finally:
        h.store.close()


def test_the_composed_attempt_and_its_grant_binding_commit_together(tmp_path: Path) -> None:
    """No committed state ever holds the composed attempt without its effect-grant binding.

    An authorization that ran between two separate commits would find no binding and skip the
    effect-grant cross-check. Every commit of the composer's store is observed from a second
    connection, exactly as that interleaved authorization would see it.
    """
    path = tmp_path / "atomic.sqlite"
    store = SqliteAttemptStore(path, governed=True)
    observer = SqliteAttemptStore(path, governed=True)
    seen: list[tuple[int, int]] = []
    commit = store._immediate

    @contextmanager
    def observed():
        """Run the store's transaction, then record what another connection sees after commit."""
        with commit() as db:
            yield db
        seen.append(observer._db.execute(
            "SELECT (SELECT count(*) FROM dispatch_attempts WHERE attempt_id = ?),"
            " (SELECT count(*) FROM effect_grant_bindings WHERE attempt_id = ?)",
            (ATTEMPT, ATTEMPT),
        ).fetchone())

    store._immediate = observed  # type: ignore[method-assign]
    try:
        composer = TrustedEffectGrantComposer(FixedVerifier(projection()), clock=lambda: NOW)
        composer.create_attempt(
            store, attempt_id=ATTEMPT, reservation_id=RESERVATION, wire=WIRE, principal=PRINCIPAL,
            run_id="run-1", operation_id=PERMIT["operation_id"],
            request_digest=PERMIT["request_digest"], effect_class="inert.simulation",
            ledger_store_id=PERMIT["ledger_store_id"], consumer_lease_epoch=1,
        )
        assert seen and (1, 0) not in seen
        assert seen[-1] == (1, 1)
    finally:
        store.close()
        observer.close()


def test_an_attempt_authorized_without_a_binding_cannot_be_bound_afterwards(tmp_path: Path) -> None:
    """Binding after an unchecked authorization is refused, so it can never launder it."""
    from tests.test_inert_effect_integration import inert_harness

    h = inert_harness(tmp_path)
    try:
        context = {"principal": "mallory", "payload_digest": "f" * 64}
        with pytest.raises(AttemptStateError, match="already authorized"):
            h.store.bind_effect_grant(ATTEMPT, WIRE, context)
        assert h.store._db.execute("SELECT count(*) FROM effect_grant_bindings").fetchone() == (0,)
    finally:
        h.store.close()


def test_final_boundary_ports_must_be_complete() -> None:
    """A composition root cannot wire a partial set of final-boundary ports."""
    FinalBoundaryPorts(Approvals(), FakeRevocations(), ISSUER)
    with pytest.raises(ValueError):
        FinalBoundaryPorts(None, FakeRevocations(), ISSUER)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        FinalBoundaryPorts(Approvals(), None, ISSUER)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        FinalBoundaryPorts(Approvals(), FakeRevocations(), " ")
