"""Real signed effect authority through issuer admission and consumer dispatch."""
from datetime import UTC, datetime, timedelta
import pytest


def test_phylax_signed_effect_grant_reaches_only_its_bound_attempt(tmp_path):
    """A real v2 signature is verified before Oramasys persists an attempt."""
    from phylax import effect_grant as phylax
    from phylax.adjustment_grant import RotatingIssuerKeyring
    from phylax.grant_store import SqliteGrantAuthorityStore
    from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority
    from orama.graph.dispatch_attempts import SqliteAttemptStore
    from orama.graph.effect_grant_composition import TrustedEffectGrantComposer

    class Seeds:
        """Supply the deterministic test issuer's signing seed."""
        def load_seed(self, seed_ref: str) -> bytes:
            """Resolve only the known fixture seed reference."""
            assert seed_ref == "seed-1"
            return b"e" * 32

    now = datetime.now(UTC)
    authority_store = SqliteGrantAuthorityStore(tmp_path / "phylax.sqlite")
    authority = phylax.EffectGrantAuthority(
        keyring=RotatingIssuerKeyring(
            key_id="issuer-1", seed_ref="seed-1", seed_provider=Seeds(), store=authority_store
        ),
        p5_approval=P5ApprovalAuthority(
            signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=lambda: now
        ),
        clock=lambda: now,
    )
    grant = authority.issue(
        phylax.EffectGrantRequest(
            principal="principal-1", run_id="run-1", operation_id="operation-1",
            request_digest="a" * 64, effect_class="inert.simulation", ledger_store_id="ledger-1",
            consumer_lease_epoch=3, second_approval_ref="", issuer_ref="phylax-1",
            revocation_ref="phylax://revocations/v1",
        ),
        authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1",
    )
    store = SqliteAttemptStore(tmp_path / "attempts.sqlite", governed=True)
    TrustedEffectGrantComposer(authority).create_attempt(
        store, attempt_id="attempt-1", reservation_id="reservation-1", wire=grant.to_wire(),
        principal="principal-1", run_id="run-1", operation_id="operation-1",
        request_digest="a" * 64, effect_class="inert.simulation", ledger_store_id="ledger-1",
        consumer_lease_epoch=3,
    )
    assert store.get_attempt("attempt-1").grant_id == grant.grant_id
    from orama.graph.effect_grant_composition import EffectGrantRefused
    from orama.graph.final_boundary import FinalBoundaryBinding
    from orama.graph.sealed_inert_driver import SealedInertDriver
    from tests.test_dispatch_attempts import FakeGates, FakeRevocations
    from tests.test_effect_fencing import Operator
    from tests.test_final_boundary import Approvals
    composer = TrustedEffectGrantComposer(authority, lease_epoch_of=lambda run_id: 3)
    # The canonical send path: the composer only verifies and binds; the send itself goes through
    # the sealed final boundary (effects switch, revocation view and approval verifier are doubles).
    driver = SealedInertDriver(
        store, effects_allowed=lambda: True, approval_verifier=Approvals(),
        revocations=FakeRevocations(), issuer_id="issuer-1",
    )
    with pytest.raises(EffectGrantRefused):
        composer.send(driver, "attempt-1", authenticated_principal="different-principal")
    import json
    from phylax import dispatch_wire as wire
    from phylax.dispatch_composition import DispatchIssuerSigner
    from phylax.dispatch_permit_store import SqliteDispatchPermitStore
    from phylax.effect_grant import EffectGrantLookup, EffectGrantVerifier
    from orama.graph.dispatch_attempts import ExpectedBinding
    from orama.graph.effect_proposals import EffectScope
    public = authority_store.key("issuer-1").public_key
    class Signatures:
        """Verify actual producer signatures using one trusted public key."""
        def verify_permit(self, key_id, body, signature):
            """Verify the permit domain under the explicitly trusted issuer key."""
            return key_id == "issuer-1" and wire.verify_permit(public, body, signature)
        def verify_finalization(self, key_id, body, signature):
            """Verify the finalization domain under the explicitly trusted issuer key."""
            return key_id == "issuer-1" and wire.verify_finalization(public, body, signature)
        def verify_event(self, key_id, digest, signature):
            """Verify the event domain under the explicitly trusted issuer key."""
            return key_id == "issuer-1" and wire.verify_event(public, digest, signature)
    scope = EffectScope("principal-1", "graph-1", "c" * 64, "a" * 64, "d" * 64, "inert://simulation")
    store.propose("proposal-1", scope, now)
    store.reserve("reservation-1", "proposal-1", scope, now + timedelta(minutes=1), now)
    issuer = SqliteDispatchPermitStore(tmp_path / "permits.sqlite")
    lookup = EffectGrantLookup(authority_store, EffectGrantVerifier(store=authority_store, clock=lambda: now))
    signer = DispatchIssuerSigner(authority._keyring)
    request = dict(grant_id=grant.grant_id, grant_payload_digest=grant.payload_digest, operation_id="operation-1", request_digest="a" * 64, artifact_digest="d" * 64, reservation_id="reservation-1", ledger_store_id="ledger-1", configuration_policy_epoch=1, authority_epoch=1, consumer_acked_through=0, attempt_id="attempt-1", requested_at=wire.timestamp(now))
    permit = json.loads(issuer.admit(request, grants=lookup, signer=signer, now=now))
    fin_request = dict(permit_id=permit["permit_id"], permit_digest=permit["payload_digest"], attempt_id="attempt-1", reservation_id="reservation-1", ledger_store_id="ledger-1", authority_epoch=1, consumer_acked_through=0, requested_at=wire.timestamp(now))
    finalization, envelope = issuer.finalize(fin_request, grants=lookup, signer=signer, now=now)
    signatures = Signatures()
    store.ingest_events("issuer-1", envelope["events"], signatures)
    store.authorize_dispatch("attempt-1", permit, json.loads(finalization), now, verifier=signatures, gates=FakeGates(), revocations=FakeRevocations(), issuer_id="issuer-1", expected=ExpectedBinding("a" * 64, "d" * 64, 1, 1, "ledger-1"), scope=scope)
    stored = store.attempt_binding("attempt-1")
    store.grant_effect_approval(
        FinalBoundaryBinding(
            attempt_id="attempt-1", principal="principal-1",
            operation_digest="sha256:" + stored.operation_digest, target=stored.target,
            epoch=stored.epoch, expires_at=stored.expires_at,
        ),
        approver=Operator(), now=now,
    )
    receipt = composer.send(driver, "attempt-1", authenticated_principal="principal-1")
    assert receipt.outcome == "confirmed"
    assert store.outbox_row("attempt-1")["outcome_evidence"] == "inert-simulation:v1"
    assert store.approval_state("attempt-1") == "consumed"
    before = store.outbox_row("attempt-1")
    authority.revoke(grant.grant_id)
    with pytest.raises(EffectGrantRefused, match="grant.revoked"):
        composer.send(driver, "attempt-1", authenticated_principal="principal-1")
    assert store.outbox_row("attempt-1") == before
    store.close()
