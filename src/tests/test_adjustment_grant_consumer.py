"""Task 6 consumer: spending Phylax adjustment grants through the injected port.

Covers design sections 7 and 13.7. Oramasys never verifies a signature; it
receives facts from an injected verifier and spends them atomically against an
UNKNOWN hold. Cross-repo end-to-end behaviour is exercised by
``scripts/verify_grant_interop.py``, which needs Phylax and therefore cannot be
a unit test here.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from orama.graph.accounting_types import ChargeUnits
from orama.graph.execution_guard import AttemptHold, StepLedger, UnknownDisposition
from orama.graph.grant_verifier import (
    CLOSED_REFUSAL_CODES,
    CONSUMPTION_REFUSAL_CODES,
    VERIFICATION_REFUSAL_CODES,
    AdjustmentGrantConsumer,
    AdjustmentGrantRefused,
    AdjustmentReceipt,
    DenyAllGrantVerifier,
    RevocationObservation,
    VerifiedGrant,
)
from orama.graph.run_control import RunControl

RUN = "run-1"
PRINCIPAL = "agent-1"


def now_utc() -> datetime:
    """Return the current UTC instant."""
    return datetime.now(UTC)


def unknown_hold(ledger: StepLedger, *, units: int = 3, attempt: str = "node::a::0") -> tuple[int, AttemptHold]:
    """Open a lease, reserve a hold and record it UNKNOWN, as a crash would."""
    epoch = ledger.open_lease(RUN, max_steps=10)
    hold = ledger.reserve_attempt(RUN, epoch, attempt, units=units)
    ledger.mark_unknown(
        RUN,
        UnknownDisposition(
            attempt_id=attempt,
            hold_id=hold.hold_id,
            fence_epoch=epoch,
            cause="crash_before_settle",
            stop_state="none",
            settlement_state="unsettled",
        ),
    )
    return epoch, hold


def grant(
    ledger: StepLedger,
    hold: AttemptHold,
    epoch: int,
    *,
    grant_id: str = "grant-1",
    kind: str = "release",
    units: int = 3,
    units_basis: str = "steps",
    basis: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    digest: str | None = None,
    store_id: str | None = None,
    principal: str = PRINCIPAL,
    hold_epoch: int | None = None,
    lease_epoch: int | None = None,
) -> VerifiedGrant:
    """Build verified facts bound to a real hold, as an issuer's verifier would."""
    stamp = now_utc()
    return VerifiedGrant(
        grant_id=grant_id,
        principal=principal,
        run_id=RUN,
        hold_id=hold.hold_id,
        kind=kind,  # type: ignore[arg-type]
        units=units,
        units_basis=units_basis,
        ledger_cost_basis=basis or ledger.LEGACY_COST_BASIS,
        hold_fence_epoch=hold_epoch if hold_epoch is not None else hold.fence_epoch,
        consumer_lease_epoch=lease_epoch if lease_epoch is not None else epoch,
        ledger_store_id=store_id or ledger.store_id,
        issued_at=issued_at or stamp - timedelta(seconds=10),
        expires_at=expires_at or stamp + timedelta(seconds=900),
        payload_digest=digest or (grant_id.encode().hex() + "0" * 64)[:64],
        verifier_id="phylax.test",
    )


def fresh_obs(g: VerifiedGrant, *, revoked: bool = False, age: float = 0.0) -> RevocationObservation:
    """Return a revocation observation taken ``age`` seconds ago."""
    return RevocationObservation(g.grant_id, revoked, now_utc() - timedelta(seconds=age))


def spend(ledger: StepLedger, g: VerifiedGrant, **kwargs: Any) -> AdjustmentReceipt:
    """Consume ``g`` with a fresh, unrevoked observation."""
    obs = kwargs.pop("obs", None) or fresh_obs(g)
    return ledger.consume_adjustment_grant(g, obs, caller_principal=kwargs.pop("caller", PRINCIPAL), **kwargs)


@pytest.fixture
def ledger(tmp_path: Path) -> StepLedger:
    """Return a ledger backed by a fresh private store."""
    return StepLedger(tmp_path / "ledger.sqlite3")


def refusal(call: Any) -> str:
    """Run ``call`` and return the closed refusal code it raises."""
    with pytest.raises(AdjustmentGrantRefused) as raised:
        call()
    return raised.value.code


# --- boundary and vocabulary -------------------------------------------------


def test_oramasys_import_graph_has_no_nacl_and_no_phylax() -> None:
    """The runtime carries no cryptographic or issuer module."""
    code = (
        "import sys, orama.graph.grant_verifier, orama.graph.execution_guard\n"
        "assert 'nacl' not in sys.modules and 'phylax' not in sys.modules\n"
        "print('OK')\n"
    )
    src = str(Path(__file__).resolve().parents[1])
    out = subprocess.run(
        [sys.executable, "-c", code], env={"PYTHONPATH": src, "PATH": ""},
        capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "OK"


def test_vocabulary_is_closed_and_partitioned() -> None:
    """Verification and consumption codes are disjoint and unknown codes are refused."""
    assert not VERIFICATION_REFUSAL_CODES & CONSUMPTION_REFUSAL_CODES
    assert CLOSED_REFUSAL_CODES == VERIFICATION_REFUSAL_CODES | CONSUMPTION_REFUSAL_CODES
    assert len(VERIFICATION_REFUSAL_CODES) == 9
    with pytest.raises(ValueError):
        AdjustmentGrantRefused("free text reason")  # type: ignore[arg-type]


def test_deny_all_is_the_default_wiring(ledger: StepLedger) -> None:
    """With no verifier injected, every adjustment is denied."""
    verifier = DenyAllGrantVerifier()
    assert refusal(lambda: verifier.verify(b"{}")) == "verifier.unavailable"
    assert refusal(lambda: verifier.revocation("g")) == "verifier.unavailable"
    consumer = AdjustmentGrantConsumer(ledger)
    assert refusal(lambda: consumer.consume(b"{}", caller_principal=PRINCIPAL)) == "verifier.unavailable"


def test_ledger_refuses_facts_that_did_not_come_through_the_port(ledger: StepLedger) -> None:
    """A look-alike object is not accepted by the consumption primitive."""
    @dataclass
    class Fake:
        grant_id: str = "g"

    assert refusal(lambda: ledger.consume_adjustment_grant(
        Fake(), Fake(), caller_principal=PRINCIPAL)) == "grant.malformed"  # type: ignore[arg-type]


# --- spending against an UNKNOWN hold ---------------------------------------


def test_release_of_an_unknown_hold_by_its_real_hold_id_frees_the_steps(ledger: StepLedger) -> None:
    """The grant's hold_id is the ledger's opaque hold id, not the attempt id."""
    epoch, hold = unknown_hold(ledger, units=3)
    assert hold.hold_id.startswith("hold:")
    assert ledger.used(RUN) == 3

    receipt = spend(ledger, grant(ledger, hold, epoch, kind="release", units=3))

    assert receipt.balance_delta == 3 and receipt.verifier_id == "phylax.test"
    assert ledger.hold_state(RUN, "node::a::0") == "released"
    assert ledger.used(RUN) == 0


def test_settle_of_an_unknown_hold_keeps_the_charge(ledger: StepLedger) -> None:
    """Settling resolves the uncertainty without refunding the steps."""
    epoch, hold = unknown_hold(ledger, units=3)
    spend(ledger, grant(ledger, hold, epoch, kind="settle", units=3))
    assert ledger.hold_state(RUN, "node::a::0") == "settled"
    assert ledger.used(RUN) == 3


@pytest.mark.parametrize("kind", ["release", "settle"])
def test_a_live_held_hold_is_never_touched_by_a_grant(ledger: StepLedger, kind: str) -> None:
    """Only UNKNOWN holds are adjustable; in-flight work keeps its reservation."""
    epoch = ledger.open_lease(RUN, max_steps=10)
    hold = ledger.reserve_attempt(RUN, epoch, "node::a::0", units=2)
    code = refusal(lambda: spend(ledger, grant(ledger, hold, epoch, kind=kind, units=2)))
    assert code == "grant.hold_ineligible"
    assert ledger.hold_state(RUN, "node::a::0") == "held"
    assert ledger.used(RUN) == 2


def test_an_attempt_id_is_not_a_hold_id(ledger: StepLedger) -> None:
    """Naming the attempt instead of the hold finds nothing."""
    epoch, hold = unknown_hold(ledger)
    forged = replace(grant(ledger, hold, epoch), hold_id="node::a::0")
    assert refusal(lambda: spend(ledger, forged)) == "grant.hold_ineligible"


def test_an_already_settled_hold_is_refused(ledger: StepLedger) -> None:
    """A normally settled hold has nothing left to adjust."""
    epoch = ledger.open_lease(RUN, max_steps=5)
    hold = ledger.reserve_attempt(RUN, epoch, "node::a::0", units=1)
    ledger.prepare_commit(RUN, "node::a::0", hold.hold_id, epoch, "digest-a")
    ledger.settle_commit(RUN, "node::a::0", "digest-a")
    assert refusal(lambda: spend(ledger, grant(ledger, hold, epoch, units=1))) == "grant.hold_ineligible"


# --- remaining balance across several grants --------------------------------


def test_partial_grants_track_the_remaining_balance_until_resolved(ledger: StepLedger) -> None:
    """Grants of 1 then 2 against a hold of 3 both land; the hold resolves last."""
    epoch, hold = unknown_hold(ledger, units=3)
    spend(ledger, grant(ledger, hold, epoch, grant_id="g1", kind="release", units=1))
    assert ledger.hold_state(RUN, "node::a::0") == "unknown"
    assert ledger.used(RUN) == 2
    spend(ledger, grant(ledger, hold, epoch, grant_id="g2", kind="settle", units=2))
    assert ledger.hold_state(RUN, "node::a::0") == "settled"
    assert ledger.used(RUN) == 2
    row = ledger._db.execute(
        "SELECT settlement_state FROM unknown_dispositions WHERE run_id = ? AND attempt_id = ?",
        (RUN, "node::a::0"),
    ).fetchone()
    assert row[0] == "settled"


def test_a_second_grant_exceeding_the_remaining_balance_is_refused(ledger: StepLedger) -> None:
    """Two valid grants cannot together exceed what the hold still holds."""
    epoch, hold = unknown_hold(ledger, units=3)
    spend(ledger, grant(ledger, hold, epoch, grant_id="g1", units=2))
    code = refusal(lambda: spend(ledger, grant(ledger, hold, epoch, grant_id="g2", units=2)))
    assert code == "grant.units_exceed_remaining"
    assert ledger.hold_state(RUN, "node::a::0") == "unknown"


def test_multi_unit_release_reduces_the_projection(ledger: StepLedger) -> None:
    """A non-step dimension is credited back through the charge projection."""
    epoch = ledger.open_lease(RUN, max_steps=10)
    limits = ChargeUnits(steps=10, elapsed_ms=100, cost_microunits=50, effect_attempts=2, cost_basis="usd_cents")
    ledger.configure_limits(RUN, epoch, limits)
    hold = ledger.reserve_charge(
        RUN, epoch, "node::a::0",
        ChargeUnits(steps=1, elapsed_ms=0, cost_microunits=40, effect_attempts=0, cost_basis="usd_cents"),
    )
    ledger.mark_unknown(RUN, UnknownDisposition(
        attempt_id="node::a::0", hold_id=hold.hold_id, fence_epoch=epoch,
        cause="crash_before_settle", stop_state="none", settlement_state="unsettled"))
    assert ledger.usage(RUN).cost_microunits == 40

    spend(ledger, grant(ledger, hold, epoch, kind="release", units=40,
                        units_basis="cost_microunits", basis="usd_cents", grant_id="g-cost"))
    assert ledger.usage(RUN).cost_microunits == 0
    assert ledger.hold_state(RUN, "node::a::0") == "unknown"  # steps dimension still open
    spend(ledger, grant(ledger, hold, epoch, kind="release", units=1, grant_id="g-steps",
                        basis="usd_cents"))
    assert ledger.hold_state(RUN, "node::a::0") == "released"


def test_cost_basis_must_equal_the_ledger_basis_exactly(ledger: StepLedger) -> None:
    """A grant computed under another basis is refused, never coerced."""
    epoch, hold = unknown_hold(ledger)
    for basis in ("usd_cents", "legacy-step-only-v1", "BTC_SATOSHIS"):
        assert refusal(lambda b=basis: spend(ledger, grant(ledger, hold, epoch, basis=b))) == "grant.basis_mismatch"


# --- idempotence -------------------------------------------------------------


def test_identical_retry_returns_the_stored_receipt_even_after_expiry_and_revocation(ledger: StepLedger) -> None:
    """An exact retry sees the recorded result, never a recomputation."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    first = spend(ledger, g)
    later = now_utc() + timedelta(days=1)
    again = ledger.consume_adjustment_grant(
        g, fresh_obs(g, revoked=True), caller_principal=PRINCIPAL, now=later)
    assert again == first
    assert ledger.retry_adjustment_grant(
        grant_id=g.grant_id, caller_principal=PRINCIPAL, payload_digest=g.payload_digest) == first
    assert ledger.used(RUN) == 0  # not freed twice


def test_altered_digest_or_principal_on_retry_is_refused(ledger: StepLedger) -> None:
    """The stored receipt is only returned for the same digest and principal."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    spend(ledger, g)
    assert refusal(lambda: ledger.retry_adjustment_grant(
        grant_id=g.grant_id, caller_principal="imposter", payload_digest=g.payload_digest)
    ) == "grant.principal_mismatch"
    assert refusal(lambda: ledger.retry_adjustment_grant(
        grant_id=g.grant_id, caller_principal=PRINCIPAL, payload_digest="f" * 64)
    ) == "grant.digest_conflict"


# --- freshness and fencing ---------------------------------------------------


def test_stale_or_revoked_observation_refuses(ledger: StepLedger) -> None:
    """A revocation observation older than 60s, or a revoked one, refuses."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    assert refusal(lambda: spend(ledger, g, obs=fresh_obs(g, age=61))) == "revocation.stale"
    assert refusal(lambda: spend(ledger, g, obs=fresh_obs(g, revoked=True))) == "grant.revoked"
    assert ledger.hold_state(RUN, "node::a::0") == "unknown"


def test_expired_and_future_dated_grants_refuse(ledger: StepLedger) -> None:
    """Lifetime is judged against the consumption clock."""
    epoch, hold = unknown_hold(ledger)
    stamp = now_utc()
    expired = grant(ledger, hold, epoch, issued_at=stamp - timedelta(seconds=100), expires_at=stamp - timedelta(seconds=1))
    assert refusal(lambda: spend(ledger, expired)) == "grant.expired"
    future = grant(ledger, hold, epoch, issued_at=stamp + timedelta(seconds=70), expires_at=stamp + timedelta(seconds=500))
    assert refusal(lambda: spend(ledger, future)) == "grant.future_dated"


def test_store_and_principal_binding(ledger: StepLedger) -> None:
    """A grant for another store, or presented by another caller, is refused."""
    epoch, hold = unknown_hold(ledger)
    assert refusal(lambda: spend(ledger, grant(ledger, hold, epoch, store_id="store:other"))) == "grant.store_mismatch"
    g = grant(ledger, hold, epoch)
    assert refusal(lambda: spend(ledger, g, caller="imposter")) == "grant.principal_mismatch"


def test_hold_and_lease_epochs_are_checked_independently(ledger: StepLedger) -> None:
    """After a takeover the hold keeps its creation epoch; the lease is the new one."""
    epoch1, hold = unknown_hold(ledger)
    epoch2 = ledger.open_lease(RUN, max_steps=10)
    assert epoch2 == epoch1 + 1
    stale_lease = grant(ledger, hold, epoch1, lease_epoch=epoch1, grant_id="stale")
    assert refusal(lambda: spend(ledger, stale_lease)) == "grant.epoch_fenced"
    wrong_hold = grant(ledger, hold, epoch2, hold_epoch=epoch2, lease_epoch=epoch2, grant_id="wrong")
    assert refusal(lambda: spend(ledger, wrong_hold)) == "grant.epoch_fenced"
    ok = grant(ledger, hold, epoch2, hold_epoch=epoch1, lease_epoch=epoch2, grant_id="ok")
    assert spend(ledger, ok).kind == "release"


def test_a_terminal_run_can_still_resolve_its_unknown_holds(tmp_path: Path) -> None:
    """Receipts are point-in-time snapshots; resolution is recorded separately."""
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    control = RunControl(store_path=store)
    control.register_run(run_id=RUN, owner_principal=PRINCIPAL)
    epoch, hold = unknown_hold(ledger)
    before = control.record_runtime_terminal(run_id=RUN, epoch=epoch, outcome="unknown", reason="run.execution_error")
    assert before.unresolved_attempts

    spend(ledger, grant(ledger, hold, epoch))

    assert control.terminal_receipt(RUN) == before  # the snapshot is immutable
    assert ledger.hold_state(RUN, "node::a::0") == "released"
    events = ledger._db.execute(
        "SELECT COUNT(*) FROM accounting_events WHERE run_id = ? AND event_type = 'adjustment_consumed'", (RUN,)
    ).fetchone()[0]
    assert events == 1
    ledger.close()
    control.close()


# --- the consumer: verifier injection, normalization, replay -----------------


class StubVerifier:
    """Verifier double returning scripted facts or raising a scripted error."""

    def __init__(self, result: Any = None, error: BaseException | None = None, revocation: Any = None) -> None:
        self.result, self.error, self.obs = result, error, revocation
        self.calls: list[str] = []

    def verify(self, wire: bytes) -> Any:
        self.calls.append("verify")
        if self.error is not None:
            raise self.error
        return self.result

    def revocation(self, grant_id: str) -> Any:
        self.calls.append("revocation")
        return self.obs or RevocationObservation(grant_id, False, now_utc())


def wire_for(g: VerifiedGrant) -> bytes:
    """Return a minimal wire carrying only the lookup keys."""
    return json.dumps({"grant_id": g.grant_id, "payload_digest": g.payload_digest}).encode()


def test_consumer_verifies_outside_the_transaction_then_spends(ledger: StepLedger) -> None:
    """Verify and revocation both run before the ledger is asked to spend."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    verifier = StubVerifier(result=g)
    receipt = AdjustmentGrantConsumer(ledger, verifier).consume(wire_for(g), caller_principal=PRINCIPAL)
    assert verifier.calls == ["verify", "revocation"]
    assert receipt.grant_id == g.grant_id


def test_consumer_rebuilds_a_foreign_result_into_its_own_type(ledger: StepLedger) -> None:
    """A structurally compatible object from another package is copied, not trusted."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)

    @dataclass(frozen=True)
    class ForeignVerified:
        grant_id: str
        principal: str
        run_id: str
        hold_id: str
        kind: str
        units: int
        units_basis: str
        ledger_cost_basis: str
        hold_fence_epoch: int
        consumer_lease_epoch: int
        ledger_store_id: str
        issued_at: datetime
        expires_at: datetime
        payload_digest: str
        verifier_id: str

    foreign = ForeignVerified(**{k: getattr(g, k) for k in ForeignVerified.__dataclass_fields__})
    assert not isinstance(foreign, VerifiedGrant)
    consumer = AdjustmentGrantConsumer(ledger, StubVerifier(result=foreign))
    assert consumer.consume(wire_for(g), caller_principal=PRINCIPAL).balance_delta == 3


def test_consumer_normalizes_foreign_failures_into_the_closed_set(ledger: StepLedger) -> None:
    """The issuer's own exception type, or an arbitrary error, never leaks inward."""
    class IssuerRefusal(Exception):
        reason = "grant.signature_invalid"

    assert refusal(lambda: AdjustmentGrantConsumer(ledger, StubVerifier(error=IssuerRefusal())).consume(
        b"{}", caller_principal=PRINCIPAL)) == "grant.signature_invalid"

    class Unknown(Exception):
        reason = "something free-form"

    assert refusal(lambda: AdjustmentGrantConsumer(ledger, StubVerifier(error=Unknown())).consume(
        b"{}", caller_principal=PRINCIPAL)) == "verifier.unavailable"
    assert refusal(lambda: AdjustmentGrantConsumer(ledger, StubVerifier(error=OSError("socket"))).consume(
        b"{}", caller_principal=PRINCIPAL)) == "verifier.unavailable"


def test_consumer_answers_a_retry_after_the_verifier_reports_expiry(ledger: StepLedger) -> None:
    """Row 9: once spent, an exact retry still gets the recorded receipt."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    first = AdjustmentGrantConsumer(ledger, StubVerifier(result=g)).consume(wire_for(g), caller_principal=PRINCIPAL)

    class Expired(Exception):
        reason = "grant.expired"

    retried = AdjustmentGrantConsumer(ledger, StubVerifier(error=Expired())).consume(
        wire_for(g), caller_principal=PRINCIPAL)
    assert retried == first
    # a different grant that is merely expired is still refused
    other = grant(ledger, hold, epoch, grant_id="never-spent")
    assert refusal(lambda: AdjustmentGrantConsumer(ledger, StubVerifier(error=Expired())).consume(
        wire_for(other), caller_principal=PRINCIPAL)) == "grant.expired"


def test_consumer_refuses_a_revocation_observation_for_another_grant(ledger: StepLedger) -> None:
    """The observation must be about the grant being spent."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch)
    wrong = RevocationObservation("someone-else", False, now_utc())
    consumer = AdjustmentGrantConsumer(ledger, StubVerifier(result=g, revocation=wrong))
    assert refusal(lambda: consumer.consume(wire_for(g), caller_principal=PRINCIPAL)) == "grant.malformed"


# --- cross-repo contract ------------------------------------------------------


def test_shared_conformance_vector_maps_onto_the_verified_grant_contract(ledger: StepLedger) -> None:
    """The issuer's fixed vector carries exactly the facts the port needs.

    Oramasys cannot verify the signature (by design); it checks that the wire
    names every field of ``VerifiedGrant`` with the right shape and that the
    cost basis is the ledger's own, so the two repositories cannot drift.
    """
    vector = json.loads(Path(__file__).with_name("vectors").joinpath("adjustment-grant-v1.json").read_text("utf-8"))
    assert vector["schema"] == "phylax.adjustment-grant.conformance.v1"
    wire = json.loads(vector["wire"])
    for name in (
        "grant_id", "principal", "run_id", "hold_id", "kind", "units", "units_basis",
        "ledger_cost_basis", "hold_fence_epoch", "consumer_lease_epoch", "ledger_store_id",
        "issued_at", "expires_at", "payload_digest",
    ):
        assert name in wire, name
    assert wire["ledger_cost_basis"] == ledger.LEGACY_COST_BASIS
    assert wire["hold_fence_epoch"] >= 1 and wire["consumer_lease_epoch"] >= 1
    facts = VerifiedGrant(
        **{k: wire[k] for k in (
            "grant_id", "principal", "run_id", "hold_id", "kind", "units", "units_basis",
            "ledger_cost_basis", "hold_fence_epoch", "consumer_lease_epoch", "ledger_store_id",
            "payload_digest")},
        issued_at=datetime.fromisoformat(wire["issued_at"].replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(wire["expires_at"].replace("Z", "+00:00")),
        verifier_id="phylax.vector",
    )
    assert facts.payload_digest == vector["payload_digest"]
