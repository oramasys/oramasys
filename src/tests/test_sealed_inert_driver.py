"""Sealed envelope and inert driver: seals, replays, unknown-preserving, redacted (DRAFT)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.effect_receipts import attempt_ref_for, receipt_digest_for
from orama.graph.final_boundary import FinalBoundaryRefused
from orama.graph.sealed_envelope import (
    INERT_TARGET,
    EnvelopeRefused,
    digest_of,
    open_envelope,
    seal,
)
from orama.graph.sealed_inert_driver import (
    INERT_EVIDENCE,
    SealedDriverRefused,
    SealedInertDriver,
    SendOutcomeUnknown,
)
from tests.test_dispatch_attempts import ATTEMPT, GRANT, ISSUER, NOW, Harness
from tests.test_effect_fencing import Operator
from tests.test_effect_seam import LIVE_UNTIL, SCOPE
from tests.test_final_boundary import Approvals, binding, untouched
from tests.test_inert_effect_integration import inert_harness

OP = "sha256:" + SCOPE.operation_digest


def envelope(**changes):
    """Seal the tuple the inert harness authorized, with optional changes."""
    fields = dict(
        attempt_id=ATTEMPT, operation_digest=OP, epoch=5, expires_at=LIVE_UNTIL, target=INERT_TARGET,
    )
    fields.update(changes)
    return seal(**fields)


class Recorder:
    """Simulation double that counts calls and may raise."""

    def __init__(self, result=INERT_EVIDENCE, error: BaseException | None = None) -> None:
        """Script the evidence or the exception."""
        self.result, self.error, self.calls = result, error, 0

    def __call__(self, env):
        """Count the call and answer as scripted."""
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def driver(h: Harness, *, effects=lambda: True, approvals="default", simulation=None, publisher=None):
    """Build a driver over the harness store with every gate open unless overridden."""
    return SealedInertDriver(
        h.store, effects_allowed=effects,
        approval_verifier=Approvals() if approvals == "default" else approvals,
        revocations=h.revocations, issuer_id=ISSUER, simulation=simulation or Recorder(),
        publisher=publisher, clock=lambda: NOW,
    )


def send(d: SealedInertDriver, env=None, principal: str = SCOPE.principal):
    """Send an envelope (the genuine one by default)."""
    env = env or envelope()
    return d.send(env.raw, env.digest, principal=principal)


def approve(h: Harness) -> str:
    """Record the single-use human approval for the genuine tuple."""
    return h.store.grant_effect_approval(binding(), approver=Operator(), now=NOW)


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    """An authorized inert attempt with its human approval granted."""
    harness = inert_harness(tmp_path)
    approve(harness)
    yield harness
    harness.store.close()


# --------------------------------------------------------------------- envelope


def test_seal_produces_the_exact_canonical_bytes_and_digest() -> None:
    """Six members, canonical, with the sha256 of the exact bytes."""
    env = envelope()
    parsed = json.loads(env.raw)
    assert set(parsed) == {"v", "attempt_id", "operation_digest", "target", "epoch", "expires_at"}
    assert parsed["v"] == 1 and parsed["target"] == "inert://simulation" and parsed["epoch"] == 5
    assert env.raw == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
    assert env.digest == digest_of(env.raw)
    reopened = open_envelope(env.raw, env.digest)
    assert reopened == env and reopened.expires_at == LIVE_UNTIL


def _bad_envelopes() -> list[tuple[str, bytes, str]]:
    """Build (id, raw bytes, expected reason) cases around a valid envelope."""
    good = json.loads(envelope().raw)

    def raw(**changes) -> bytes:
        body = {**good, **changes}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def without(key: str) -> bytes:
        body = {k: v for k, v in good.items() if k != key}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    return [
        ("extra-cmd", raw(cmd="rm -rf /"), "envelope_fields"),
        ("extra-shell", raw(shell="echo hi"), "envelope_fields"),
        ("missing-target", without("target"), "envelope_fields"),
        ("missing-epoch", without("epoch"), "envelope_fields"),
        ("version-2", raw(v=2), "envelope_version"),
        ("version-text", raw(v="1"), "envelope_version"),
        ("version-bool", raw(v=True), "envelope_version"),
        ("version-float", raw(v=1.0), "envelope_version"),
        ("target-http", raw(target="https://example.test/x"), "envelope_target"),
        ("target-file", raw(target="file:///etc/passwd"), "envelope_target"),
        ("target-suffix", raw(target="inert://simulation/x"), "envelope_target"),
        ("target-case", raw(target="inert://Simulation"), "envelope_target"),
        ("target-shell", raw(target="; rm -rf /"), "envelope_target"),
        ("digest-upper", raw(operation_digest="sha256:" + "B" * 64), "envelope_operation_digest"),
        ("digest-bare", raw(operation_digest="b" * 64), "envelope_operation_digest"),
        ("digest-short", raw(operation_digest="sha256:abc"), "envelope_operation_digest"),
        ("epoch-zero", raw(epoch=0), "envelope_epoch"),
        ("epoch-neg", raw(epoch=-1), "envelope_epoch"),
        ("epoch-bool", raw(epoch=True), "envelope_epoch"),
        ("epoch-text", raw(epoch="5"), "envelope_epoch"),
        ("epoch-float", raw(epoch=5.5), "envelope_epoch"),
        ("expiry-no-micros", raw(expires_at="2026-10-25T00:00:00Z"), "envelope_expiry_invalid"),
        ("expiry-offset", raw(expires_at="2026-10-25T00:00:00.000000+00:00"), "envelope_expiry_invalid"),
        ("expiry-number", raw(expires_at=5), "envelope_expiry_invalid"),
        ("attempt-space", raw(attempt_id="a b"), "envelope_attempt_id"),
        ("attempt-empty", raw(attempt_id=""), "envelope_attempt_id"),
        ("attempt-long", raw(attempt_id="a" * 1025), "envelope_attempt_id"),
        ("attempt-null", raw(attempt_id=None), "envelope_attempt_id"),
        ("spaced", json.dumps(good, sort_keys=True).encode(), "envelope_not_canonical"),
        ("unsorted", json.dumps(dict(reversed(list(good.items()))), separators=(",", ":")).encode(), "envelope_not_canonical"),
        ("duplicate", b'{"v":1,"v":1}', "envelope_malformed"),
        ("nan", b'{"v":NaN}', "envelope_malformed"),
        ("array", b"[1]", "envelope_fields"),
        ("scalar", b"55", "envelope_fields"),
        ("not-json", b"run this command", "envelope_malformed"),
        ("bad-utf8", b"\xff\xfe{}", "envelope_malformed"),
        ("oversize", b"{" + b" " * 5000 + b"}", "envelope_size"),
        ("empty", b"", "envelope_size"),
    ]


@pytest.mark.parametrize(("raw", "reason"), [(c[1], c[2]) for c in _bad_envelopes()],
                         ids=[c[0] for c in _bad_envelopes()])
def test_anything_but_the_exact_sealed_form_is_refused(raw: bytes, reason: str) -> None:
    """Each deviation is refused with its stable reason even when its digest is self-consistent."""
    with pytest.raises(EnvelopeRefused) as excinfo:
        open_envelope(raw, digest_of(raw))
    assert excinfo.value.reason == reason


@pytest.mark.parametrize("digest", ["", "sha256:" + "0" * 64, "sha256:XYZ", None, 5, "b" * 64])
def test_a_wrong_or_malformed_digest_is_refused(digest) -> None:
    """The envelope must hash to the digest it claims; the digest must be well formed."""
    with pytest.raises(EnvelopeRefused) as excinfo:
        open_envelope(envelope().raw, digest)  # type: ignore[arg-type]
    assert excinfo.value.reason == "envelope_digest_mismatch"


def test_seal_refuses_invalid_inputs_before_producing_bytes() -> None:
    """Sealing a bad tuple fails; it cannot produce an envelope that open would reject silently."""
    with pytest.raises(EnvelopeRefused):
        envelope(target="https://example.test")
    with pytest.raises(EnvelopeRefused):
        envelope(epoch=0)
    with pytest.raises(EnvelopeRefused):
        envelope(expires_at=NOW.replace(tzinfo=None))


def test_the_driver_modules_hold_no_execution_path() -> None:
    """Structural guard: no shell, process, network, eval or file access in the driver or envelope."""
    for module in ("sealed_inert_driver", "sealed_envelope", "effect_receipts"):
        source = Path(__import__(f"orama.graph.{module}", fromlist=["x"]).__file__).read_text(
            encoding="utf-8"
        )
        for forbidden in ("subprocess", "os.system", "socket", "eval(", "exec(", "open(", "requests",
                          "httpx", "urllib", "shlex", "popen"):
            assert forbidden not in source, (module, forbidden)


# ------------------------------------------------------------------------ driver


def test_a_sealed_send_settles_once_with_a_redacted_receipt(h: Harness) -> None:
    """The send runs, settles confirmed, and the receipt has exactly the four public fields."""
    sim = Recorder()
    receipt = send(driver(h, simulation=sim))
    assert sim.calls == 1
    assert set(receipt.as_dict()) == {"attempt_ref", "outcome", "receipt_digest", "recorded_at"}
    assert receipt.outcome == "confirmed" and receipt.attempt_ref == attempt_ref_for(ATTEMPT)
    assert receipt.receipt_digest == receipt_digest_for(receipt.attempt_ref, "confirmed", envelope().digest)
    row = h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (1, "confirmed", INERT_EVIDENCE)
    public = json.dumps(receipt.as_dict())
    for secret in (ATTEMPT, GRANT, SCOPE.principal, SCOPE.operation_digest, ISSUER, "inert://"):
        assert secret not in public


def test_the_receipt_is_written_with_the_outcome_in_one_transaction(h: Harness) -> None:
    """There is a stored receipt exactly when the outcome settled, and settle refuses unproven input."""
    assert h.store.receipt(ATTEMPT) is None
    send(driver(h))
    stored = h.store.receipt(ATTEMPT)
    assert stored is not None and stored.published_at is None and stored.attempt_id == ATTEMPT
    with pytest.raises(OutcomeRefused):
        h.store.settle_with_receipt(ATTEMPT, "failed", "evidence", "sha256:" + "1" * 64, NOW)
    assert h.store._db.execute("SELECT count(*) FROM effect_receipts").fetchone() == (1,)


def test_exact_replay_returns_the_stored_receipt_without_dispatching(h: Harness) -> None:
    """Double submit: the second call returns the identical receipt and nothing runs again."""
    sim = Recorder()
    d = driver(h, simulation=sim)
    first, second = send(d), send(d)
    assert first == second and sim.calls == 1
    denied = driver(h, effects=None, approvals=None, simulation=sim)
    assert send(denied) == first and sim.calls == 1


def test_replay_after_restart_returns_the_same_receipt(tmp_path: Path) -> None:
    """The receipt is durable: a new process-equivalent (reopened store, new driver) gets it back."""
    h = inert_harness(tmp_path)
    approve(h)
    first = send(driver(h))
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        h2 = Harness(reopened, h.path, h.verifier, h.gates, h.revocations)
        sim = Recorder()
        assert send(driver(h2, simulation=sim)) == first
        assert sim.calls == 0
    finally:
        reopened.close()


def test_a_second_dispatch_for_the_same_identity_is_refused(h: Harness) -> None:
    """A different envelope for a settled attempt is refused, not dispatched."""
    sim = Recorder()
    d = driver(h, simulation=sim)
    send(d)
    other = envelope(expires_at=LIVE_UNTIL + timedelta(seconds=1))
    with pytest.raises(SealedDriverRefused, match="replay_envelope_mismatch"):
        send(d, other)
    assert sim.calls == 1


def test_another_principal_cannot_replay_the_receipt(h: Harness) -> None:
    """Replay is bound to the recorded principal."""
    d = driver(h)
    send(d)
    with pytest.raises(SealedDriverRefused, match="principal_mismatch"):
        send(d, principal="someone-else")


def test_concurrent_double_submit_dispatches_exactly_once(h: Harness) -> None:
    """Racing submits of one envelope produce one simulation; losers refuse or replay."""
    sim = Recorder()
    d = driver(h, simulation=sim)
    env = envelope()
    results, errors = [], []

    def worker() -> None:
        try:
            results.append(d.send(env.raw, env.digest, principal=SCOPE.principal))
        except OutcomeRefused as refusal:
            errors.append(refusal.reason)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert sim.calls == 1
    assert len(results) >= 1 and len(set(r.receipt_digest for r in results)) == 1
    assert set(errors) <= {"send_already_started"}
    assert h.store._db.execute("SELECT count(*) FROM effect_receipts").fetchone() == (1,)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"operation_digest": "sha256:" + "e" * 64}, "operation_digest_mismatch"),
        ({"epoch": 6}, "epoch_mismatch"),
        ({"expires_at": LIVE_UNTIL + timedelta(minutes=1)}, "expiry_mismatch"),
        ({"attempt_id": "attempt-other"}, "attempt_not_authorized"),
    ],
)
def test_a_substituted_field_never_dispatches(h: Harness, changes: dict, reason: str) -> None:
    """Post-approval substitution of any sealed field is refused before the send marker."""
    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        send(driver(h, simulation=sim), envelope(**changes))
    assert excinfo.value.reason == reason
    assert sim.calls == 0
    untouched(h)
    assert send(driver(h)).outcome == "confirmed"


def test_a_different_principal_cannot_send(h: Harness) -> None:
    """The authenticated principal is part of the bound tuple."""
    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused, match="principal_mismatch"):
        send(driver(h, simulation=sim), principal="mallory")
    assert sim.calls == 0


def test_effects_deny_is_the_default_and_refuses_before_dispatch(h: Harness) -> None:
    """A driver built with no effects switch and no verifier refuses; nothing is sent."""
    sim = Recorder()
    d = SealedInertDriver(
        h.store, effects_allowed=None, approval_verifier=None, revocations=None,
        issuer_id=ISSUER, simulation=sim, clock=lambda: NOW,
    )
    with pytest.raises(FinalBoundaryRefused, match="effects_denied"):
        send(d)
    assert sim.calls == 0
    untouched(h)
    assert h.store.terminal_refusal(ATTEMPT).reason == "effects_denied"


def test_an_unavailable_verifier_refuses_before_dispatch(h: Harness) -> None:
    """A Phylax outage refuses; it does not send and verify later."""
    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused, match="approval_verifier_unavailable"):
        send(driver(h, approvals=Approvals(RuntimeError("down")), simulation=sim))
    assert sim.calls == 0
    untouched(h)


def test_the_epoch_advancing_during_verification_still_stops_the_send(h: Harness) -> None:
    """The store re-checks the tuple inside the send transaction, closing check-then-act."""
    class Advancing(Approvals):
        """Verifier that lets the fencing epoch move after the pre-check."""

        def verify(self, binding):
            """Advance the epoch, then approve."""
            h.store.advance_fencing_epoch(9, operator=Operator(), now=NOW)
            return super().verify(binding)

    sim = Recorder()
    with pytest.raises(FinalBoundaryRefused) as excinfo:
        send(driver(h, approvals=Advancing(), simulation=sim))
    assert excinfo.value.reason == "epoch_stale" and excinfo.value.terminal
    assert sim.calls == 0
    untouched(h)
    assert h.store.terminal_refusal(ATTEMPT).reason == "epoch_stale"


def test_an_expired_envelope_refuses(h: Harness) -> None:
    """At or after expiry the sealed command is dead."""
    d = SealedInertDriver(
        h.store, effects_allowed=lambda: True, approval_verifier=Approvals(),
        revocations=h.revocations, issuer_id=ISSUER, clock=lambda: LIVE_UNTIL,
    )
    with pytest.raises(FinalBoundaryRefused, match="expired"):
        send(d)


# ---------------------------------------------------------- unknown is preserved


def test_a_timeout_after_dispatch_leaves_the_outcome_unknown_and_never_retries(tmp_path: Path) -> None:
    """The send marker is durable; a timeout does not fail, roll back or retry the effect."""
    h = inert_harness(tmp_path)
    approve(h)
    sim = Recorder(error=TimeoutError("provider slow"))
    with pytest.raises(SendOutcomeUnknown) as excinfo:
        send(driver(h, simulation=sim))
    assert excinfo.value.reason == "outcome_unknown" and isinstance(excinfo.value.__cause__, TimeoutError)
    row = h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (1, "unknown", None)
    assert h.store.receipt(ATTEMPT) is None and h.store.terminal_refusal(ATTEMPT) is None
    again = Recorder()
    with pytest.raises(FinalBoundaryRefused, match="send_already_started"):
        send(driver(h, simulation=again))
    assert again.calls == 0
    h.store.close()
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        assert reopened.outbox_row(ATTEMPT)["outcome"] == "unknown"
        h2 = Harness(reopened, h.path, h.verifier, h.gates, h.revocations)
        with pytest.raises(FinalBoundaryRefused, match="send_already_started"):
            send(driver(h2, simulation=again))
        assert again.calls == 0
    finally:
        reopened.close()


@pytest.mark.parametrize("evidence", ["", "http://provider/ok", 5, None, "inert-simulation:" + "x" * 200,
                                      "inert-simulation:\n"],
                         ids=["empty", "url", "int", "none", "long", "newline"])
def test_unproven_evidence_keeps_the_outcome_unknown(h: Harness, evidence) -> None:
    """Only the inert evidence label can settle; anything else is unproven and stays unknown."""
    with pytest.raises(SendOutcomeUnknown) as excinfo:
        send(driver(h, simulation=Recorder(result=evidence)))
    assert excinfo.value.reason == "evidence_invalid"
    assert h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"
    assert h.store.receipt(ATTEMPT) is None


# ---------------------------------------------------------------- publication


def test_publication_delivers_only_the_redacted_receipt_and_stamps_it(h: Harness) -> None:
    """The observer gets the four-field record; the store notes the first delivery."""
    seen = []
    receipt = send(driver(h, publisher=seen.append))
    assert seen == [receipt]
    assert h.store.receipt(ATTEMPT).published_at is not None
    assert h.store.unpublished_receipts() == []
    assert h.store.mark_receipt_published(ATTEMPT, NOW) is False


def test_a_failing_observer_leaves_the_receipt_for_bounded_redelivery(h: Harness) -> None:
    """Publication trouble never affects the effect; pending receipts are delivered later."""
    def broken(receipt) -> None:
        raise ConnectionError("observer down")

    first = send(driver(h, publisher=broken))
    assert [s.attempt_id for s in h.store.unpublished_receipts()] == [ATTEMPT]
    delivered = []
    d = driver(h, publisher=delivered.append)
    assert d.publish_pending(limit=1) == 1 and delivered == [first]
    assert d.publish_pending() == 0 and delivered == [first]


def test_unpublished_limit_is_bounded() -> None:
    """The delivery batch size must be a sane integer."""
    store = SqliteAttemptStore.__new__(SqliteAttemptStore)
    for bad in (0, -1, 1001, True, "5"):
        with pytest.raises(ValueError):
            store.unpublished_receipts(bad)  # type: ignore[arg-type]


def test_receipts_are_append_only_except_the_first_publication_stamp(h: Harness) -> None:
    """The table refuses deletes and any rewrite of a recorded fact."""
    send(driver(h))
    db = h.store._db
    for statement in (
        "DELETE FROM effect_receipts",
        "UPDATE effect_receipts SET outcome = 'failed'",
        "UPDATE effect_receipts SET receipt_digest = 'x'",
        "UPDATE effect_receipts SET recorded_at = 'x'",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="append-only|first publication"):
            db.execute(statement)
    db.execute("UPDATE effect_receipts SET published_at = 'stamp'")
    with pytest.raises(sqlite3.DatabaseError, match="first publication"):
        db.execute("UPDATE effect_receipts SET published_at = 'again'")
