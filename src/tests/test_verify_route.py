"""POST /grants/verify: verification only, never exposed unless serving, denials are auditable."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.api.capabilities import CapabilityConfig
from orama.api.denial_audit import DenialAuditLog, receipt_ref_for
from orama.api.public_errors import DENY_CODES
from orama.api.server import create_app
from orama.api.verify_route import AUTH_FAILURE_AUDIT_LIMIT, _BODY_LIMIT
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import (
    AdjustmentGrantConsumer,
    AdjustmentGrantRefused,
    RevocationObservation,
    VerifiedGrant,
)
from tests.test_adjustment_grant_consumer import StubVerifier, grant, unknown_hold, wire_for
from tests.test_capabilities import BIN, CFG, Signer, signed

TOKEN = "test-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)
SECRET_GRANT_ID = "grant-secret-id-0001"
SECRET_KEY = "key-secret-id-0001"


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the bearer capability the route authenticates with."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


def verified(grant_id: str = SECRET_GRANT_ID, **changes) -> VerifiedGrant:
    """Return a well-formed verified grant that is live at ``NOW``."""
    fields = dict(
        grant_id=grant_id, principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL, run_id="run-1",
        hold_id="hold-1", kind="release", units=1, units_basis="steps", ledger_cost_basis="steps",
        hold_fence_epoch=1, consumer_lease_epoch=1, ledger_store_id="store-1",
        issued_at=NOW - timedelta(seconds=30), expires_at=NOW + timedelta(minutes=5),
        payload_digest="a" * 64, verifier_id="phylax.test",
    )
    fields.update(changes)
    return VerifiedGrant(**fields)


def observation(grant_id: str = SECRET_GRANT_ID, **changes) -> RevocationObservation:
    """Return a fresh, not-revoked observation at ``NOW``."""
    fields = dict(grant_id=grant_id, revoked=False, observed_at=NOW)
    fields.update(changes)
    return RevocationObservation(**fields)


def serving_app(verifier, tmp_path: Path, **kw):
    """Build an app with a signed serving bit, the injected verifier and a denial log."""
    audit = DenialAuditLog(tmp_path / "audit" / "denials.sqlite")
    app = create_app(
        capability_config=CapabilityConfig(
            record=signed(serving=True), expected_binary_digest=BIN, expected_config_digest=CFG,
            signature_verifier=Signer(),
        ),
        grant_verifier=verifier, denial_audit=audit, verify_clock=lambda: NOW, **kw,
    )
    return app, audit


async def post(app, body, headers=AUTH, *, raw: bytes | None = None):
    """POST to the verify route."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        if raw is not None:
            return await client.post("/grants/verify", content=raw, headers=headers)
        return await client.post("/grants/verify", json=body, headers=headers)


def assert_public_error(response, status: int, code: str) -> dict:
    """Assert the contract body shape and that nothing secret leaked; return the error object."""
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) <= {"code", "correlation_id", "receipt_ref"}
    assert body["error"]["code"] == code
    assert SECRET_GRANT_ID not in response.text and SECRET_KEY not in response.text
    return body["error"]


# --------------------------------------------------------------- exposure


async def test_route_is_not_exposed_by_default() -> None:
    """With no serving bit the route answers 404 serving.route_not_exposed, even authenticated."""
    stub = StubVerifier(result=verified(), revocation=observation())
    response = await post(create_app(grant_verifier=stub), {"grant": "{}"})  # type: ignore[arg-type]
    assert_public_error(response, 404, "serving.route_not_exposed")
    assert stub.calls == []


async def test_route_is_not_exposed_when_serving_is_false_in_a_valid_record(tmp_path: Path) -> None:
    """A valid record with serving false and effects true still does not expose verification."""
    app = create_app(
        capability_config=CapabilityConfig(
            record=signed(effects=True), expected_binary_digest=BIN, expected_config_digest=CFG,
            signature_verifier=Signer(), permit_verifier=object(),
        ),
        grant_verifier=StubVerifier(result=verified(), revocation=observation()),  # type: ignore[arg-type]
    )
    assert_public_error(await post(app, {"grant": "{}"}), 404, "serving.route_not_exposed")


async def test_the_route_still_needs_the_bearer(tmp_path: Path) -> None:
    """Exposure is not authentication: no bearer, no verification."""
    app, _ = serving_app(StubVerifier(result=verified(), revocation=observation()), tmp_path)
    response = await post(app, {"grant": "{}"}, headers={})
    assert response.status_code == 401


async def test_a_failed_bearer_gets_the_public_denial_and_an_audit_record(tmp_path: Path) -> None:
    """Middleware enforces the bearer, yet the 401 carries the public body and a durable receipt."""
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)
    for headers in ({}, {"Authorization": "Bearer wrong-token"}):
        error = assert_public_error(
            await post(app, {"grant": "{}"}, headers=headers), 401, "deny.unauthorized_caller"
        )
        assert audit.has(error["receipt_ref"])
    assert stub.calls == []


async def test_an_oversized_stream_is_cut_off_at_the_limit(tmp_path: Path) -> None:
    """A streamed upload is refused once it passes the limit, without a Content-Length to rely on."""
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)
    pulled = 0

    async def chunks():
        """Yield 1 KiB chunks and count how many the server pulls."""
        nonlocal pulled
        for _ in range(10_000):
            pulled += 1
            yield b"a" * 1024

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        response = await client.post("/grants/verify", content=chunks(), headers=AUTH)
    assert_public_error(response, 400, "deny.malformed_grant")
    assert pulled < 200 and stub.calls == [] and audit.count() == 1


async def test_an_oversized_chunk_is_rejected_before_it_is_buffered(tmp_path: Path) -> None:
    """One streamed chunk larger than the body cap receives the usual malformed denial."""
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)

    async def chunks():
        yield b"a" * (_BODY_LIMIT + 1)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        response = await client.post("/grants/verify", content=chunks(), headers=AUTH)
    assert_public_error(response, 400, "deny.malformed_grant")
    assert stub.calls == [] and audit.count() == 1


async def test_missing_principal_is_denied_as_unauthorized_caller_and_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With authentication disabled no principal exists, so the caller is denied and recorded."""
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)
    error = assert_public_error(await post(app, {"grant": "{}"}), 401, "deny.unauthorized_caller")
    assert stub.calls == []
    assert audit.has(error["receipt_ref"])


async def test_unauthorized_failure_audits_are_bounded_per_window(tmp_path: Path) -> None:
    """Repeated bad bearers retain their public denials without unbounded durable audit growth."""
    app, audit = serving_app(StubVerifier(result=verified(), revocation=observation()), tmp_path)
    for _ in range(AUTH_FAILURE_AUDIT_LIMIT + 1):
        error = assert_public_error(
            await post(app, {"grant": "{}"}, headers={}), 401, "deny.unauthorized_caller"
        )
    assert "receipt_ref" not in error
    assert audit.count() == AUTH_FAILURE_AUDIT_LIMIT


async def test_route_denial_audit_runs_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The asynchronous route delegates its synchronous durable audit write to a worker."""
    app, audit = serving_app(StubVerifier(error=AdjustmentGrantRefused("grant.revoked")), tmp_path)  # type: ignore[arg-type]
    thread_ids: list[int] = []
    record = audit.record

    def recording_audit(*args, **kwargs):
        thread_ids.append(threading.get_ident())
        return record(*args, **kwargs)

    monkeypatch.setattr(audit, "record", recording_audit)
    assert_public_error(await post(app, {"grant": "{}"}), 403, "deny.revoked_grant")
    assert thread_ids and thread_ids != [threading.get_ident()]


# ------------------------------------------------------------- verification


async def test_a_valid_grant_is_verified_and_only_a_status_is_returned(tmp_path: Path) -> None:
    """Success carries status and correlation id; no grant facts."""
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)
    response = await post(app, {"grant": '{"g": 1}'})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "correlation_id"} and body["status"] == "verified"
    assert stub.calls == ["verify", "revocation"]
    assert audit.count() == 0
    assert SECRET_GRANT_ID not in response.text


@pytest.mark.parametrize(
    ("internal", "public", "status"),
    [
        ("revocation.stale", "deny.revocation_stale", 503),
        ("grant.key_unknown", "deny.unknown_key", 403),
        ("grant.malformed", "deny.malformed_grant", 400),
        ("grant.schema_unsupported", "deny.malformed_grant", 400),
        ("grant.signature_invalid", "deny.malformed_grant", 400),
        ("grant.expired", "deny.malformed_grant", 400),
        ("grant.future_dated", "deny.malformed_grant", 400),
        ("grant.revoked", "deny.revoked_grant", 403),
        ("verifier.unavailable", "deny.verifier_unavailable", 503),
    ],
)
async def test_every_verifier_refusal_maps_to_its_public_code_and_is_audited(
    tmp_path: Path, internal: str, public: str, status: int
) -> None:
    """Each phylax reason maps to the closed public code with a durable receipt reference."""
    app, audit = serving_app(StubVerifier(error=AdjustmentGrantRefused(internal)), tmp_path)  # type: ignore[arg-type]
    error = assert_public_error(await post(app, {"grant": "{}"}), status, public)
    assert error["receipt_ref"] == receipt_ref_for(error["correlation_id"], public)
    assert audit.has(error["receipt_ref"])


async def test_an_unexpected_verifier_error_denies_as_unavailable(tmp_path: Path) -> None:
    """A crashing verifier is a deny with no internals."""
    app, _ = serving_app(StubVerifier(error=RuntimeError(f"boom {SECRET_KEY}")), tmp_path)
    assert_public_error(await post(app, {"grant": "{}"}), 503, "deny.verifier_unavailable")


async def test_a_revoked_observation_is_denied(tmp_path: Path) -> None:
    """The route checks revocation after verification."""
    stub = StubVerifier(result=verified(), revocation=observation(revoked=True))
    app, _ = serving_app(stub, tmp_path)
    assert_public_error(await post(app, {"grant": "{}"}), 403, "deny.revoked_grant")


@pytest.mark.parametrize("age", [61, 3600, -61])
async def test_revocation_older_than_sixty_seconds_is_actually_raised_as_stale(
    tmp_path: Path, age: int
) -> None:
    """Freshness is enforced here too: an observation outside 60 seconds is stale."""
    stub = StubVerifier(result=verified(), revocation=observation(observed_at=NOW - timedelta(seconds=age)))
    app, _ = serving_app(stub, tmp_path)
    assert_public_error(await post(app, {"grant": "{}"}), 503, "deny.revocation_stale")


async def test_revocation_exactly_sixty_seconds_old_is_still_fresh(tmp_path: Path) -> None:
    """The boundary is strict: older than 60 seconds is stale, 60 is not."""
    stub = StubVerifier(result=verified(), revocation=observation(observed_at=NOW - timedelta(seconds=60)))
    app, _ = serving_app(stub, tmp_path)
    assert (await post(app, {"grant": "{}"})).status_code == 200


async def test_an_observation_for_a_different_grant_is_denied(tmp_path: Path) -> None:
    """A revocation answer about another grant cannot clear this one."""
    stub = StubVerifier(result=verified(), revocation=observation("other-grant"))
    app, _ = serving_app(stub, tmp_path)
    assert_public_error(await post(app, {"grant": "{}"}), 503, "deny.verifier_unavailable")


async def test_an_already_expired_verified_grant_is_denied(tmp_path: Path) -> None:
    """The route refuses a grant whose expiry has passed even if the verifier returned it."""
    old = verified(issued_at=NOW - timedelta(hours=2), expires_at=NOW - timedelta(hours=1))
    app, _ = serving_app(StubVerifier(result=old, revocation=observation()), tmp_path)
    assert_public_error(await post(app, {"grant": "{}"}), 400, "deny.malformed_grant")


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'{"grant": 5}', b'{"grant": "x"}', b'{"grant": "{}", "extra": 1}',
     b"{}", b"\xff\xfe", b'{"grant": "' + b"a" * 70_000 + b'"}'],
    ids=["text", "array", "number", "short", "extra", "empty", "bad-utf8", "oversize"],
)
async def test_malformed_requests_are_denied_without_echoing_input(tmp_path: Path, raw: bytes) -> None:
    """Malformed bodies get the public code, never a framework validation echo."""
    stub = StubVerifier(result=verified(), revocation=observation())
    app, audit = serving_app(stub, tmp_path)
    response = await post(app, None, raw=raw)
    assert_public_error(response, 400, "deny.malformed_grant")
    assert stub.calls == []
    assert audit.count() == 1


# ----------------------------------------------------------------- audit log


def test_audit_log_is_append_only_and_free_of_identifiers(tmp_path: Path) -> None:
    """The table has exactly three columns, refuses UPDATE and DELETE, and rejects odd codes."""
    log = DenialAuditLog(tmp_path / "a" / "log.sqlite")
    ref = log.record("cid-1", "deny.unknown_key", NOW)
    assert log.has(ref) and not log.has("0" * 32)
    conn = sqlite3.connect(tmp_path / "a" / "log.sqlite")
    assert [r[1] for r in conn.execute("PRAGMA table_info(denial_audit)")] == [
        "correlation_id", "code", "recorded_at",
    ]
    for statement in ("UPDATE denial_audit SET code = 'x'", "DELETE FROM denial_audit"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(statement)
    conn.close()
    with pytest.raises(ValueError):
        log.record("cid-2", "serving.not_ready")
    with pytest.raises(ValueError):
        log.record(" ", "deny.unknown_key")
    assert set(DENY_CODES) >= {"deny.unknown_key"}
    log.close()


def test_audit_records_survive_reopening(tmp_path: Path) -> None:
    """A recorded denial is durable across a restart."""
    path = tmp_path / "a" / "log.sqlite"
    first = DenialAuditLog(path)
    ref = first.record("cid-1", "deny.revoked_grant", NOW)
    first.close()
    second = DenialAuditLog(path)
    assert second.has(ref) and second.count() == 1
    second.close()


async def test_a_failing_audit_log_still_denies_without_a_receipt_ref(tmp_path: Path) -> None:
    """Audit trouble never turns a denial into an allow; the response just has no receipt_ref."""
    app, audit = serving_app(StubVerifier(error=AdjustmentGrantRefused("grant.revoked")), tmp_path)  # type: ignore[arg-type]
    audit.close()
    error = assert_public_error(await post(app, {"grant": "{}"}), 403, "deny.revoked_grant")
    assert "receipt_ref" not in error


# --------------------------------------------------------- never spends or mutates


async def test_verification_never_spends_the_grant_or_touches_the_ledger(tmp_path: Path) -> None:
    """Verifying twice leaves the hold unknown; the grant is still spendable exactly once."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    try:
        epoch, hold = unknown_hold(ledger, units=3)
        g = grant(ledger, hold, epoch, principal=AUTHENTICATED_CONTROL_PLANE_PRINCIPAL)
        stub = StubVerifier(result=g)  # fresh real-clock observation
        audit = DenialAuditLog(tmp_path / "audit" / "denials.sqlite")
        app = create_app(
            adjustment_consumer=AdjustmentGrantConsumer(ledger, stub),
            capability_config=CapabilityConfig(
                record=signed(serving=True), expected_binary_digest=BIN,
                expected_config_digest=CFG, signature_verifier=Signer(),
            ),
            grant_verifier=stub, denial_audit=audit,
        )
        before = ledger.hold_state("run-1", "node::a::0")
        for _ in range(2):
            assert (await post(app, {"grant": wire_for(g).decode()})).status_code == 200
        assert ledger.hold_state("run-1", "node::a::0") == before == "unknown"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
            spend = await client.post("/adjustments", json={"grant": wire_for(g).decode()}, headers=AUTH)
        assert spend.status_code == 200
        assert ledger.hold_state("run-1", "node::a::0") == "released"
    finally:
        ledger.close()


def test_the_verify_route_module_holds_no_ledger_or_issuer_reference() -> None:
    """Structural guard: the route module imports no ledger, store, issuer or signing code."""
    source = Path(__import__("orama.api.verify_route", fromlist=["x"]).__file__).read_text(encoding="utf-8")
    for forbidden in ("StepLedger", "SqliteAttemptStore", "consume(", "sign", "subprocess", "os.system"):
        assert forbidden not in source


def test_audit_receipt_reference_is_opaque() -> None:
    """The reference reveals neither the code nor the correlation id."""
    ref = receipt_ref_for("cid-1", "deny.unknown_key")
    assert "cid-1" not in ref and "unknown" not in ref and len(ref) == 32
    assert json.dumps({"r": ref})
