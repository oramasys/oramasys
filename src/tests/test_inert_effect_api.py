"""Authenticated inert endpoint: dark unless effects hold, final boundary only, contract errors."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL, install_authz
from orama.api.capabilities import CapabilityConfig, StartupRefused
from orama.api.inert_effect_route import install_inert_effect_route
from orama.api.public_errors import public_effect_denial_code
from orama.api.server import create_app
from orama.graph.effect_grant_composition import FinalBoundarySender
from orama.graph.effect_receipts import attempt_ref_for
from orama.graph.effect_reconciliation import startup_reconciliation_report
from orama.graph.inert_effect_driver import InertEffectDriver
from tests.test_capabilities import BIN, CFG, Signer, make_record, signed
from tests.test_dispatch_attempts import ATTEMPT, GRANT, NOW
from tests.test_effect_grant_composition import Bound, bound_harness, sealed, untouched
from tests.test_final_boundary import Approvals

TOKEN = "test-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CALLER = AUTHENTICATED_CONTROL_PLANE_PRINCIPAL


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the shared bearer the control plane authenticates with."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


def effects_config() -> CapabilityConfig:
    """A record whose effects bit is effective under a test signature verifier (tests only)."""
    return CapabilityConfig(
        record=signed(effects=True), expected_binary_digest=BIN, expected_config_digest=CFG,
        signature_verifier=Signer(), permit_verifier=object(),
    )


@pytest.fixture
def bound(tmp_path: Path) -> Bound:
    """An attempt bound to the control-plane caller, authorized and approved."""
    b = bound_harness(tmp_path, principal=CALLER)
    yield b
    b.h.store.close()


async def post(app, body=None, headers=AUTH, *, raw: bytes | None = None):
    """POST to the inert route."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        if raw is not None:
            return await client.post("/effects/inert", content=raw, headers=headers)
        return await client.post("/effects/inert", json=body, headers=headers)


def public_error(response, status: int, code: str, *, receipt_ref: str | None = None) -> dict:
    """Assert the contract error body exactly, with no grant id or internal reason leaking.

    ``receipt_ref`` (when given) must be nested inside the ``error`` object and equal this value;
    it is never a sibling of ``error``.
    """
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    expected_keys = {"code", "correlation_id"} | ({"receipt_ref"} if receipt_ref is not None else set())
    assert set(body["error"]) == expected_keys
    if receipt_ref is not None:
        assert body["error"]["receipt_ref"] == receipt_ref
    assert body["error"]["code"] == code
    for secret in (GRANT, ATTEMPT, "effect.", "grant.", "effects_denied", "principal_mismatch"):
        assert secret not in response.text
    return body["error"]


async def test_inert_send_requires_authenticated_context(bound: Bound) -> None:
    """Only a token-authenticated principal reaches the canonical sender (now via the final boundary).

    Previously this used a bare recording callable and an unconditional route; the route now needs
    an effective effects bit and accepts only the final-boundary sender, so the same assertions are
    made against the durable outbox: nothing is dispatched without the bearer, and with it the
    attempt id and the authenticated principal reach the sealed send.
    """
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    response = await post(app, {"attempt_id": ATTEMPT}, headers={})
    assert response.status_code in (401, 403)
    untouched(bound)
    response = await post(app, {"attempt_id": ATTEMPT})
    assert response.status_code == 200
    receipt = response.json()["receipt"]
    assert set(receipt) == {"attempt_ref", "outcome", "receipt_digest", "recorded_at"}
    assert receipt["attempt_ref"] == attempt_ref_for(ATTEMPT) and receipt["outcome"] == "confirmed"
    assert bound.h.store.outbox_row(ATTEMPT)["send_started"] == 1
    assert GRANT not in response.text and ATTEMPT not in response.text


async def test_inert_sender_is_disabled_by_default() -> None:
    """Installing composition code grants no sending capability.

    Stricter than before: the unwired route used to answer 503 effects_unavailable; it is now dark
    with the contract's 404 serving.route_not_exposed.
    """
    response = await post(create_app(), {"attempt_id": "a"})
    public_error(response, 404, "serving.route_not_exposed")


async def test_a_wired_sender_stays_dark_without_an_effective_effects_bit(bound: Bound) -> None:
    """A sender without effects (no record, an all-false record) is never called."""
    sender = FinalBoundarySender(bound.composer, sealed(bound))
    configs = [
        None,
        CapabilityConfig(record=make_record(), expected_binary_digest=BIN, expected_config_digest=CFG),
    ]
    for config in configs:
        app = create_app(capability_config=config, inert_sender=sender)
        public_error(await post(app, {"attempt_id": ATTEMPT}), 404, "serving.route_not_exposed")
    assert bound.verifier.calls == 1  # only the create_attempt verification
    untouched(bound)


class StartupOnlyEffects:
    """Capability view double: ``effects`` is effective when the route is installed, then denied."""

    def __init__(self) -> None:
        """Start with no question asked."""
        self.asked = 0

    def is_effective(self, bit: str) -> bool:
        """Grant ``effects`` to the first (install-time) question only; deny every later one."""
        self.asked += 1
        return bit == "effects" and self.asked == 1


class AlwaysEffects:
    """Capability view double whose ``effects`` bit is effective on every question."""

    def is_effective(self, bit: str) -> bool:
        """Grant ``effects`` and nothing else."""
        return bit == "effects"


def bare_app(view, sender: FinalBoundarySender) -> FastAPI:
    """Build an app with only the bearer middleware and the inert route over ``view``."""
    app = FastAPI()
    install_authz(app)
    install_inert_effect_route(app, capabilities=view, sender=sender)  # type: ignore[arg-type]
    return app


async def test_the_route_asks_the_effects_capability_again_for_every_request(bound: Bound) -> None:
    """The second route-level gate, isolated: effects held at startup but not for this request.

    The sender is wired and was live at install, so only the per-request capability question
    stands between the request and a send: the route answers 404 and the sender is never called.
    The same app shape with a view that keeps answering yes does send (control).
    """
    view = StartupOnlyEffects()
    sender = FinalBoundarySender(bound.composer, sealed(bound))
    public_error(await post(bare_app(view, sender), {"attempt_id": ATTEMPT}), 404, "serving.route_not_exposed")
    assert view.asked >= 2
    assert bound.verifier.calls == 1  # only the create_attempt verification
    untouched(bound)
    response = await post(bare_app(AlwaysEffects(), sender), {"attempt_id": ATTEMPT})
    assert response.status_code == 200 and response.json()["receipt"]["outcome"] == "confirmed"


def test_an_unsigned_effects_record_refuses_startup(bound: Bound) -> None:
    """A true effects bit without a verified operator signature refuses before any route exists."""
    with pytest.raises(StartupRefused, match="capability.unsigned_enablement"):
        create_app(
            capability_config=CapabilityConfig(
                record=make_record(effects=True), expected_binary_digest=BIN,
                expected_config_digest=CFG, permit_verifier=object(),
            ),
            inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
        )
    untouched(bound)


async def test_effects_without_a_sender_stay_dark() -> None:
    """An effective effects bit alone exposes nothing."""
    app = create_app(capability_config=effects_config())
    public_error(await post(app, {"attempt_id": "a"}), 404, "serving.route_not_exposed")


def test_only_the_final_boundary_sender_is_accepted(bound: Bound) -> None:
    """A bare callable (for example around the plain inert driver) cannot be wired to HTTP."""
    plain = InertEffectDriver(bound.h.store, clock=lambda: NOW)
    with pytest.raises(TypeError):
        create_app(capability_config=effects_config(), inert_sender=lambda a, p: plain.send(a))  # type: ignore[arg-type]
    untouched(bound)


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[]", b'{"attempt_id": ""}', b'{"attempt_id": 5}',
     b'{"attempt_id": "a", "grant": "x"}', b'{"attempt": "a"}', b"\xff\xfe",
     json.dumps({"attempt_id": "a" * 1025}).encode(), b'{"attempt_id": "' + b"a" * 5000 + b'"}'],
    ids=["empty", "text", "array", "blank", "int", "extra", "renamed", "utf8", "long", "oversize"],
)
async def test_a_malformed_request_is_the_public_malformed_denial(bound: Bound, raw: bytes) -> None:
    """Anything but ``{"attempt_id": "<1..1024 chars>"}`` is 400 deny.malformed_grant, unsent."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    headers = {**AUTH, "Content-Type": "application/json"}
    public_error(await post(app, raw=raw, headers=headers), 400, "deny.malformed_grant")
    untouched(bound)


async def test_a_caller_that_is_not_the_bound_principal_is_unauthorized(tmp_path: Path) -> None:
    """The composer's principal mismatch maps to 401 deny.unauthorized_caller; nothing is sent."""
    b = bound_harness(tmp_path, principal="principal-1")
    try:
        app = create_app(
            capability_config=effects_config(),
            inert_sender=FinalBoundarySender(b.composer, sealed(b)),
        )
        public_error(await post(app, {"attempt_id": ATTEMPT}), 401, "deny.unauthorized_caller")
        untouched(b)
    finally:
        b.h.store.close()


async def test_final_boundary_refusals_map_to_public_codes(bound: Bound) -> None:
    """Effects denied at the boundary and a revoked grant surface only as public deny codes."""
    denied = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, effects=None)),
    )
    public_error(
        await post(denied, {"attempt_id": ATTEMPT}), 403, "deny.missing_capability_record",
        receipt_ref=attempt_ref_for(ATTEMPT),
    )
    untouched(bound)


async def test_a_revoked_signed_grant_is_the_public_revocation_denial(bound: Bound) -> None:
    """A grant revoked during the final boundary is refused in the send transaction: 403 revoked."""

    class Revoking(Approvals):
        """Approval verifier during which the signed grant is revoked."""

        def verify(self, binding):
            """Revoke the signed grant, then approve."""
            bound.verifier.revoked = True
            return super().verify(binding)

    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, approvals=Revoking())),
    )
    public_error(await post(app, {"attempt_id": ATTEMPT}), 403, "deny.revoked_grant")
    untouched(bound)
    assert bound.h.store.approval_state(ATTEMPT) == "granted"


class FailingSimulation:
    """Inert simulation double that fails after the send marker committed (a timeout, say)."""

    def __init__(self) -> None:
        """Start with no calls."""
        self.calls = 0

    def __call__(self, envelope) -> str:
        """Count the call and fail as a slow provider would."""
        self.calls += 1
        raise TimeoutError("simulated provider timeout")


def in_doubt_error(response) -> dict:
    """Assert the in-doubt answer: 503 deny.verifier_unavailable plus the attempt's receipt_ref."""
    assert response.status_code == 503
    body = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "correlation_id", "receipt_ref"}
    assert body["error"]["code"] == "deny.verifier_unavailable"
    assert body["error"]["receipt_ref"] == attempt_ref_for(ATTEMPT)
    for secret in (GRANT, ATTEMPT, "outcome_unknown", "outcome_unrecorded", "Timeout", "sqlite"):
        assert secret not in response.text
    return body["error"]


async def test_an_in_doubt_send_reports_the_durable_attempt_reference(bound: Bound) -> None:
    """A failure after the send marker keeps 503 and the contract code, plus ``receipt_ref``.

    The reference is the opaque attempt reference the startup reconciliation report lists, so the
    caller can tell this in-doubt dispatch from a pre-dispatch deny (which never carries one). The
    outcome stays unknown, and a retry dispatches nothing.
    """
    sim = FailingSimulation()
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, sim=sim)),
    )
    error = in_doubt_error(await post(app, {"attempt_id": ATTEMPT}))
    row = bound.h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"]) == (1, "unknown") and sim.calls == 1
    assert error["receipt_ref"] in startup_reconciliation_report(bound.h.store).in_doubt
    retry = await post(app, {"attempt_id": ATTEMPT})
    assert retry.status_code == 400 and retry.json()["error"]["code"] == "deny.malformed_grant"
    assert sim.calls == 1 and bound.h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"


async def test_an_unrecorded_settlement_is_reported_in_doubt_too(
    bound: Bound, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the outcome cannot be written after the marker, the answer is the in-doubt one as well."""

    def broken(*args, **kwargs):
        """Fail the settlement write as a damaged disk would."""
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(bound.h.store, "settle_with_receipt", broken)
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    in_doubt_error(await post(app, {"attempt_id": ATTEMPT}))
    row = bound.h.store.outbox_row(ATTEMPT)
    assert (row["send_started"], row["outcome"]) == (1, "unknown")
    assert bound.h.store.receipt(ATTEMPT) is None


async def test_a_pre_dispatch_deny_without_a_record_carries_no_receipt_ref(bound: Bound) -> None:
    """A deny that leaves no durable record (here a malformed request) has no ``receipt_ref``."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    public_error(await post(app, {"attempt_id": ""}), 400, "deny.malformed_grant")
    assert bound.h.store.terminal_refusal(ATTEMPT) is None
    untouched(bound)


async def test_a_recorded_refusal_carries_its_stored_code_and_nested_receipt_ref(bound: Bound) -> None:
    """A refusal that wrote the terminal record answers with its public code and the record's ref."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, approvals=Approvals(False))),
    )
    error = public_error(
        await post(app, {"attempt_id": ATTEMPT}), 400, "deny.malformed_grant",
        receipt_ref=attempt_ref_for(ATTEMPT),
    )
    stored = bound.h.store.terminal_refusal(ATTEMPT)
    assert stored is not None and error["receipt_ref"] == stored.receipt_ref
    untouched(bound)


async def test_a_failed_bearer_on_the_live_route_gets_the_public_denial(bound: Bound) -> None:
    """With the route live, a bad bearer answers 401 with the contract body."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    response = await post(app, {"attempt_id": ATTEMPT}, headers={"Authorization": "Bearer wrong-token-0000000000000"})
    public_error(response, 401, "deny.unauthorized_caller")
    untouched(bound)


def live_app(bound: Bound) -> FastAPI:
    """Build the full app with the route exposed (effects effective under a test signature)."""
    return create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )


async def test_a_missing_bearer_on_the_live_route_gets_the_public_denial(bound: Bound) -> None:
    """With the route exposed, no bearer at all also answers 401 with the contract body."""
    response = await post(live_app(bound), {"attempt_id": ATTEMPT}, headers={})
    public_error(response, 401, "deny.unauthorized_caller")
    untouched(bound)


async def test_the_dark_route_keeps_the_plain_401_and_the_404(bound: Bound) -> None:
    """Dark at startup, or dark for this request: the auth-failure hook stays silent.

    An unauthenticated caller gets the middleware's plain 401 (unchanged) and an authenticated
    caller the contract's 404 ``serving.route_not_exposed``; neither reaches the sender.
    """
    sender = FinalBoundarySender(bound.composer, sealed(bound))
    for app in (create_app(inert_sender=sender), bare_app(StartupOnlyEffects(), sender)):
        for headers in ({}, {"Authorization": "Bearer wrong-token-0000000000000"}):
            response = await post(app, {"attempt_id": ATTEMPT}, headers=headers)
            assert response.status_code == 401
            assert response.json() == {"detail": "Unauthorized"}
        public_error(await post(app, {"attempt_id": ATTEMPT}), 404, "serving.route_not_exposed")
    untouched(bound)


async def test_an_auth_failure_hook_can_never_turn_a_denial_into_an_allow(bound: Bound) -> None:
    """The middleware takes only a 401 from a route's hook; anything else is its plain 401."""

    def allow(request):
        """A misbehaving hook that tries to answer a failed bearer with a success."""
        return JSONResponse({"receipt": "forged"}, status_code=200)

    def broken(request):
        """A hook that fails outright."""
        raise RuntimeError("hook failure")

    for hook in (allow, broken):
        app = live_app(bound)
        app.state.auth_failure_handlers["/effects/inert"] = hook
        response = await post(app, {"attempt_id": ATTEMPT}, headers={})
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}
    untouched(bound)


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        ("effect.principal_mismatch", "deny.unauthorized_caller"),
        ("principal_mismatch", "deny.unauthorized_caller"),
        ("effect.binding_mismatch", "deny.malformed_grant"),
        ("grant.schema_unsupported", "deny.malformed_grant"),
        ("approval_missing", "deny.malformed_grant"),
        ("send_already_started", "deny.malformed_grant"),
        ("effect_grant_bound_send_required", "deny.malformed_grant"),
        ("effect_grant_recheck_required", "deny.verifier_unavailable"),
        ("send_authority_issuer_mismatch", "deny.verifier_unavailable"),
        ("envelope_target", "deny.malformed_grant"),
        ("grant.revoked", "deny.revoked_grant"),
        ("send_authority_revoked", "deny.revoked_grant"),
        ("effects_denied", "deny.missing_capability_record"),
        ("grant.key_unknown", "deny.unknown_key"),
        ("revocation.stale", "deny.revocation_stale"),
        ("approval_verifier_unavailable", "deny.verifier_unavailable"),
        ("outcome_unknown", "deny.verifier_unavailable"),
        ("outcome_unrecorded", "deny.verifier_unavailable"),
        ("something-new", "deny.verifier_unavailable"),
    ],
)
def test_effect_reasons_map_to_the_closed_public_vocabulary(reason: str, code: str) -> None:
    """Every internal send-path reason has one public code; unknown reasons deny as unavailable."""
    assert public_effect_denial_code(reason) == code


async def test_a_replay_of_a_refused_attempt_answers_the_stored_code_and_receipt_ref(bound: Bound) -> None:
    """The refusal and every replay carry the same code and nested receipt_ref, with fresh correlation."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, approvals=Approvals(False))),
    )
    ref = attempt_ref_for(ATTEMPT)
    first = public_error(await post(app, {"attempt_id": ATTEMPT}), 400, "deny.malformed_grant", receipt_ref=ref)
    # A replay with a verifier that would now approve still performs no new authorization or dispatch.
    sim = FailingSimulation()
    replay_app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, sim=sim)),
    )
    response = await post(replay_app, {"attempt_id": ATTEMPT})
    again = public_error(response, 400, "deny.malformed_grant", receipt_ref=ref)
    assert again["correlation_id"] != first["correlation_id"]
    assert "receipt_ref" not in response.json()  # nested in ``error``, never a sibling
    assert sim.calls == 0
    untouched(bound)


async def test_a_replay_of_a_refusal_with_a_different_public_code_keeps_that_code(bound: Bound) -> None:
    """The stored code is replayed, not recomputed: an effects refusal stays 403 on replay."""
    denied = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, effects=None)),
    )
    ref = attempt_ref_for(ATTEMPT)
    for _ in range(2):
        public_error(
            await post(denied, {"attempt_id": ATTEMPT}), 403, "deny.missing_capability_record",
            receipt_ref=ref,
        )
    allowed = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    public_error(
        await post(allowed, {"attempt_id": ATTEMPT}), 403, "deny.missing_capability_record",
        receipt_ref=ref,
    )
    untouched(bound)


async def test_an_in_doubt_dispatch_is_503_with_a_nested_receipt_ref_and_never_a_refusal(bound: Bound) -> None:
    """After the send marker an unproven outcome is 503 deny.verifier_unavailable plus receipt_ref."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound, sim=FailingSimulation())),
    )
    response = await post(app, {"attempt_id": ATTEMPT})
    public_error(response, 503, "deny.verifier_unavailable", receipt_ref=attempt_ref_for(ATTEMPT))
    assert "receipt_ref" not in response.json()
    assert bound.h.store.terminal_refusal(ATTEMPT) is None
    assert bound.h.store.outbox_row(ATTEMPT)["outcome"] == "unknown"
