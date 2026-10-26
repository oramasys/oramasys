"""Authenticated inert endpoint: dark unless effects hold, final boundary only, contract errors."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.api.capabilities import CapabilityConfig, StartupRefused
from orama.api.public_errors import public_effect_denial_code
from orama.api.server import create_app
from orama.graph.effect_grant_composition import FinalBoundarySender
from orama.graph.effect_receipts import attempt_ref_for
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


def public_error(response, status: int, code: str) -> dict:
    """Assert the contract error body exactly, with no grant id or internal reason leaking."""
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"} and set(body["error"]) == {"code", "correlation_id"}
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
    public_error(await post(denied, {"attempt_id": ATTEMPT}), 403, "deny.missing_capability_record")
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


async def test_a_failed_bearer_on_the_live_route_gets_the_public_denial(bound: Bound) -> None:
    """With the route live, a bad bearer answers 401 with the contract body."""
    app = create_app(
        capability_config=effects_config(),
        inert_sender=FinalBoundarySender(bound.composer, sealed(bound)),
    )
    response = await post(app, {"attempt_id": ATTEMPT}, headers={"Authorization": "Bearer wrong-token-0000000000000"})
    public_error(response, 401, "deny.unauthorized_caller")
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
        ("envelope_target", "deny.malformed_grant"),
        ("grant.revoked", "deny.revoked_grant"),
        ("send_authority_revoked", "deny.revoked_grant"),
        ("effects_denied", "deny.missing_capability_record"),
        ("grant.key_unknown", "deny.unknown_key"),
        ("revocation.stale", "deny.revocation_stale"),
        ("approval_verifier_unavailable", "deny.verifier_unavailable"),
        ("outcome_unknown", "deny.verifier_unavailable"),
        ("something-new", "deny.verifier_unavailable"),
    ],
)
def test_effect_reasons_map_to_the_closed_public_vocabulary(reason: str, code: str) -> None:
    """Every internal send-path reason has one public code; unknown reasons deny as unavailable."""
    assert public_effect_denial_code(reason) == code
