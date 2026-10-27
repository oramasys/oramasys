"""Four independent readiness facts; /readyz is a stable 503 unless the serving facts hold."""
from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.capabilities import CapabilityConfig, StartupRefused, read_capability_record
from orama.api.public_errors import PUBLIC_CODES, error_body, public_denial_code
from orama.api.readiness import ReadinessProbes, collect_facts
from orama.api.server import create_app
from tests.test_capabilities import BIN, CFG, Signer, make_record, signed


def serving_config(**bits: bool) -> CapabilityConfig:
    """Return a config whose signed record turns the named bits on through an accepting verifier."""
    return CapabilityConfig(
        record=signed(**bits), expected_binary_digest=BIN, expected_config_digest=CFG,
        signature_verifier=Signer(),
    )


async def get(app, path: str):
    """GET ``path`` from an ASGI app."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path)


def facts_for(view, *, verifier: bool, probes: ReadinessProbes | None = None):
    """Collect facts for a view."""
    return collect_facts(view, verify_authority_present=verifier, probes=probes or ReadinessProbes())


def serving_view():
    """Return a view with only the serving bit effective."""
    return read_capability_record(
        signed(serving=True), expected_binary_digest=BIN, expected_config_digest=CFG,
        signature_verifier=Signer(),
    )


# ------------------------------------------------------------------ pure facts


def test_every_fact_defaults_to_false() -> None:
    """With nothing wired no fact is true."""
    facts = facts_for(read_capability_record(None), verifier=False)
    assert facts.as_public() == {
        "verifier_ready": False, "issuer_ready": False,
        "serving_enabled": False, "autonomous_policy_ready": False,
    }
    assert not facts.serving_facts_hold()


def test_facts_are_not_inferred_from_one_another() -> None:
    """Each fact follows only its own source, in every combination."""
    none = read_capability_record(make_record())
    assert facts_for(serving_view(), verifier=False).as_public() == {
        "verifier_ready": False, "issuer_ready": False, "serving_enabled": True,
        "autonomous_policy_ready": False,
    }
    assert facts_for(none, verifier=True).as_public()["serving_enabled"] is False
    only_issuer = facts_for(none, verifier=False, probes=ReadinessProbes(issuer=lambda: True))
    assert only_issuer.as_public() == {
        "verifier_ready": False, "issuer_ready": True, "serving_enabled": False,
        "autonomous_policy_ready": False,
    }
    only_policy = facts_for(
        none, verifier=False, probes=ReadinessProbes(autonomous_policy=lambda: True)
    )
    assert only_policy.as_public()["autonomous_policy_ready"] is True
    assert only_policy.as_public()["issuer_ready"] is False


def test_issuer_and_policy_readiness_never_satisfy_the_serving_facts() -> None:
    """Issuer-ready and autonomous-policy-ready cannot stand in for verifier or serving."""
    view = read_capability_record(make_record())
    probes = ReadinessProbes(verifier=lambda: True, issuer=lambda: True, autonomous_policy=lambda: True)
    facts = facts_for(view, verifier=False, probes=probes)
    assert facts.issuer_ready and facts.autonomous_policy_ready
    assert not facts.verifier_ready and not facts.serving_facts_hold()


@pytest.mark.parametrize("answer", [False, None, 1, "yes", RuntimeError("down")], ids=[
    "false", "none", "int", "text", "raises",
])
def test_a_probe_that_fails_or_is_not_exactly_true_is_false(answer) -> None:
    """Raising or truthy-but-not-True probe answers are not-ready."""
    def probe():
        """Raise or return the scripted answer."""
        if isinstance(answer, Exception):
            raise answer
        return answer

    view = read_capability_record(make_record())
    facts = facts_for(view, verifier=True, probes=ReadinessProbes(
        verifier=probe, issuer=probe, autonomous_policy=probe,
    ))
    assert facts.as_public() == {
        "verifier_ready": False, "issuer_ready": False,
        "serving_enabled": False, "autonomous_policy_ready": False,
    }


# ------------------------------------------------------------------------- /readyz


async def test_readyz_is_a_stable_503_with_the_contract_body_by_default() -> None:
    """The default process is live but not ready; body is exactly code plus correlation id."""
    app = create_app()
    assert (await get(app, "/healthz")).status_code == 200
    first, second = await get(app, "/readyz"), await get(app, "/readyz")
    for response in (first, second):
        assert response.status_code == 503
        body = response.json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "correlation_id"}
        assert body["error"]["code"] == "serving.not_ready"
    assert first.json()["error"]["correlation_id"] != second.json()["error"]["correlation_id"]


async def test_readyz_503_never_leaks_facts_ids_or_paths() -> None:
    """The refusal body carries nothing beyond the stable code."""
    text = (await get(create_app(), "/readyz")).text
    for forbidden in ("verifier_ready", "grant", "capabilit", "path", "rec-"):
        assert forbidden not in text


def test_serving_without_a_verifier_cannot_even_start() -> None:
    """Serving true with no verify-only authority is refused at startup, not left half-ready."""
    with pytest.raises(StartupRefused):
        create_app(capability_config=serving_config(serving=True))


async def test_readyz_503_when_verifier_present_but_serving_not_enabled() -> None:
    """A verifier alone is not serving."""
    app = create_app(grant_verifier=object())  # type: ignore[arg-type]
    assert (await get(app, "/readyz")).status_code == 503


async def test_readyz_503_when_serving_enabled_but_verifier_probe_fails() -> None:
    """Serving enabled does not make a failing verifier ready."""
    app = create_app(
        capability_config=serving_config(serving=True), grant_verifier=object(),  # type: ignore[arg-type]
        readiness_probes=ReadinessProbes(verifier=lambda: False),
    )
    assert (await get(app, "/readyz")).status_code == 503


async def test_readyz_503_when_the_composition_is_unavailable() -> None:
    """An unavailable grant composition makes the verifier not ready even if one is passed."""
    app = create_app(
        capability_config=serving_config(serving=True), grant_verifier=object(),  # type: ignore[arg-type]
        grant_capability="unavailable",
    )
    assert (await get(app, "/readyz")).status_code == 503


async def test_readyz_200_only_when_both_serving_facts_hold_and_effects_stay_denied() -> None:
    """Ready reports verification-only scope and all four facts; effects is never implied."""
    app = create_app(
        capability_config=serving_config(serving=True), grant_verifier=object(),  # type: ignore[arg-type]
    )
    response = await get(app, "/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "verification_only"
    assert body["facts"] == {
        "verifier_ready": True, "issuer_ready": False,
        "serving_enabled": True, "autonomous_policy_ready": False,
    }
    assert body["capabilities"]["bits"]["effects"] == {"effective": False, "reason": None}


async def test_readyz_does_not_become_ready_from_issuer_or_policy_facts() -> None:
    """Issuer and autonomous-policy readiness cannot make the serving surface ready."""
    app = create_app(readiness_probes=ReadinessProbes(
        verifier=lambda: True, issuer=lambda: True, autonomous_policy=lambda: True,
    ))
    assert (await get(app, "/readyz")).status_code == 503


async def test_health_lists_the_four_facts() -> None:
    """The data-free health payload shows each independent fact."""
    body = (await get(create_app(), "/health")).json()
    assert set(body["facts"]) == {
        "verifier_ready", "issuer_ready", "serving_enabled", "autonomous_policy_ready",
    }
    assert not any(body["facts"].values())


# ------------------------------------------------------------------- public errors


def test_public_vocabulary_is_closed_and_maps_internal_reasons() -> None:
    """Internal verifier reasons map to the seven deny codes; an unknown reason denies."""
    expected = {
        "revocation.stale": "deny.revocation_stale",
        "grant.key_unknown": "deny.unknown_key",
        "grant.malformed": "deny.malformed_grant",
        "grant.schema_unsupported": "deny.malformed_grant",
        "grant.signature_invalid": "deny.malformed_grant",
        "grant.expired": "deny.malformed_grant",
        "grant.future_dated": "deny.malformed_grant",
        "grant.revoked": "deny.revoked_grant",
        "verifier.unavailable": "deny.verifier_unavailable",
        "something.unmapped": "deny.verifier_unavailable",
    }
    assert {k: public_denial_code(k) for k in expected} == expected
    assert {
        "serving.not_ready", "serving.disabled", "serving.route_not_exposed",
        "deny.revocation_stale", "deny.unknown_key", "deny.malformed_grant",
        "deny.revoked_grant", "deny.missing_capability_record",
        "deny.unauthorized_caller", "deny.verifier_unavailable",
    } == PUBLIC_CODES
    with pytest.raises(ValueError):
        error_body("grant.revoked", "c")
    assert json.dumps(error_body("serving.not_ready", "c", "r")) == (
        '{"error": {"code": "serving.not_ready", "correlation_id": "c", "receipt_ref": "r"}}'
    )
