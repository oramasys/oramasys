"""The adjustment route: the only way a grant is spent, inert unless wired."""
from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import AUTHENTICATED_CONTROL_PLANE_PRINCIPAL
from orama.api.server import create_app
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import (
    VERIFICATION_REFUSAL_CODES,
    AdjustmentGrantConsumer,
    AdjustmentGrantRefused,
)
from tests.test_adjustment_grant_consumer import (
    StubVerifier,
    grant,
    unknown_hold,
    wire_for,
)

TOKEN = "test-control-plane-token-32b"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
OPERATOR = AUTHENTICATED_CONTROL_PLANE_PRINCIPAL


@pytest.fixture(autouse=True)
def configured_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the shared bearer capability the route authenticates with."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


@pytest.fixture
def ledger(tmp_path: Path) -> StepLedger:
    """Return a ledger with a fresh private store."""
    return StepLedger(tmp_path / "ledger.sqlite3")


async def post(app, body: dict, headers: dict | None = None):
    """POST ``body`` to the adjustment route."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        return await client.post("/adjustments", json=body, headers=headers or {})


def wired(ledger: StepLedger, verifier: StubVerifier):
    """Return an app whose consumer uses ``verifier`` against ``ledger``."""
    return create_app(adjustment_consumer=AdjustmentGrantConsumer(ledger, verifier))


async def test_an_unwired_deployment_refuses_every_adjustment() -> None:
    """Without an injected consumer the route is inert, not absent."""
    response = await post(create_app(), {"grant": "{}"}, AUTH)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "adjustments_unavailable"


async def test_the_route_requires_the_bearer_capability(ledger: StepLedger) -> None:
    """No bearer, no adjustment."""
    response = await post(wired(ledger, StubVerifier()), {"grant": "{}"})
    assert response.status_code == 401


async def test_insecure_dev_never_authenticates_an_adjustment(
    ledger: StepLedger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disabled auth leaves no principal, so spending a grant is refused."""
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    response = await post(wired(ledger, StubVerifier()), {"grant": "{}"})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "authentication_required"


async def test_a_verified_grant_is_spent_and_the_receipt_returned(ledger: StepLedger) -> None:
    """The caller's capability principal, the verifier and the ledger agree."""
    epoch, hold = unknown_hold(ledger, units=3)
    g = grant(ledger, hold, epoch, principal=OPERATOR, kind="release", units=3)

    response = await post(wired(ledger, StubVerifier(result=g)), {"grant": wire_for(g).decode()}, AUTH)

    assert response.status_code == 200
    body = response.json()
    assert body["grant_id"] == g.grant_id and body["balance_delta"] == 3
    assert body["verifier_id"] == "phylax.test"
    assert ledger.hold_state("run-1", "node::a::0") == "released"
    assert ledger.used("run-1") == 0


async def test_a_grant_for_another_principal_is_a_conflict(ledger: StepLedger) -> None:
    """Principal binding is enforced against the authenticated caller."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch, principal="someone-else")
    response = await post(wired(ledger, StubVerifier(result=g)), {"grant": wire_for(g).decode()}, AUTH)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "grant.principal_mismatch"
    assert ledger.hold_state("run-1", "node::a::0") == "unknown"


async def test_a_deny_all_consumer_is_retryable_unavailable(ledger: StepLedger) -> None:
    """The default verifier answers 503 so callers know to retry once wired."""
    response = await post(create_app(adjustment_consumer=AdjustmentGrantConsumer(ledger)),
                          {"grant": "{}"}, AUTH)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "verifier.unavailable"


@pytest.mark.parametrize("code", sorted(VERIFICATION_REFUSAL_CODES))
async def test_every_verification_refusal_is_a_503_not_a_ledger_conflict(
    ledger: StepLedger, code: str
) -> None:
    """Verification refusals never read as definitive ledger answers (409)."""
    verifier = StubVerifier(error=AdjustmentGrantRefused(code))  # type: ignore[arg-type]
    response = await post(wired(ledger, verifier), {"grant": "{}"}, AUTH)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == code


async def test_an_exact_retry_returns_the_same_receipt(ledger: StepLedger) -> None:
    """Posting the same grant twice is idempotent."""
    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch, principal=OPERATOR)
    app = wired(ledger, StubVerifier(result=g))
    first = await post(app, {"grant": wire_for(g).decode()}, AUTH)
    second = await post(app, {"grant": wire_for(g).decode()}, AUTH)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert ledger.used("run-1") == 0


@pytest.mark.parametrize("body", [{}, {"grant": ""}, {"grant": "x" * 65_537}, {"grant": "{}", "extra": 1}])
async def test_malformed_requests_are_rejected_before_the_ledger(ledger: StepLedger, body: dict) -> None:
    """Shape and size are validated at the boundary."""
    response = await post(wired(ledger, StubVerifier()), body, AUTH)
    assert response.status_code == 422


async def test_refusal_reasons_are_logged_with_the_correlation_id(ledger: StepLedger, caplog) -> None:
    """Operators can trace a reported correlation id to its closed reason."""
    import logging

    epoch, hold = unknown_hold(ledger)
    g = grant(ledger, hold, epoch, principal="someone-else")
    with caplog.at_level(logging.WARNING, logger="orama.api.server"):
        response = await post(wired(ledger, StubVerifier(result=g)), {"grant": wire_for(g).decode()}, AUTH)
    cid = response.json()["detail"]["correlation_id"]
    record = next(r for r in caplog.records if getattr(r, "correlation_id", None) == cid)
    assert record.reason == "grant.principal_mismatch"
