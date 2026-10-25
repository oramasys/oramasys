"""Separate liveness from fail-closed composition readiness."""
from httpx import ASGITransport, AsyncClient

from orama.api.server import create_app
from orama.graph.execution_guard import StepLedger
from orama.graph.grant_verifier import AdjustmentGrantConsumer
from tests.test_adjustment_grant_consumer import StubVerifier


async def test_live_process_without_verifier_is_not_ready(monkeypatch):
    """A healthy disabled process must not advertise grant-serving readiness."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test") as client:
        assert (await client.get("/healthz")).status_code == 200
        response = await client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "serving_unavailable"


async def test_unavailable_verifier_is_not_ready():
    """A composition failure refuses readiness without leaking its cause."""
    app = create_app(grant_capability="unavailable")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"detail": {"code": "serving_unavailable"}}


async def test_composed_consumer_reports_only_composition_readiness(tmp_path):
    """Readiness does not claim valid grants, effect activation or issuer capability."""
    ledger = StepLedger(tmp_path / "ledger.sqlite")
    try:
        app = create_app(adjustment_consumer=AdjustmentGrantConsumer(ledger, StubVerifier()))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/readyz")
            assert response.status_code == 200
            assert response.json() == {"status": "ready", "scope": "grant_composition"}
    finally:
        ledger.close()
