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
        assert response.json()["error"]["code"] == "serving.not_ready"


async def test_unavailable_verifier_is_not_ready():
    """A composition failure refuses readiness without leaking its cause."""
    app = create_app(grant_capability="unavailable")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")
        assert response.status_code == 503
        body = response.json()
        assert set(body) == {"error"} and set(body["error"]) == {"code", "correlation_id"}
        assert body["error"]["code"] == "serving.not_ready"


async def test_composed_consumer_alone_is_not_ready_without_serving_enabled(tmp_path):
    """A wired consumer is a composition fact; it never turns serving on by itself."""
    ledger = StepLedger(tmp_path / "ledger.sqlite")
    try:
        app = create_app(adjustment_consumer=AdjustmentGrantConsumer(ledger, StubVerifier()))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/readyz")
            assert response.status_code == 503
            assert response.json()["error"]["code"] == "serving.not_ready"
    finally:
        ledger.close()
