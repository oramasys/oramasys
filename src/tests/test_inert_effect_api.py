"""Authenticated inert endpoint exposes no caller-controlled grant facts."""
import pytest
from httpx import ASGITransport, AsyncClient
from orama.api.server import create_app


async def test_inert_send_requires_authenticated_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a token-authenticated principal reaches the composed sender."""
    token = "test-control-plane-token-32b"
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    calls = []
    def send(attempt: str, principal: str) -> str:
        """Record server-derived ownership and return sanitized inert evidence."""
        calls.append((attempt, principal))
        return "inert-simulation:v1"
    async with AsyncClient(transport=ASGITransport(app=create_app(inert_sender=send)), base_url="http://test") as client:
        response = await client.post("/effects/inert", json={"attempt_id": "a"})
        assert response.status_code in (401, 403)
        assert calls == []
        response = await client.post("/effects/inert", json={"attempt_id": "a"}, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert calls[0][0] == "a" and calls[0][1]


async def test_inert_sender_is_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Installing composition code grants no sending capability."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test") as client:
        response = await client.post("/effects/inert", json={"attempt_id": "a"}, headers={"Authorization": "Bearer test-control-plane-token-32b"})
        assert response.status_code == 503
