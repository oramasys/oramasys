"""TDD: oramasys API glass-window contracts."""
import pytest
from httpx import AsyncClient, ASGITransport
from orama.api.server import app

_TOKEN = "test-control-plane-token-32b"


@pytest.fixture(autouse=True)
def _auth_env(monkeypatch):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", _TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_TOKEN}"}


async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_run_endpoint_returns_200():
    payload = {
        "session_id": "test-session",
        "task": "Explain hardware routing.",
        "task_type": "reasoning",
        "target_tier": "shared",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=payload, headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "test-session"
    assert body["status"] == "done"
    assert "nodes_visited" in body


async def test_run_response_has_result():
    payload = {"session_id": "s2", "task": "hello"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=payload, headers=_auth_headers())
    body = resp.json()
    assert body["result"] is not None


async def test_import_boundary_oramasys_does_not_import_back():
    """oramasys must not be imported by perpetua_core."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-c", "import perpetua_core"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
