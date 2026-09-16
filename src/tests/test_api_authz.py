"""S-AuthZ API tests: bearer on /run, public /health, bind helpers."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.authz import (
    LanBindError,
    ROUTE_MANIFEST,
    assert_host_allowed,
    auth_enforced,
    capability_for,
    is_loopback_host,
    manifest_keys,
    resolve_bind_host,
)
from orama.api.server import app

_RUN_PAYLOAD = {
    "session_id": "test-session",
    "task": "Explain hardware routing.",
    "task_type": "reasoning",
    "target_tier": "shared",
}


@pytest.fixture
def strong_token() -> str:
    return "test-control-plane-token-32b"


async def test_health_endpoint_public_without_auth(monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_run_without_token_configured_returns_503(monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 503


async def test_run_requires_bearer(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 401


async def test_run_rejects_wrong_bearer(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run",
            json=_RUN_PAYLOAD,
            headers={"Authorization": "Bearer wrong-token-value-here!!"},
        )
    assert resp.status_code == 401


async def test_run_with_valid_bearer_ok(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run",
            json=_RUN_PAYLOAD,
            headers={"Authorization": f"Bearer {strong_token}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == "test-session"
    assert body["status"] == "done"
    assert "nodes_visited" in body


async def test_run_insecure_dev_loopback_skips_auth(monkeypatch):
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 200


async def test_insecure_dev_ignored_when_lan_bound(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 401


def test_lan_bind_rejects_weak_token(monkeypatch):
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "changeme")
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_lan_bind_rejects_missing_token(monkeypatch):
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_lan_bind_ok_with_strong_token(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    host = resolve_bind_host()
    assert host == ".".join(["0"] * 4)


def test_default_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    assert resolve_bind_host() == "127.0.0.1"


def test_manifest_covers_app_routes():
    from fastapi.routing import APIRoute

    declared = manifest_keys()
    app_routes = {
        (list(route.methods)[0].upper(), route.path)
        for route in app.routes
        if isinstance(route, APIRoute) and route.path in {"/health", "/run"}
    }
    assert app_routes <= declared
    assert ("GET", "/health") in declared
    assert ("POST", "/run") in declared
    assert capability_for("GET", "/health").value == "public"
    assert capability_for("POST", "/run").value == "mutate"
    assert len(ROUTE_MANIFEST) >= 2


def test_non_loopback_bind_host_requires_lan_policy(monkeypatch):
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_BIND_HOST", ".".join(["0"] * 4))
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_assert_host_allows_loopback_without_lan(monkeypatch):
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    assert assert_host_allowed("127.0.0.1") == "127.0.0.1"


def test_assert_host_rejects_explicit_non_loopback_without_lan(monkeypatch, strong_token):
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    with pytest.raises(LanBindError):
        assert_host_allowed(".".join(["0"] * 4))


def test_assert_host_allows_non_loopback_with_lan_and_strong_token(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    host = ".".join(["0"] * 4)
    assert assert_host_allowed(host) == host


def test_insecure_dev_still_enforced_when_listen_host_not_loopback(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_LISTEN_HOST", ".".join(["0"] * 4))
    assert auth_enforced() is True


def test_insecure_dev_loopback_listen_not_enforced(monkeypatch):
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_LISTEN_HOST", "127.0.0.1")
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    assert auth_enforced() is False


def test_insecure_dev_honors_uvicorn_host_when_listen_unset(monkeypatch, strong_token):
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    monkeypatch.setenv("UVICORN_HOST", ".".join(["0"] * 4))
    assert auth_enforced() is True


def test_loopback_host_rejects_127_prefix_hostnames():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("[::1]") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host(".".join(["0"] * 4)) is False
    assert is_loopback_host("::") is False
    assert is_loopback_host("127.attacker.example") is False
