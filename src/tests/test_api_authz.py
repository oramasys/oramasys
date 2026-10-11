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
from orama.api.server import app, create_app

_RUN_PAYLOAD = {
    "session_id": "test-session",
    "task": "Explain hardware routing.",
    "task_type": "reasoning",
    "target_tier": "shared",
}


class _DirectRunner:
    """Test-only runner used where this file verifies authorization, not admission."""

    async def invoke(self, graph: object, state: object) -> object:
        """Run the supplied graph explicitly for an authorization-only test."""
        return await graph.ainvoke(state)


class _RecordingBoundRunner:
    """Minimal request runner returned from the authenticated factory."""

    def __init__(self) -> None:
        """Initialize captured invocation inputs."""
        self.states: list[object] = []

    async def invoke(self, graph: object, state: object) -> object:
        """Record the state while preserving the public API response contract."""
        self.states.append(state)
        return await graph.ainvoke(state)


class _RecordingRunnerFactory:
    """Probe that makes middleware-established capability binding observable."""

    def __init__(self) -> None:
        """Initialize captured principal and request runner."""
        self.principals: list[str] = []
        self.bound_runner = _RecordingBoundRunner()

    def for_authenticated_principal(self, principal_id: str) -> _RecordingBoundRunner:
        """Capture the principal supplied by the HTTP authorization boundary."""
        self.principals.append(principal_id)
        return self.bound_runner


@pytest.fixture
def strong_token() -> str:
    """Test helper: strong token."""
    return "test-control-plane-token-32b"


async def test_health_endpoint_public_without_auth(monkeypatch):
    """Health endpoint public without auth."""
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=create_app(runner=_DirectRunner())), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_run_without_token_configured_returns_503(monkeypatch):
    """Run without token configured returns 503."""
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 503


async def test_run_requires_bearer(monkeypatch, strong_token):
    """Run requires bearer."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 401


async def test_run_rejects_wrong_bearer(monkeypatch, strong_token):
    """Run rejects wrong bearer."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run",
            json=_RUN_PAYLOAD,
            headers={"Authorization": "Bearer wrong-token-value-here!!"},
        )
    assert resp.status_code == 401


async def test_run_with_valid_bearer_refuses_without_admission_runner(monkeypatch, strong_token) -> None:
    """Run with valid bearer refuses without admission runner."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run",
            json=_RUN_PAYLOAD,
            headers={"Authorization": f"Bearer {strong_token}"},
        )
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "run_unavailable"
    assert isinstance(resp.json()["detail"]["correlation_id"], str)


async def test_valid_bearer_binds_control_plane_capability_to_runner(monkeypatch, strong_token) -> None:
    """The verified bearer provides authority without exposing its secret value."""
    factory = _RecordingRunnerFactory()
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    async with AsyncClient(
        transport=ASGITransport(app=create_app(runner=factory)), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/run",
            json=_RUN_PAYLOAD,
            headers={"Authorization": f"Bearer {strong_token}"},
        )
    assert resp.status_code == 200
    assert factory.principals == ["local-operator"]
    assert len(factory.bound_runner.states) == 1


async def test_insecure_dev_does_not_invent_capability_for_runner(monkeypatch) -> None:
    """An auth bypass never becomes an implicit production authority source."""
    factory = _RecordingRunnerFactory()
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    async with AsyncClient(
        transport=ASGITransport(app=create_app(runner=factory)), base_url="http://127.0.0.1"
    ) as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 503
    assert factory.principals == []


async def test_run_insecure_dev_loopback_skips_auth(monkeypatch):
    """Run insecure dev loopback skips auth."""
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    # base_url must be a genuinely loopback host: auth_enforced() now also
    # checks the ASGI request's own scope["server"] (ground truth for the
    # interface the connection arrived on), not just declared env intent.
    # The symbolic "http://test" host used elsewhere in this file is neither
    # loopback nor representative of a real loopback-bound dev server, so it
    # would no longer exercise the "genuinely loopback" case this test names.
    async with AsyncClient(transport=ASGITransport(app=create_app(runner=_DirectRunner())), base_url="http://127.0.0.1") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 200


async def test_insecure_dev_ignored_when_lan_bound(monkeypatch, strong_token):
    """Insecure dev ignored when lan bound."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)
    assert resp.status_code == 401


def test_lan_bind_rejects_weak_token(monkeypatch):
    """Lan bind rejects weak token."""
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "changeme")
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_lan_bind_rejects_missing_token(monkeypatch):
    """Lan bind rejects missing token."""
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_lan_bind_ok_with_strong_token(monkeypatch, strong_token):
    """Lan bind ok with strong token."""
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    host = resolve_bind_host()
    assert host == ".".join(["0"] * 4)


def test_default_bind_is_loopback(monkeypatch):
    """Default bind is loopback."""
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    assert resolve_bind_host() == "127.0.0.1"


def test_manifest_covers_app_routes():
    """Manifest covers app routes."""
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
    """Non loopback bind host requires lan policy."""
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_BIND_HOST", ".".join(["0"] * 4))
    with pytest.raises(LanBindError):
        resolve_bind_host()


def test_assert_host_allows_loopback_without_lan(monkeypatch):
    """Assert host allows loopback without lan."""
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    assert assert_host_allowed("127.0.0.1") == "127.0.0.1"


def test_assert_host_rejects_explicit_non_loopback_without_lan(monkeypatch, strong_token):
    """Assert host rejects explicit non loopback without lan."""
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    with pytest.raises(LanBindError):
        assert_host_allowed(".".join(["0"] * 4))


def test_assert_host_allows_non_loopback_with_lan_and_strong_token(monkeypatch, strong_token):
    """Assert host allows non loopback with lan and strong token."""
    monkeypatch.setenv("ORAMA_BIND_LAN", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    host = ".".join(["0"] * 4)
    assert assert_host_allowed(host) == host


def test_insecure_dev_still_enforced_when_listen_host_not_loopback(monkeypatch, strong_token):
    """Insecure dev still enforced when listen host not loopback."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_LISTEN_HOST", ".".join(["0"] * 4))
    assert auth_enforced() is True


def test_insecure_dev_loopback_listen_not_enforced(monkeypatch):
    """Insecure dev loopback listen not enforced."""
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.setenv("ORAMA_LISTEN_HOST", "127.0.0.1")
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    assert auth_enforced() is False


def test_insecure_dev_honors_uvicorn_host_when_listen_unset(monkeypatch, strong_token):
    """Insecure dev honors uvicorn host when listen unset."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)
    monkeypatch.setenv("UVICORN_HOST", ".".join(["0"] * 4))
    assert auth_enforced() is True


async def test_insecure_dev_bypass_is_closed_when_process_bound_non_loopback_without_declared_intent(
    monkeypatch, strong_token
):
    """Reproduces CodeRabbit review 5234647841 (PR#14).

    A process started without going through ``bin/serve`` (direct
    ``uvicorn --host 0.0.0.0``, a container CMD, a systemd unit) sets none
    of ORAMA_LISTEN_HOST / UVICORN_HOST / ORAMA_BIND_HOST. Declared intent
    alone (``effective_listen_host()``) then silently defaults to
    loopback, and previously let ``ORAMA_INSECURE_DEV`` disable Bearer
    auth on a listener actually reachable from the LAN/internet. The fix
    must also check the ASGI request's own ``scope["server"]`` -- ground
    truth for the interface the connection arrived on -- and keep auth on
    when that disagrees with the (absent) declared intent.
    """
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("UVICORN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)

    lan_base_url = f"http://{'.'.join(['192', '0', '2', '10'])}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url=lan_base_url) as client:
        resp = await client.post("/run", json=_RUN_PAYLOAD)

    # Auth stays enforced despite ORAMA_INSECURE_DEV=1: no declared env var
    # claims a bind host, so effective_listen_host() still (wrongly) reports
    # loopback -- but the request's own ASGI scope proves it actually arrived
    # on a non-loopback interface, and that ground truth wins.
    assert resp.status_code == 401


def test_observed_listen_host_reads_asgi_scope_server_tuple():
    """Observed listen host reads asgi scope server tuple."""
    from orama.api.authz.tokens import observed_listen_host

    assert observed_listen_host({"server": ("127.0.0.1", 8000)}) == "127.0.0.1"
    assert observed_listen_host({"server": (".".join(["0"] * 4), 8000)}) == ".".join(["0"] * 4)
    assert observed_listen_host({"server": None}) is None
    assert observed_listen_host({}) is None
    assert observed_listen_host(None) is None


def test_auth_enforced_scope_ground_truth_overrides_stale_loopback_declaration(
    monkeypatch, strong_token
):
    """Auth enforced scope ground truth overrides stale loopback declaration."""
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", strong_token)
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    monkeypatch.delenv("ORAMA_LISTEN_HOST", raising=False)
    monkeypatch.delenv("UVICORN_HOST", raising=False)
    monkeypatch.delenv("ORAMA_BIND_HOST", raising=False)

    # Declared intent alone (no scope) still defaults to loopback -> bypass allowed.
    assert auth_enforced() is False
    # The same env, but a real request whose scope proves non-loopback arrival
    # -> bypass denied, even though nothing declared a non-loopback intent.
    assert auth_enforced({"server": (".".join(["0"] * 4), 8000)}) is True
    # A genuinely loopback scope agrees with declared intent -> bypass still allowed.
    assert auth_enforced({"server": ("127.0.0.1", 8000)}) is False


def test_loopback_host_rejects_127_prefix_hostnames():
    """Loopback host rejects 127 prefix hostnames."""
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("[::1]") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host(".".join(["0"] * 4)) is False
    assert is_loopback_host("::") is False
    assert is_loopback_host("127.attacker.example") is False
