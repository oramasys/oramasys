"""Behavioral regression tests for Oramasys Telos-backed health probes."""
from __future__ import annotations

import inspect
import json
import socket
import threading
from unittest.mock import patch

import pytest

from perpetua_core.discovery.backend import BackendHealth, BackendKind

from orama.discovery import probe as probe_module
from orama.discovery.probe import health_probe
from orama.discovery.registry import DiscoveryBackendRegistry


def _serve_once(sock: socket.socket, status_line: str, body: bytes) -> None:
    conn, _ = sock.accept()
    conn.recv(4096)
    headers = (
        f"{status_line}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    conn.sendall(headers + body)
    conn.close()
    sock.close()


def _serve_raw_once(sock: socket.socket, payload: bytes) -> None:
    conn, _ = sock.accept()
    conn.recv(4096)
    conn.sendall(payload)
    conn.close()
    sock.close()


def _start_server(status_line: str, body: bytes) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    thread = threading.Thread(
        target=_serve_once,
        args=(sock, status_line, body),
        daemon=True,
    )
    thread.start()
    return port


def _start_raw_server(payload: bytes) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    thread = threading.Thread(
        target=_serve_raw_once,
        args=(sock, payload),
        daemon=True,
    )
    thread.start()
    return port


def test_probe_has_no_always_allow_authorizer() -> None:
    source = inspect.getsource(probe_module)

    assert "AlwaysAllowHealthProbeAuthorizer" not in source
    assert "EndpointUseDecision(" not in source
    assert "EndpointAuthorizer.from_exact_rules" in source


@pytest.mark.asyncio
async def test_health_probe_allows_loopback_and_reports_online():
    body = json.dumps({"data": [{"id": "llama3"}]}).encode()
    port = _start_server("HTTP/1.1 200 OK", body)
    result = await health_probe(f"http://127.0.0.1:{port}/v1")
    assert result.health == BackendHealth.ONLINE
    assert result.models == ("llama3",)


@pytest.mark.asyncio
async def test_health_probe_reports_offline_on_non_200():
    port = _start_server("HTTP/1.1 500 Internal Server Error", b"")
    result = await health_probe(f"http://127.0.0.1:{port}/v1")
    assert result.health == BackendHealth.OFFLINE
    assert result.models == ()


@pytest.mark.asyncio
async def test_health_probe_reports_degraded_on_malformed_json():
    port = _start_server("HTTP/1.1 200 OK", b"not json")
    result = await health_probe(f"http://127.0.0.1:{port}/v1")
    assert result.health == BackendHealth.DEGRADED


@pytest.mark.asyncio
async def test_health_probe_reports_offline_on_malformed_http_response():
    port = _start_raw_server(b"NOT-HTTP\r\n\r\n")

    result = await health_probe(f"http://127.0.0.1:{port}/v1")

    assert result.health == BackendHealth.OFFLINE
    assert result.models == ()


@pytest.mark.asyncio
async def test_health_probe_rejects_public_address_without_attempting_a_connection():
    """A literal public IP must be rejected by Telos before socket creation."""
    with patch(
        "telos.transport.socket.create_connection",
        side_effect=AssertionError("public address must not be dialed"),
    ):
        result = await health_probe("http://93.184.216.34/v1")

    assert result.health == BackendHealth.OFFLINE
    assert result.models == ()


@pytest.mark.asyncio
async def test_health_probe_allows_private_address_to_attempt_connection():
    """RFC1918 destinations clear transport policy and may attempt a dial."""
    dialed: list[object] = []

    def _record_dial(*args: object, **kwargs: object) -> None:
        dialed.append(args)
        raise OSError("refused after policy admission")

    with patch(
        "telos.transport.socket.create_connection",
        side_effect=_record_dial,
    ):
        result = await health_probe("http://10.0.0.1:1234/v1")

    assert dialed, "private address must be admitted through to dial"
    assert result.health == BackendHealth.OFFLINE
    assert result.models == ()


@pytest.mark.asyncio
async def test_discovery_registry_autodetect_uses_caller_supplied_seeds_only():
    body = json.dumps({"data": [{"id": "local-model"}]}).encode()
    port = _start_server("HTTP/1.1 200 OK", body)
    registry = DiscoveryBackendRegistry()

    found = await registry.autodetect(
        (("loopback-ollama", f"http://127.0.0.1:{port}/v1", BackendKind.OLLAMA),)
    )

    assert len(found) == 1
    assert found[0].health == BackendHealth.ONLINE
    assert found[0].models == ("local-model",)
    assert registry.online()[0].name == "loopback-ollama"


@pytest.mark.asyncio
async def test_discovery_registry_autodetect_with_no_seeds_is_empty():
    registry = DiscoveryBackendRegistry()
    assert await registry.autodetect(()) == []
    assert registry.all() == []


def test_discovery_module_has_no_hardcoded_lan_seeds() -> None:
    """Composition must not embed workstation LAN topology."""
    from pathlib import Path as _Path

    import orama.discovery.registry as registry_module
    import orama.discovery.probe as probe_module

    for mod in (registry_module, probe_module):
        source = _Path(mod.__file__).read_text()
        assert "192.168." not in source
