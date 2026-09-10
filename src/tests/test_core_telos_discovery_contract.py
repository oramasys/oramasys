from __future__ import annotations

import inspect

from perpetua_core.discovery import probe


def test_core_health_probe_has_no_raw_httpx_transport() -> None:
    source = inspect.getsource(probe)

    assert "httpx.AsyncClient" not in source
    assert "import httpx" not in source
    assert "EndpointAuthorizer.from_exact_rules" in source
    assert "AlwaysAllowHealthProbeAuthorizer" not in source


def test_core_health_probe_uses_telos_request_transport() -> None:
    source = inspect.getsource(probe)

    assert "from telos import" in source
    assert "request," in source
    assert "allow_public=False" in source
    assert "allow_private=True" in source
    assert "allow_loopback=True" in source
