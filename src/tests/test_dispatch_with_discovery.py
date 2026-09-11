"""Dispatch resolves a backend through the discovery contract without raw I/O."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from perpetua_core.discovery import Backend, BackendHealth, BackendKind
from perpetua_core.state import PerpetuaState

from orama.graph.perpetua_graph import build_graph


class _Registry:
    def __init__(self, backends: list[Backend]) -> None:
        self._backends = list(backends)

    def online(self) -> list[Backend]:
        return [backend for backend in self._backends if backend.health is BackendHealth.ONLINE]


def _windows_backend() -> Backend:
    return Backend(
        name="lmstudio-win",
        base_url="http://192.168.254.103:1234/v1",
        kind=BackendKind.LMSTUDIO,
        models=("qwen3-coder-30b",),
        health=BackendHealth.ONLINE,
        last_seen=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_dispatch_routes_through_discovery_registry():
    reg = _Registry([_windows_backend()])
    graph = build_graph(registry=reg)
    state = PerpetuaState(
        session_id="t1",
        task_type="coding",
        target_tier="shared",
    )

    result = await graph.ainvoke(state)

    assert result.metadata.get("resolved_backend") == "lmstudio-win"
    assert result.metadata.get("resolved_url") == "http://192.168.254.103:1234/v1"
    assert result.status == "done"
