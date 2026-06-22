"""TDD: dispatch_node consults discovery registry to resolve a backend."""
import pytest
import respx
import httpx
from perpetua_core.state import PerpetuaState
from perpetua_core.discovery import BackendRegistry
from orama.graph.perpetua_graph import build_graph


@pytest.mark.asyncio
@respx.mock
async def test_dispatch_routes_through_discovery_registry():
    # Seed registry with one online windows backend.
    respx.get("http://192.168.254.103:1234/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "qwen3-coder-30b"}]})
    )
    respx.get("http://localhost:11434/v1/models").mock(return_value=httpx.Response(404))
    respx.get("http://localhost:1234/v1/models").mock(return_value=httpx.Response(404))

    reg = BackendRegistry()
    await reg.autodetect()

    # Build graph with registry injected.
    graph = build_graph(registry=reg)
    state = PerpetuaState(session_id="t1", task_type="coding", target_tier="shared")
    result = await graph.ainvoke(state)
    assert result.metadata.get("resolved_backend") == "lmstudio-win"
    assert result.metadata.get("resolved_url") == "http://192.168.254.103:1234/v1"
    assert result.status == "done"
