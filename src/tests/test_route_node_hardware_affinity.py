"""route_node consults agate, the canonical v2 hardware authority, for
model-hardware fit -- never orama-system's legacy dynamic PT import (v1,
frozen), and never perpetua-core's own now-superseded duplicate resolver.

The prior implementation was a silent no-op: it looked for
config/model_hardware_policy.yml, a file that never existed in this repo,
so the hardware-affinity check never actually ran. These tests exercise
the real, now-functional check against agate's real, migrated policy
data -- not a synthetic fixture standing in for it.
"""
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
        return [b for b in self._backends if b.health is BackendHealth.ONLINE]


def _mac_backend(model: str) -> Backend:
    return Backend(
        name="ollama-mac",
        base_url="http://127.0.0.1:11434/v1",
        kind=BackendKind.OLLAMA,
        models=(model,),
        health=BackendHealth.ONLINE,
        last_seen=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_route_node_rejects_a_mac_only_model_on_windows_tier():
    """Confirmed directly against agate's real policy data before writing
    this test: qwen3.5:9b-nvfp4 is NEVER on the windows tier. The prior
    silent-no-op implementation would have let this through with no
    error at all, since its policy file never existed. route_node runs
    before dispatch_node, so this must fail here regardless of backend
    availability -- no registry needed for this case."""
    graph = build_graph()
    state = PerpetuaState(
        session_id="t1",
        task_type="reasoning",
        target_tier="windows",
        model_hint="qwen3.5:9b-nvfp4",
    )

    result = await graph.ainvoke(state)

    assert result.error is not None
    assert "qwen3.5:9b-nvfp4" in result.error
    assert "win-rtx3080" in result.error


@pytest.mark.asyncio
async def test_route_node_allows_a_mac_preferred_model_on_mac_tier():
    reg = _Registry([_mac_backend("qwen3.5:9b-nvfp4")])
    graph = build_graph(registry=reg)
    state = PerpetuaState(
        session_id="t2",
        task_type="reasoning",
        target_tier="mac",
        model_hint="qwen3.5:9b-nvfp4",
    )

    result = await graph.ainvoke(state)

    assert result.metadata.get("routed_model") == "qwen3.5:9b-nvfp4"
    assert result.metadata.get("routed_verdict") == "PREFER"
    assert result.error is None


@pytest.mark.asyncio
async def test_route_node_routes_a_default_model_when_no_hint_given():
    """No model_hint: agate's own routing table supplies a default,
    verified fit for the target profile -- exercises preferred_model(),
    not decide(), the other real code path added in this fix."""
    graph = build_graph()
    state = PerpetuaState(
        session_id="t3",
        task_type="reasoning",
        target_tier="mac",
    )

    result = await graph.ainvoke(state)

    # dispatch_node may still fail closed with no backend registered --
    # that's a separate, expected concern from route_node's own job,
    # which is only to supply a verified-fit routed_model.
    assert result.metadata.get("routed_model") is not None


def test_route_node_no_longer_imports_the_superseded_duplicate_resolver():
    """Regression for the actual architectural violation this fix closes:
    perpetua_core.policy.HardwarePolicyResolver was a second, independent
    hardware-affinity implementation embedded inside the core scheduler
    package -- confirmed directly before this fix, contrary to the
    documented invariant that the core scheduler carries no policy
    dependency. Fails if a future edit reintroduces that import."""
    import orama.graph.perpetua_graph as module

    source = module.__file__
    with open(source, encoding="utf-8") as f:
        content = f.read()
    assert "perpetua_core.policy" not in content
    assert "HardwarePolicyResolver" not in content


@pytest.mark.asyncio
async def test_route_node_unknown_target_tier_raises_clearly():
    graph = build_graph()
    state = PerpetuaState(
        session_id="t4",
        task_type="reasoning",
        target_tier="mac",
    )
    # Bypass pydantic's own Literal validation to exercise the internal
    # mapping's own defensive branch directly, matching the real failure
    # shape a future new tier value (added to HardwareTier but not yet
    # wired into this mapping) would hit.
    object.__setattr__(state, "target_tier", "nonexistent-tier")

    with pytest.raises(ValueError, match="unknown target_tier"):
        await graph.ainvoke(state)

