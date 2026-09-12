"""Static topology contract for the default Oramasys graph."""
from __future__ import annotations

import copy

import pytest

from perpetua_core.graph.spec import GraphSpec

from orama.graph.perpetua_graph import build_graph_spec


def test_default_graph_spec_round_trips_with_stable_identity() -> None:
    spec = build_graph_spec()

    assert [node.name for node in spec.nodes] == ["dispatch", "respond", "route"]
    assert {(edge.source, edge.target) for edge in spec.edges} == {
        ("__start__", "route"),
        ("route", "dispatch"),
        ("dispatch", "respond"),
        ("respond", "__end__"),
    }
    assert spec.max_steps == 3
    assert spec.metadata["runtime_builder"] == "orama.graph.perpetua_graph:build_graph"
    assert GraphSpec.from_dict(spec.to_dict()) == spec


def test_default_graph_spec_rejects_tampered_topology() -> None:
    payload = copy.deepcopy(build_graph_spec().to_dict())
    payload["edges"][0]["target"] = "unexpected"

    with pytest.raises(ValueError, match="graph_id mismatch"):
        GraphSpec.from_dict(payload)
