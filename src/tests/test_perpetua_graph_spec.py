"""Static topology contract for the default Oramasys graph."""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib

import pytest

from perpetua_core.graph.spec import GraphSpec

from orama.graph.perpetua_graph import build_graph_spec


ROOT = Path(__file__).resolve().parents[2]
_GRAPH_SPEC_VALIDATION_REVISION = "717f97565583fefd34f4a43064da870c0a95fb9a"


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


def test_default_graph_spec_rejects_missing_identity() -> None:
    payload = copy.deepcopy(build_graph_spec().to_dict())
    payload.pop("graph_id")

    with pytest.raises(ValueError, match="graph_id is required"):
        GraphSpec.from_dict(payload)


def test_project_pins_the_validated_graphspec_revision() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]

    assert (
        "perpetua-core @ git+https://github.com/oramasys/perpetua-core.git@"
        f"{_GRAPH_SPEC_VALIDATION_REVISION}"
    ) in dependencies
