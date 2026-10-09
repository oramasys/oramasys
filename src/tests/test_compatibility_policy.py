"""Policy binding changes must fail before a graph or foreign effect runs."""
from __future__ import annotations

import pytest

from perpetua_core.graph.spec import EdgeSpec, GraphSpec, NodeSpec
from orama.compat.policy import GraphPolicy, bind_policy, load_policy


def spec(name: str = "a") -> GraphSpec:
    """Build a small structural graph with a stable content hash."""
    return GraphSpec.create(max_steps=2, nodes=(NodeSpec(name),), edges=(
        EdgeSpec(source="__start__", kind="static", target=name),
        EdgeSpec(source=name, kind="static", target="__end__"),
    ))


def test_policy_binding_and_summary() -> None:
    """Changing structure invalidates policy while summaries leave Core unchanged."""
    graph = spec()
    policy = GraphPolicy.model_validate({"graph_id": graph.graph_id, "budgets": {"requests": 2}})
    binding = bind_policy(graph, policy, reference="policies/test.json")
    assert binding.summary["graph_id"] == graph.graph_id
    assert binding.summary["policy_id"] == policy.policy_id
    assert binding.summary["budgets"]["requests"] == 2
    changed = GraphPolicy(graph_id=graph.graph_id, revision=2)
    assert changed.policy_id != policy.policy_id
    assert bind_policy(graph, changed, reference="policies/test.json").graph.graph_id == graph.graph_id
    with pytest.raises(ValueError, match="graph_id"):
        bind_policy(spec("b"), policy, reference="policies/test.json")


@pytest.mark.parametrize("value", [0, -1, True, "2"])
def test_policy_rejects_invalid_budget(value: object) -> None:
    """Strict positive bounds must not accept bools or string coercion."""
    with pytest.raises(ValueError):
        GraphPolicy.model_validate({"graph_id": spec().graph_id, "budgets": {"requests": value}})


def test_unknown_fields_effects_and_mutation_fail_closed() -> None:
    """Policy cannot carry unknown keys, undeclared nodes, or mutable nested bounds."""
    graph = spec()
    with pytest.raises(ValueError):
        GraphPolicy.model_validate({"graph_id": graph.graph_id, "allow_all": True})
    policy = GraphPolicy.model_validate({"graph_id": graph.graph_id,
        "effects": ({"node": "missing", "kind": "untrusted", "replay": "deny"},)})
    with pytest.raises(ValueError, match="node"):
        bind_policy(graph, policy, reference="policies/test.json")
    policy = GraphPolicy(graph_id=graph.graph_id)
    with pytest.raises(ValueError):
        policy.budgets.requests = 100
    with pytest.raises(ValueError, match="relative"):
        bind_policy(graph, policy, reference="../outside.json")


def test_load_policy_has_bounded_input(tmp_path: object) -> None:
    """Reject oversized documents before parsing or allocating nested structures."""
    from pathlib import Path
    path = Path(str(tmp_path)) / "policy.json"
    path.write_text(" " * 65537)
    with pytest.raises(ValueError, match="size"):
        load_policy(path)


def test_application_transcludes_bound_policy() -> None:
    """Installed application exposes its policy link and exact independent hashes."""
    from orama.graph.perpetua_graph import build_application_graph_definition, build_graph_spec
    definition = build_application_graph_definition()
    assert definition.graph == build_graph_spec()
    assert definition.summary["policy_reference"] == "src/orama/graph/policies/default.json"
    assert definition.summary["approval"] == "deny-until-durable"
    assert {effect.node for effect in definition.policy.effects} == {"route", "dispatch", "respond"}


@pytest.mark.parametrize("effects", [
    ({"node": "a", "kind": "untrusted"}, {"node": "a", "kind": "provider"}),
    ({"node": "a", "kind": "provider", "replay": "idempotent"},),
])
def test_invalid_effect_replay_declarations_are_rejected(effects) -> None:
    """Duplicate effects and unbound replay claims cannot pass policy binding lint."""
    graph = spec()
    policy = GraphPolicy.model_validate({"graph_id": graph.graph_id, "effects": effects})
    with pytest.raises(ValueError):
        bind_policy(graph, policy, reference="policies/test.json")
