"""Policy restrictions checked against real Core fan-out regions (needs Core R3).

These tests need a Core that has GraphSpec schema 2. The candidate-Core lane sets
ORAMA_REQUIRE_CORE_R3=1, so there they cannot be skipped: a missing feature fails.
The production lane skips them until its Core pin is promoted past R3.
"""
from __future__ import annotations

import os

import pytest

from perpetua_core.graph import spec as core_spec

HAS_R3 = hasattr(core_spec, "ReducerSpec")
if os.environ.get("ORAMA_REQUIRE_CORE_R3"):
    assert HAS_R3, "candidate Core must provide GraphSpec reducers and joins"
if not HAS_R3:
    pytest.skip("Core pin predates R3 fan-out regions", allow_module_level=True)

from orama.compat.policy import (  # noqa: E402
    ForbiddenReducer,
    GraphPolicy,
    JoinRestrictions,
    ReducerRestrictions,
    bind_policy,
)
from perpetua_core.graph.engine import FanOut, Join, MiniGraph  # noqa: E402
from perpetua_core.graph.reducers import Reducer  # noqa: E402


def graph(join: Join | None = None, reducers: dict[str, Reducer] | None = None):
    builder = MiniGraph()
    for name in ("plan", "a", "b", "after"):
        builder.add_node(name, lambda s: {})
    builder.set_entry("plan")
    builder.add_edge("plan", FanOut(("a", "b"), "after", join or Join()))
    for field, reducer in (reducers or {}).items():
        builder.add_reducer(field, reducer)
    return builder.describe()


def policy_for(spec, **restrictions) -> GraphPolicy:
    return GraphPolicy(graph_id=spec.graph_id, policy_schema_version="2", **restrictions)


def bind(spec, policy):
    return bind_policy(spec, policy, reference="policies/test.json")


def test_unrestricted_policy_binds_a_region_graph() -> None:
    spec = graph()
    assert bind(spec, GraphPolicy(graph_id=spec.graph_id)).summary["graph_id"] == spec.graph_id


def test_required_reducer_field_must_be_declared() -> None:
    spec = graph()
    restrictions = ReducerRestrictions(required_fields=("messages",))
    with pytest.raises(ValueError, match="requires a declared reducer for field 'messages'"):
        bind(spec, policy_for(spec, reducer_restrictions=restrictions))
    declared = graph(reducers={"messages": Reducer("concat")})
    bind(declared, policy_for(declared, reducer_restrictions=restrictions))


def test_forbidden_reducer_kind_by_field_and_by_wildcard() -> None:
    spec = graph(reducers={"messages": Reducer("last"), "scratchpad": Reducer("union")})
    for field in ("messages", "*"):
        rule = ReducerRestrictions(forbidden=(ForbiddenReducer(field=field, kind="last"),))
        with pytest.raises(ValueError, match="forbids the 'last' reducer on field 'messages'"):
            bind(spec, policy_for(spec, reducer_restrictions=rule))
    other = ReducerRestrictions(forbidden=(ForbiddenReducer(field="scratchpad", kind="last"),))
    bind(spec, policy_for(spec, reducer_restrictions=other))


def test_join_allow_list_treats_a_missing_join_as_all() -> None:
    implied = graph()
    only_any = JoinRestrictions(allowed_kinds=("any",))
    with pytest.raises(ValueError, match="forbids the 'all' join at 'plan'"):
        bind(implied, policy_for(implied, join_restrictions=only_any))
    bind(implied, policy_for(implied, join_restrictions=JoinRestrictions(allowed_kinds=("all",))))
    anyjoin = graph(join=Join("any"))
    bind(anyjoin, policy_for(anyjoin, join_restrictions=only_any))


def test_minimum_quorum_is_enforced() -> None:
    spec = graph(join=Join("quorum", 1))
    with pytest.raises(ValueError, match="requires quorum >= 2"):
        bind(spec, policy_for(spec, join_restrictions=JoinRestrictions(min_quorum=2)))
    ok = graph(join=Join("quorum", 2))
    bind(ok, policy_for(ok, join_restrictions=JoinRestrictions(min_quorum=2)))


def test_policy_never_changes_graph_id_and_cannot_alter_declarations() -> None:
    spec = graph(reducers={"messages": Reducer("concat")})
    before = spec.graph_id
    policy = policy_for(
        spec, reducer_restrictions=ReducerRestrictions(required_fields=("messages",)))
    binding = bind(spec, policy)
    assert binding.graph.graph_id == before
    assert binding.graph.reducers == spec.reducers
    assert binding.summary["reducer_restrictions"]["required_fields"] == ("messages",)
    changed = policy_for(spec, revision=2)
    assert changed.policy_id != policy.policy_id and bind(spec, changed).graph.graph_id == before


def test_graphs_without_regions_ignore_restrictions() -> None:
    builder = MiniGraph().add_node("a", lambda s: {}).set_entry("a")
    spec = builder.describe()
    assert spec.schema_version == "1"
    strict = policy_for(spec, reducer_restrictions=ReducerRestrictions(required_fields=("x",)),
                        join_restrictions=JoinRestrictions(allowed_kinds=("all",)))
    assert bind(spec, strict).graph.graph_id == spec.graph_id


@pytest.mark.parametrize("declaration", ["reducers", "joins"])
def test_invalid_duplicate_declarations_cannot_bypass_restrictions(declaration: str) -> None:
    """Policy must not collapse duplicate declarations into an allowed last value."""
    from perpetua_core.graph.spec import GraphSpec, JoinSpec, ReducerSpec
    original = graph()
    changes = {"reducers": (ReducerSpec("messages", "last"), ReducerSpec("messages", "concat"))}
    if declaration == "joins":
        changes = {"joins": (JoinSpec("plan", "any"), JoinSpec("plan", "quorum", quorum=2))}
    invalid = GraphSpec.create(max_steps=original.max_steps, nodes=original.nodes,
                               edges=original.edges, **changes)
    restrictions = dict(
        reducer_restrictions=ReducerRestrictions(forbidden=(ForbiddenReducer(field="*", kind="last"),)),
        join_restrictions=JoinRestrictions(allowed_kinds=("all", "quorum")),
    )
    with pytest.raises(ValueError, match="GS208|GS210"):
        bind(invalid, policy_for(invalid, **restrictions))
