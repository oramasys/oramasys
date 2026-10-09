"""Restrict-only reducer/join policy fields: schema, id stability, fail-closed parsing."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from orama.compat.policy import (
    ForbiddenReducer,
    GraphPolicy,
    JoinRestrictions,
    ReducerRestrictions,
    load_policy,
)

GRAPH_ID = "0" * 64
# Captured from the policy schema before restrictions existed.
GOLDEN_DEFAULT_ID = "8f20f61296ee4e5d5e556025fd534d70a765c1b817a2de146826468237323202"
GOLDEN_BUDGET_ID = "9b84db5d22bc57c17fb9bbd1884993449c8e3284d2994c323ef43045d43fec56"


def test_policy_id_is_unchanged_for_policies_without_restrictions() -> None:
    """Existing policies and their bindings stay valid (D-LG-5, point 5)."""
    assert GraphPolicy(graph_id=GRAPH_ID).policy_id == GOLDEN_DEFAULT_ID
    budgeted = GraphPolicy.model_validate(
        {"graph_id": "1" * 64, "revision": 3, "budgets": {"requests": 2}})
    assert budgeted.policy_id == GOLDEN_BUDGET_ID


def test_schema_two_with_default_restrictions_has_its_own_id_but_same_meaning() -> None:
    plain = GraphPolicy(graph_id=GRAPH_ID)
    explicit = GraphPolicy(graph_id=GRAPH_ID, policy_schema_version="2")
    assert explicit.policy_id != plain.policy_id
    assert explicit.reducer_restrictions == ReducerRestrictions()


def test_restrictions_require_policy_schema_two() -> None:
    restrictions = ReducerRestrictions(required_fields=("messages",))
    with pytest.raises(ValidationError, match="policy_schema_version '2'"):
        GraphPolicy(graph_id=GRAPH_ID, reducer_restrictions=restrictions)
    with pytest.raises(ValidationError, match="policy_schema_version '2'"):
        GraphPolicy(graph_id=GRAPH_ID, join_restrictions=JoinRestrictions(min_quorum=2))
    ok = GraphPolicy(graph_id=GRAPH_ID, policy_schema_version="2",
                     reducer_restrictions=restrictions)
    assert ok.policy_id not in {GOLDEN_DEFAULT_ID}


def test_restrictions_change_the_policy_id() -> None:
    a = GraphPolicy(graph_id=GRAPH_ID, policy_schema_version="2",
                    join_restrictions=JoinRestrictions(allowed_kinds=("all",)))
    b = GraphPolicy(graph_id=GRAPH_ID, policy_schema_version="2",
                    join_restrictions=JoinRestrictions(allowed_kinds=("all", "any")))
    assert a.policy_id != b.policy_id


def test_policy_cannot_declare_reducers_or_joins() -> None:
    """Declarations belong to Core's GraphSpec; unknown policy keys fail closed."""
    for key in ("reducers", "joins"):
        with pytest.raises(ValidationError):
            GraphPolicy.model_validate({"graph_id": GRAPH_ID, key: {}})
    with pytest.raises(ValidationError):
        ReducerRestrictions.model_validate({"declare": ()})
    with pytest.raises(ValidationError):
        JoinRestrictions.model_validate({"set_kind": "all"})


def test_restriction_values_are_validated() -> None:
    with pytest.raises(ValidationError):
        ForbiddenReducer(field="messages", kind="sum")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ForbiddenReducer(field="", kind="last")
    with pytest.raises(ValidationError):
        JoinRestrictions(allowed_kinds=("race",))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        JoinRestrictions(min_quorum=0)


def test_restrictions_load_from_bounded_json(tmp_path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        '{"graph_id": "%s", "policy_schema_version": "2",'
        ' "reducer_restrictions": {"required_fields": ["messages"],'
        ' "forbidden": [{"field": "*", "kind": "last"}]},'
        ' "join_restrictions": {"allowed_kinds": ["all", "quorum"], "min_quorum": 2}}' % GRAPH_ID)
    policy = load_policy(path)
    assert policy.reducer_restrictions.forbidden == (ForbiddenReducer(field="*", kind="last"),)
    assert policy.join_restrictions.allowed_kinds == ("all", "quorum")
    path.write_text('{"graph_id": "%s", "reducers": []}' % GRAPH_ID)
    with pytest.raises(ValidationError):
        load_policy(path)
