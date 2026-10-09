"""Independent, immutable graph-policy document. Lint is not runtime admission."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from perpetua_core.graph.spec import GraphSpec

ReducerKind = Literal["reject_conflict", "first", "last", "concat", "union", "custom"]
JoinKind = Literal["all", "any", "first_success", "quorum", "custom"]


class PolicyRecord(BaseModel):
    """Reject unknown fields, coercion, and mutation at every nested boundary."""
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Budgets(PolicyRecord):
    """Optional ceilings; absence is not an authorization to execute effects."""
    requests: int | None = Field(default=None, gt=0)
    input_tokens: int | None = Field(default=None, gt=0)
    output_tokens: int | None = Field(default=None, gt=0)


class EffectDeclaration(PolicyRecord):
    """Declared replay intent, not permission or a deduplication implementation.

    ``operation_id`` is the logical-operation component of a future durable
    effect key. A valid declaration does not prove provider idempotency, restore
    an execution cursor or authorize replay; durable admission remains gated.
    """
    node: str = Field(min_length=1, max_length=128)
    kind: Literal["pure", "untrusted", "provider"]
    replay: Literal["deny", "idempotent"] = "deny"
    operation_id: str | None = Field(default=None, min_length=1, max_length=128)


class ForbiddenReducer(PolicyRecord):
    """A reducer kind a graph may not declare; ``field`` ``"*"`` means any field."""
    field: str = Field(min_length=1, max_length=128)
    kind: ReducerKind


class ReducerRestrictions(PolicyRecord):
    """Restrict-only: narrow which declared reducers a graph may use.

    Reducer declarations live in Core's GraphSpec and change ``graph_id``. A policy
    can require or forbid them; it can never add, remove or change one (D-LG-5).
    """
    required_fields: tuple[str, ...] = Field(default=(), max_length=64)
    forbidden: tuple[ForbiddenReducer, ...] = Field(default=(), max_length=64)


class JoinRestrictions(PolicyRecord):
    """Restrict-only: narrow which join kinds a fan-out region may use.

    A region with no declared join is an ``all`` join. ``allowed_kinds`` of ``None`` means
    no restriction; ``min_quorum`` bounds every ``quorum`` join from below.
    """
    allowed_kinds: tuple[JoinKind, ...] | None = Field(default=None, max_length=5)
    min_quorum: int | None = Field(default=None, gt=0)


class GraphPolicy(PolicyRecord):
    """Versioned policy bound to Core's exact structural content hash."""
    policy_schema_version: Literal["1", "2"] = "1"
    graph_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    revision: int = Field(default=1, gt=0)
    budgets: Budgets = Field(default_factory=Budgets)
    effects: tuple[EffectDeclaration, ...] = Field(default=(), max_length=256)
    approval: Literal["deny-until-durable"] = "deny-until-durable"
    reducer_restrictions: ReducerRestrictions = Field(default_factory=ReducerRestrictions)
    join_restrictions: JoinRestrictions = Field(default_factory=JoinRestrictions)

    @model_validator(mode="after")
    def _restrictions_need_schema_two(self) -> "GraphPolicy":
        if self.policy_schema_version == "1" and self._has_restrictions:
            raise ValueError("reducer and join restrictions require policy_schema_version '2'")
        return self

    @property
    def _has_restrictions(self) -> bool:
        return (self.reducer_restrictions != ReducerRestrictions()
                or self.join_restrictions != JoinRestrictions())

    @property
    def policy_id(self) -> str:
        """Hash canonical policy bytes independently of graph structure.

        Default restrictions are omitted, so a policy that predates them keeps its id.
        """
        document = self.model_dump(mode="json")
        if not self._has_restrictions:
            document.pop("reducer_restrictions")
            document.pop("join_restrictions")
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class PolicyBinding:
    """Application-level transclusion, outside GraphSpec to avoid hash recursion."""
    graph: GraphSpec
    policy: GraphPolicy
    reference: str

    @property
    def summary(self) -> dict[str, Any]:
        """Build a fresh projection with links and hashes; never make it an authority."""
        view = {"graph_id": self.graph.graph_id, "policy_id": self.policy.policy_id,
                "policy_reference": self.reference, "revision": self.policy.revision,
                "budgets": self.policy.budgets.model_dump(), "approval": self.policy.approval,
                "effects": [effect.model_dump() for effect in self.policy.effects]}
        if self.policy._has_restrictions:
            view["reducer_restrictions"] = self.policy.reducer_restrictions.model_dump()
            view["join_restrictions"] = self.policy.join_restrictions.model_dump()
        return view


def bind_policy(graph: GraphSpec, policy: GraphPolicy, *, reference: str) -> PolicyBinding:
    """Validate structure before restrict-only lint and return a non-authoritative view.

    Duplicate declarations must fail before indexing could discard a forbidden
    choice. Binding never schedules work, approves effects or enables replay.
    """
    if graph.graph_id != policy.graph_id:
        raise ValueError("policy graph_id does not match structural graph_id")
    from perpetua_core.graph.lint import validate_graph_spec

    validate_graph_spec(graph)
    path = PurePosixPath(reference)
    if not reference or path.is_absolute() or ".." in path.parts or "\\" in reference or ":" in reference:
        raise ValueError("policy reference must be a repository-relative path")
    names = {node.name for node in graph.nodes}
    seen: set[str] = set()
    for effect in policy.effects:
        if effect.node not in names or effect.node in seen:
            raise ValueError("effect node must be present and unique")
        if effect.replay == "idempotent" and not effect.operation_id:
            raise ValueError("idempotent effect requires a logical operation_id")
        seen.add(effect.node)
    _check_region_restrictions(graph, policy)
    return PolicyBinding(graph, policy, reference)


def _check_region_restrictions(graph: GraphSpec, policy: GraphPolicy) -> None:
    """Refuse a graph whose declarations violate the policy's restrictions.

    Restrict-only: this reads the graph's declarations and never edits them. A graph
    without fan-out regions has nothing to restrict, which includes every graph built
    by a Core release that predates fan-out.
    """
    regions = [edge for edge in graph.edges if edge.kind == "fanout"]
    if not regions:
        return
    declared = {reducer.field: reducer.kind for reducer in graph.reducers}
    for field_name in policy.reducer_restrictions.required_fields:
        if field_name not in declared:
            raise ValueError(f"policy requires a declared reducer for field {field_name!r}")
    for rule in policy.reducer_restrictions.forbidden:
        for field_name, kind in declared.items():
            if kind == rule.kind and rule.field in ("*", field_name):
                raise ValueError(f"policy forbids the {kind!r} reducer on field {field_name!r}")
    joins = {join.source: join for join in graph.joins}
    restrictions = policy.join_restrictions
    for region in regions:
        join = joins.get(region.source)
        kind = join.kind if join else "all"
        if restrictions.allowed_kinds is not None and kind not in restrictions.allowed_kinds:
            raise ValueError(f"policy forbids the {kind!r} join at {region.source!r}")
        if (kind == "quorum" and restrictions.min_quorum is not None
                and join is not None and (join.quorum or 0) < restrictions.min_quorum):
            raise ValueError(
                f"policy requires quorum >= {restrictions.min_quorum} at {region.source!r}")


def load_policy(path: Path) -> GraphPolicy:
    """Read bounded JSON strictly; no executable includes or URL fetching."""
    with path.open("rb") as stream:
        payload = stream.read(65537)
    if len(payload) > 65536:
        raise ValueError("policy size exceeds 65536 bytes")
    return GraphPolicy.model_validate_json(payload)
