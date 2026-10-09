"""Independent, immutable graph-policy document. Lint is not runtime admission."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from perpetua_core.graph.spec import GraphSpec


class PolicyRecord(BaseModel):
    """Reject unknown fields, coercion, and mutation at every nested boundary."""
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Budgets(PolicyRecord):
    """Optional ceilings; absence is not an authorization to execute effects."""
    requests: int | None = Field(default=None, gt=0)
    input_tokens: int | None = Field(default=None, gt=0)
    output_tokens: int | None = Field(default=None, gt=0)


class EffectDeclaration(PolicyRecord):
    """Effect intent and safe replay disposition; attempt IDs are evidence only."""
    node: str = Field(min_length=1, max_length=128)
    kind: Literal["pure", "untrusted", "provider"]
    replay: Literal["deny", "idempotent"] = "deny"
    operation_id: str | None = Field(default=None, min_length=1, max_length=128)


class GraphPolicy(PolicyRecord):
    """Versioned policy bound to Core's exact structural content hash."""
    policy_schema_version: Literal["1"] = "1"
    graph_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    revision: int = Field(default=1, gt=0)
    budgets: Budgets = Field(default_factory=Budgets)
    effects: tuple[EffectDeclaration, ...] = Field(default=(), max_length=256)
    approval: Literal["deny-until-durable"] = "deny-until-durable"

    @property
    def policy_id(self) -> str:
        """Hash canonical policy bytes independently of graph structure."""
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
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
        return {"graph_id": self.graph.graph_id, "policy_id": self.policy.policy_id,
                "policy_reference": self.reference, "revision": self.policy.revision,
                "budgets": self.policy.budgets.model_dump(), "approval": self.policy.approval,
                "effects": [effect.model_dump() for effect in self.policy.effects]}


def bind_policy(graph: GraphSpec, policy: GraphPolicy, *, reference: str) -> PolicyBinding:
    """Lint the exact structure binding and node declarations before returning a view."""
    if graph.graph_id != policy.graph_id:
        raise ValueError("policy graph_id does not match structural graph_id")
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
    return PolicyBinding(graph, policy, reference)


def load_policy(path: Path) -> GraphPolicy:
    """Read bounded JSON strictly; no executable includes or URL fetching."""
    with path.open("rb") as stream:
        payload = stream.read(65537)
    if len(payload) > 65536:
        raise ValueError("policy size exceeds 65536 bytes")
    return GraphPolicy.model_validate_json(payload)
