"""Request/response contracts for the oramasys FastAPI glass-window."""
from __future__ import annotations
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from perpetua_core.state import PerpetuaState, HardwareTier, TaskType, OptHint


class RunRequest(BaseModel):
    """A request to run one task through the compiled graph."""

    model_config = ConfigDict(protected_namespaces=())

    session_id: str
    task: str
    task_type: TaskType = "reasoning"
    target_tier: HardwareTier = "shared"
    optimize_for: OptHint = "quality"
    model_hint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_state(self) -> PerpetuaState:
        """Convert the request into the initial graph state."""
        return PerpetuaState(
            session_id=self.session_id,
            messages=[{"role": "user", "content": self.task}],
            task_type=self.task_type,
            target_tier=self.target_tier,
            optimize_for=self.optimize_for,
            model_hint=self.model_hint,
            metadata=self.metadata,
        )


class RunResponse(BaseModel):
    """The outcome of a run: status, final message and the nodes visited."""

    model_config = ConfigDict(protected_namespaces=())

    session_id: str
    status: str
    result: str | None = None
    nodes_visited: list[str] = Field(default_factory=list)
    error: str | None = None

    @classmethod
    def from_state(cls, state: PerpetuaState) -> "RunResponse":
        """Build the response from a finished graph state."""
        last_message = (
            state.messages[-1].get("content") if state.messages else None
        )
        return cls(
            session_id=state.session_id,
            status=state.status,
            result=last_message,
            nodes_visited=state.nodes_visited,
            error=state.error,
        )


class AdjustmentRequest(BaseModel):
    """One signed adjustment grant, in the issuer's wire form, to be spent once."""

    model_config = ConfigDict(extra="forbid")

    grant: str = Field(min_length=2, max_length=65_536)


class AdjustmentReceiptResponse(BaseModel):
    """The ledger's immutable receipt for a consumed grant; no issuer internals."""

    grant_id: str
    run_id: str
    hold_id: str
    kind: str
    units_basis: str
    balance_delta: int
    verifier_id: str
    payload_digest: str
