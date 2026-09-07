"""Public contracts for Gateway Lifecycle and semantic-owner adapters."""

from __future__ import annotations

import re
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from telos import EndpointRef, EndpointUseDecision, EndpointUseRequest


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactPin(Contract):
    artifact_id: str
    version: str
    digest: str

    @field_validator("version")
    @classmethod
    def version_must_be_immutable(cls, value: str) -> str:
        normalized = value.strip()
        semver = re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
            r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
            r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
            normalized,
        )
        commit = re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", normalized)
        if normalized != value or not (semver or commit):
            raise ValueError("artifact version must be an immutable exact version")
        return normalized

    @field_validator("digest")
    @classmethod
    def digest_must_be_sha256(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("artifact digest must be sha256:<64 lowercase hex>")
        return value


class OperatorConsent(Contract):
    accepted: bool
    artifact_id: str
    version: str
    digest: str

    @field_validator("digest")
    @classmethod
    def digest_must_be_sha256(cls, value: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("operator consent digest must be sha256:<64 lowercase hex>")
        return value


class GatewayLifecycleRequest(Contract):
    gateway_id: str
    artifact: ArtifactPin
    operator_consent: OperatorConsent
    provider_kind: Literal["ollama", "lm_studio", "openclaw_gateway"]
    config_endpoint: EndpointRef
    health_endpoint: EndpointRef
    allow_public_model_servers: bool = False
    model_hint: str | None = None
    readiness_timeout_seconds: int = Field(gt=0)


class PhylaxDecision(Contract):
    allowed: bool
    policy_version: str
    decision_ref: str | None = None
    reason_code: str


class PlacementDecision(Contract):
    allowed: bool
    policy_version: str
    placement_ref: str | None = None
    reason_code: str


class ProviderReadiness(Contract):
    ready: bool
    timed_out: bool = False
    provider_ref: str | None = None
    reason_code: str

    @model_validator(mode="after")
    def readiness_state_is_consistent(self) -> "ProviderReadiness":
        if self.ready and self.timed_out:
            raise ValueError("provider cannot be ready and timed out")
        if self.ready != (self.provider_ref is not None):
            raise ValueError("provider_ref must be present exactly when ready")
        return self


class GatewayProgressEvent(Contract):
    sequence: int
    phase: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class RoutingState(Contract):
    gateway_id: str
    idempotency_key: str
    artifact: ArtifactPin
    provider_kind: str
    provider_ref: str
    placement_ref: str
    placement_policy_version: str
    config_endpoint: EndpointRef
    health_endpoint: EndpointRef
    config_telos_policy_version: str
    health_telos_policy_version: str
    artifact_decision_ref: str
    admission_decision_ref: str
    artifact_phylax_policy_version: str
    admission_phylax_policy_version: str


class GatewayLifecycleResult(Contract):
    status: Literal["ready", "already_ready", "denied", "timed_out", "error"]
    reason_code: str
    routing_state: RoutingState | None = None
    events: tuple[GatewayProgressEvent, ...] = ()


class TelosPort(Protocol):
    async def authorize(self, request: EndpointUseRequest) -> EndpointUseDecision: ...


class PhylaxPort(Protocol):
    async def verify_artifact(self, artifact: ArtifactPin) -> PhylaxDecision: ...

    async def admit_runtime(
        self, *, artifact: ArtifactPin, placement_ref: str
    ) -> PhylaxDecision: ...

    async def redact(self, details: dict[str, object]) -> dict[str, object]: ...


class AgatePort(Protocol):
    async def resolve_placement(
        self, *, provider_kind: str, model_hint: str | None
    ) -> PlacementDecision: ...


class ClaudeProviderPort(Protocol):
    async def ensure_ready(
        self,
        *,
        provider_kind: str,
        placement_ref: str,
        config_endpoint: EndpointRef,
        health_endpoint: EndpointRef,
        timeout_seconds: int,
    ) -> ProviderReadiness: ...


class RoutingStateStore(Protocol):
    async def claim(self, key: str) -> RoutingState | None:
        """Atomically claim a key or await and return its completed state."""
        ...

    async def complete(self, key: str, state: RoutingState) -> None: ...

    async def abort(self, key: str) -> None:
        """Release a claimed key.

        MUST be a safe, idempotent no-op when called on a key that was never
        actually reserved by this caller (including the case where a
        cancellation raced the underlying claim() reservation and the caller
        cannot tell whether it committed). Implementations must not raise or
        corrupt state when abort() targets an unknown or already-released key.
        """
        ...


class ProgressEventSink(Protocol):
    async def emit(self, event: GatewayProgressEvent) -> None: ...
