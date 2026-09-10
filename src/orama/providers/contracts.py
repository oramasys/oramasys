"""Application-facing provider invocation contracts.

These contracts deliberately contain no network client. A concrete provider
invoker may translate application/provider semantics, but any real outbound
transport must remain Telos-backed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from perpetua_core.discovery import Backend


@dataclass(frozen=True, slots=True)
class ProviderMessage:
    role: str
    content: str


@dataclass(frozen=True, slots=True)
class ProviderInvocationRequest:
    backend: Backend
    model: str
    messages: tuple[ProviderMessage, ...]
    run_id: str

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError("model is required")
        if not self.run_id.strip():
            raise ValueError("run_id is required")
        # A caller-supplied list is stored by reference; without coercing to
        # a real tuple here, mutating that list after construction silently
        # changes what this "frozen" request contains. Confirmed directly
        # before this fix: appending to the original list after
        # construction was reflected in .messages despite frozen=True.
        object.__setattr__(self, "messages", tuple(self.messages))


@dataclass(frozen=True, slots=True)
class ProviderInvocationResult:
    content: str
    provider_ref: str
    decision_ref: str

    def __post_init__(self) -> None:
        if not self.provider_ref.strip():
            raise ValueError("provider_ref is required")
        if not self.decision_ref.strip():
            raise ValueError("decision_ref is required")


class ProviderInvoker(Protocol):
    async def invoke(
        self,
        request: ProviderInvocationRequest,
    ) -> ProviderInvocationResult: ...
