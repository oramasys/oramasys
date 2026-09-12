"""Application-facing provider invocation contracts.

These contracts deliberately contain no network client. A concrete provider
invoker may translate application/provider semantics, but any real outbound
transport must remain Telos-backed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

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
    #: Telos policy version that authorized the outbound dial, when the
    #: concrete invoker can supply it (audit correlation; optional so existing
    #: invokers stay valid).
    policy_version: str | None = None

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


@runtime_checkable
class AbortableProviderInvoker(Protocol):
    """Optional capability extension: an invoker that can release its
    underlying transport immediately, independent of whether its own
    ``invoke()`` coroutine ever notices asyncio cancellation.

    Plain ``.cancel()`` only requests cooperative cancellation -- an
    invoker that catches ``CancelledError`` and keeps running (a real,
    tested scenario; see test_dispatch_settles_on_deadline_even_when_
    invoker_suppresses_cancellation) is not stopped by it. A concrete
    invoker that implements ``abort()`` gets a second, independent chance
    to force resource release -- e.g. closing the underlying
    ``httpx.AsyncClient`` a request is in-flight on, which makes that
    in-flight request fail promptly regardless of what its own
    request-handling code is doing. This is checked via
    ``isinstance(invoker, AbortableProviderInvoker)`` (structural, thanks
    to ``@runtime_checkable``) at the dispatch boundary; an invoker that
    does not implement ``abort()`` is unaffected -- calling it is never
    required.
    """

    async def invoke(
        self,
        request: ProviderInvocationRequest,
    ) -> ProviderInvocationResult: ...

    async def abort(self, request: ProviderInvocationRequest) -> None: ...
