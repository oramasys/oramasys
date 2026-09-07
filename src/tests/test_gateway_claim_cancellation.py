"""Focused cancellation interleaving regression tests for Gateway Lifecycle."""

from __future__ import annotations

import asyncio

import pytest

from telos import EndpointRef

from orama.gateway.contracts import ArtifactPin, GatewayLifecycleRequest, OperatorConsent
from orama.gateway.lifecycle import GatewayLifecycle


class ClaimBeforeReserveStore:
    """Pause before reservation to expose abort-before-reserve races."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.in_progress: set[str] = set()
        self.aborts = 0

    async def claim(self, key: str):
        self.entered.set()
        await self.release.wait()
        self.in_progress.add(key)
        return None

    async def complete(self, key: str, state) -> None:
        raise AssertionError("claim-interleaving test must not reach complete()")

    async def abort(self, key: str) -> None:
        self.in_progress.discard(key)
        self.aborts += 1


class EventSink:
    async def emit(self, event) -> None:
        return None


class Phylax:
    async def redact(self, details):
        return dict(details)

    async def verify_artifact(self, artifact):
        raise AssertionError("claim-interleaving test must stop before Phylax")

    async def admit_runtime(self, *, artifact, placement_ref):
        raise AssertionError("claim-interleaving test must stop before Phylax")


class UnreachedOwner:
    async def authorize(self, *, purpose, endpoint):
        raise AssertionError("claim-interleaving test must stop before Telos")

    async def resolve_placement(self, *, provider_kind, model_hint):
        raise AssertionError("claim-interleaving test must stop before Agate")

    async def ensure_ready(self, **kwargs):
        raise AssertionError("claim-interleaving test must stop before provider")


def request() -> GatewayLifecycleRequest:
    digest = "sha256:" + "a" * 64
    return GatewayLifecycleRequest(
        gateway_id="local-model-gateway",
        artifact=ArtifactPin(
            artifact_id="alphaclaw",
            version="1.2.3",
            digest=digest,
        ),
        operator_consent=OperatorConsent(
            accepted=True,
            artifact_id="alphaclaw",
            version="1.2.3",
            digest=digest,
        ),
        provider_kind="ollama",
        config_endpoint=EndpointRef("http", "127.0.0.1", 18789, is_public=False),
        health_endpoint=EndpointRef("http", "127.0.0.1", 18789, is_public=False),
        readiness_timeout_seconds=30,
    )


@pytest.mark.asyncio
async def test_cancellation_waits_for_claim_to_settle_before_abort():
    store = ClaimBeforeReserveStore()
    owner = UnreachedOwner()
    runner = GatewayLifecycle(
        telos=owner,
        phylax=Phylax(),
        agate=owner,
        claude=owner,
        store=store,
        events=EventSink(),
    )

    task = asyncio.create_task(runner.run(request()))
    await store.entered.wait()
    task.cancel()

    # Cancellation must not finish while claim() can still reserve the key.
    await asyncio.sleep(0)
    assert not task.done()
    assert store.aborts == 0

    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert store.aborts == 1
    assert store.in_progress == set()


@pytest.mark.asyncio
async def test_repeated_cancellation_does_not_bypass_claim_cleanup():
    """A second Task.cancel() while the first cancellation's cleanup is
    still draining the claim must not bypass abort(). asyncio.CancelledError
    is a BaseException, not caught by `except Exception`, so a naive cleanup
    path can be interrupted mid-drain by repeated cancellation, leaving the
    key permanently reserved.
    """
    store = ClaimBeforeReserveStore()
    owner = UnreachedOwner()
    runner = GatewayLifecycle(
        telos=owner,
        phylax=Phylax(),
        agate=owner,
        claude=owner,
        store=store,
        events=EventSink(),
    )

    task = asyncio.create_task(runner.run(request()))
    await store.entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()

    assert not task.done()
    assert store.aborts == 0

    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert store.aborts == 1
    assert store.in_progress == set()
