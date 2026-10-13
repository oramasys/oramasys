"""Observer identity comes from the bound authority, never from guessed constructor strings."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from perpetua_core import PerpetuaState
from perpetua_core.graph.engine import GraphEvent, GraphObservation

from orama.graph.bounded_observer import BoundedObserver, OrderedEvent
from orama.graph.execution_guard import UnknownDisposition


@dataclass(frozen=True)
class _Hold:
    """The identity fields an authoritative hold exposes."""

    attempt_id: str
    hold_id: str
    fence_epoch: int


def _observation() -> GraphObservation:
    """One minimal observation to push through the observer."""
    return GraphObservation(
        GraphEvent("node.end", node="a", steps=1), PerpetuaState(session_id="s")
    )


async def _failing(event: OrderedEvent) -> None:
    """A critical sink that always rejects its boundary."""
    raise RuntimeError("persistence unavailable")


async def test_bound_authority_supplies_every_unsettled_identity() -> None:
    """Each held attempt becomes one disposition, persisted through the hook."""
    persisted: list[UnknownDisposition] = []
    observer = BoundedObserver(run_id="run-1")
    observer.register_sink("audit", _failing, critical=True)
    observer.bind_authority(
        identity_source=lambda: [_Hold("a1", "h1", 3), _Hold("a2", "h2", 3)],
        on_unknown=persisted.append,
    )

    with pytest.raises(RuntimeError, match="persistence unavailable"):
        await observer.on_observation(_observation())

    assert [(d.attempt_id, d.hold_id, d.fence_epoch) for d in persisted] == [
        ("a1", "h1", 3),
        ("a2", "h2", 3),
    ]
    assert observer.unknown_dispositions == persisted
    assert not observer.healthy()


async def test_an_empty_bound_authority_is_not_overridden_by_constructor_guesses() -> None:
    """When the authority names nothing unsettled, no identity is invented."""
    observer = BoundedObserver(run_id="run-1", attempt_id="guess", hold_id="guess", fence_epoch=9)
    observer.register_sink("audit", _failing, critical=True)
    observer.bind_authority(identity_source=lambda: [], on_unknown=lambda d: None)

    with pytest.raises(RuntimeError, match="persistence unavailable"):
        await observer.on_observation(_observation())

    assert observer.unknown_dispositions == []
    assert not observer.healthy()


async def test_a_failing_persistence_hook_never_masks_the_sink_failure() -> None:
    """The original failure propagates and the unpersisted record is kept, not lost."""

    def refuse(_: UnknownDisposition) -> None:
        """Simulate a fenced or conflicting durable write."""
        raise ValueError("unknown disposition does not match its hold")

    observer = BoundedObserver(run_id="run-1")
    observer.register_sink("audit", _failing, critical=True)
    observer.bind_authority(identity_source=lambda: [_Hold("a1", "h1", 3)], on_unknown=refuse)

    with pytest.raises(RuntimeError, match="persistence unavailable"):
        await observer.on_observation(_observation())

    assert [d.attempt_id for d in observer.unpersisted_dispositions] == ["a1"]


async def test_a_failing_identity_source_never_masks_the_sink_failure() -> None:
    """An authority read error leaves the circuit tripped and the failure intact."""

    def unavailable() -> list[_Hold]:
        """Simulate the ledger being unreadable at trip time."""
        raise OSError("ledger unavailable")

    observer = BoundedObserver(run_id="run-1")
    observer.register_sink("audit", _failing, critical=True)
    observer.bind_authority(identity_source=unavailable, on_unknown=lambda d: None)

    with pytest.raises(RuntimeError, match="persistence unavailable"):
        await observer.on_observation(_observation())

    assert not observer.healthy()


def test_authority_cannot_be_rebound_to_a_different_source() -> None:
    """Identity is bound once per run; a second binding is a programming error."""
    observer = BoundedObserver(run_id="run-1")
    observer.bind_authority(identity_source=lambda: [], on_unknown=lambda d: None)

    with pytest.raises(RuntimeError, match="already bound"):
        observer.bind_authority(identity_source=lambda: [], on_unknown=lambda d: None)
