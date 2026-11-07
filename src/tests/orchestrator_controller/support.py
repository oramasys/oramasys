"""Shared builders for the controller tests: a fake clock, requests and stores."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from orama.orchestrator_controller.envelope import ClaimRequest
from orama.orchestrator_controller.store import Admission, ControllerStore

BASE_SHA = "0123456789abcdef0123456789abcdef01234567"
SOURCE_REF = "refs/heads/reviewed"
PAYLOAD_DIGEST = "f" * 64
RESULT_DIGEST = "e" * 64
START = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
DROP = object()  # sentinel: remove this field from a raw request


@dataclass
class FakeClock:
    """A controllable, timezone-aware clock injected into the controller."""

    now: datetime = field(default_factory=lambda: START)

    def __call__(self) -> datetime:
        """Return the current fake time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the fake time forward (or backward with a negative value)."""
        self.now = self.now + timedelta(seconds=seconds)


def open_store(
    tmp_path: Path, clock: FakeClock | None = None, *, ttl: float = 30.0, name: str = "controller.db"
) -> ControllerStore:
    """Open a controller store in a private directory under ``tmp_path``."""
    return ControllerStore(
        tmp_path / "state" / name,
        clock=clock or FakeClock(),
        lease_ttl=timedelta(seconds=ttl),
    )


def declare(store: ControllerStore, task_id: str = "task-1", *, effect_class: str = "pure") -> None:
    """Declare one task with the shared source line."""
    store.declare_task(
        task_id,
        source_ref=SOURCE_REF,
        expected_base_sha=BASE_SHA,
        payload_digest=PAYLOAD_DIGEST,
        effect_class=effect_class,
    )


def raw(operation: str = "claim", **overrides: Any) -> dict[str, Any]:
    """Return a valid raw request mapping for ``operation`` with overrides applied."""
    body: dict[str, Any] = {
        "schema_version": "1",
        "operation": operation,
        "task_id": "task-1",
        "principal": "agent-a",
        "idempotency_key": f"key-{operation}",
        "expected_task_version": 1,
        "source_ref": SOURCE_REF,
        "expected_base_sha": BASE_SHA,
        "capability_proof": "proof-secret-material",
    }
    if operation == "complete":
        body["result_digest"] = RESULT_DIGEST
    if operation == "fail":
        body["failure_class"] = "worker_error"
    body.update(overrides)
    return {key: value for key, value in body.items() if value is not DROP}


def request(operation: str = "claim", **overrides: Any) -> ClaimRequest:
    """Parse a valid request for ``operation`` with overrides applied."""
    return ClaimRequest.from_mapping(raw(operation, **overrides))


def lease_request(operation: str, receipt: Any, **overrides: Any) -> ClaimRequest:
    """Build a lease-bound request that presents ``receipt``'s lease."""
    body: dict[str, Any] = {
        "lease_id": receipt.lease_id,
        "lease_token": receipt.lease_token,
        "expected_task_version": receipt.task_version,
    }
    body.update(overrides)
    return request(operation, **body)


def admitted(principal: str = "agent-a") -> Admission:
    """Return the admission a verified principal would carry into the store."""
    return Admission(principal_id=principal)


def table_snapshot(store: ControllerStore, *tables: str) -> Mapping[str, list[tuple[Any, ...]]]:
    """Return every row of the named tables, for unchanged-state assertions."""
    return {name: store._read_all(name) for name in tables}


CLAIM_TABLES = ("tasks", "leases", "idempotency")
ALL_TABLES = ("tasks", "leases", "idempotency", "outbox", "audit", "maintenance_owner")
