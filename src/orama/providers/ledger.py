"""Append-only outbound decision ledger.

Records one entry per outbound provider dispatch attempt (success, contained
failure, or timeout) so an audit can correlate run_id -> Telos decision_ref ->
provider outcome. Entries are append-only per the migration-debt program
control ("preserve historical records append-only"); this module never edits
or removes records, and it never performs network I/O itself.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

OUTCOME_SUCCESS = "success"
OUTCOME_FAILED = "failed"
OUTCOME_TIMEOUT = "timeout"


def _utc_now_iso() -> str:
    # Migration-debt program control: use UTC in generated evidence.
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class OutboundLedgerEntry:
    """One outbound dispatch attempt, as recorded at the dispatch boundary."""

    run_id: str
    backend_name: str
    model: str
    outcome: str
    decision_ref: str | None = None
    provider_ref: str | None = None
    policy_version: str | None = None
    #: Exception *type name* only -- never str(exc), which can carry endpoint
    #: URLs or provider payloads into audit records.
    reason: str | None = None
    recorded_at: str = ""


class OutboundLedger(Protocol):
    def record(self, entry: OutboundLedgerEntry) -> None: ...

    def entries(self) -> tuple[OutboundLedgerEntry, ...]: ...


class InMemoryOutboundLedger:
    """Thread-safe, append-only in-memory ledger implementation."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[OutboundLedgerEntry] = []

    def record(self, entry: OutboundLedgerEntry) -> None:
        stamped = entry
        if not entry.recorded_at:
            stamped = replace(entry, recorded_at=_utc_now_iso())
        with self._lock:
            self._entries.append(stamped)

    def entries(self) -> tuple[OutboundLedgerEntry, ...]:
        with self._lock:
            return tuple(self._entries)
