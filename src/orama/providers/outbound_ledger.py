"""Append-only outbound decision ledger.

Per-run audit journal of provider dispatches through the graph boundary:
enough to correlate who was called, under which Telos decision, with what
outcome, without becoming a second policy authority. It is deliberately not
the Tier-5 financial reservation/settlement ledger. The schema stays narrow
on purpose — routing and policy evaluation remain in the graph and Telos
respectively, while paid-call accounting remains a separate SQLite authority.

Records are JSON-lines, one per dispatch, written under an in-process
asyncio lock so concurrent run_ids within the SAME process cannot
interleave a line -- this does not coordinate multiple OS processes
writing to the same path; see JsonlOutboundLedger's own docstring.
``read_all`` parses and validates strictly: a malformed line, or a
syntactically valid line that violates the record schema (wrong field
types, an outcome outside the allowed vocabulary, a missing/invalid
recorded_at), means tampering or disk corruption and must surface, not
be silently skipped — append-only evidence is only worth keeping if
damage is loud.

This module is a standalone durable-persistence utility. It is not currently
wired into ``build_graph``: the graph boundary already records dispatches
through ``orama.providers.ledger.OutboundLedger`` (a sync Protocol, richer
entry schema, in-process by default via ``InMemoryOutboundLedger``). Wiring
durable JSON-lines persistence into that same seam is a follow-up seam
decision, not a merge-conflict fix -- it would mean either adapting this
class's async interface to the sync Protocol, or making the dispatch-node
recording call async-aware, either of which changes behavior beyond
resolving the conflict between the two branches this file came from.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_ALLOWED_OUTCOMES = frozenset({"succeeded", "failed"})


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True, slots=True)
class OutboundDispatchRecord:
    """One provider dispatch through the graph boundary."""

    run_id: str
    outcome: str  # "succeeded" | "failed"
    decision_ref: str = ""
    provider_ref: str = ""
    telos_policy_version: str | None = None
    # Exception type name only. Never persist exception text: it may contain
    # endpoint URLs, credentials, or provider payload fragments.
    error: str | None = None
    recorded_at: str = field(default_factory=_utc_now_iso)


def _validate_persisted_payload(payload: dict[str, Any]) -> None:
    """Enforce the on-disk record schema at readback.

    ``OutboundDispatchRecord(**payload)`` alone does not enforce field
    types or the outcome vocabulary at runtime -- a syntactically valid
    JSON line with ``run_id: 7`` or ``outcome: "sideways"`` would otherwise
    construct successfully, and a line missing ``recorded_at`` would
    silently receive a *fresh* timestamp from the dataclass's
    default_factory instead of surfacing that the persisted value is gone.
    Both defeat the "loud on tampering/corruption" contract this ledger
    documents. Validate explicitly before construction instead.
    """
    if not isinstance(payload.get("run_id"), str):
        raise ValueError("run_id must be a string")
    if payload.get("outcome") not in _ALLOWED_OUTCOMES:
        raise ValueError(f"outcome must be one of {sorted(_ALLOWED_OUTCOMES)}")
    for field_name in ("decision_ref", "provider_ref", "telos_policy_version", "error"):
        value = payload.get(field_name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string or null")
    recorded_at = payload.get("recorded_at")
    if not isinstance(recorded_at, str):
        raise ValueError("recorded_at is required and must be a string")
    try:
        datetime.fromisoformat(recorded_at)
    except ValueError as exc:
        raise ValueError(f"recorded_at is not a valid ISO timestamp: {exc}") from exc


class JsonlOutboundLedger:
    """JSON-lines append-only ledger of outbound provider dispatches.

    Renamed from OutboundLedger (its original PR name) to avoid colliding
    with the in-process orama.providers.ledger.OutboundLedger Protocol this
    branch already wires into build_graph(outbound_ledger=...). This class
    does not (yet) satisfy that Protocol -- its record() is async and its
    read accessor is read_all(), not entries() -- so it is a standalone
    durable audit-log utility, not a drop-in implementation of that seam.
    """

    def __init__(self, path: Path | str) -> None:
        # Single-writer-process restriction: self._lock is an in-process
        # asyncio.Lock, so it serializes concurrent writers only within
        # this Python process. It does not coordinate writers in separate
        # OS processes sharing the same ledger path -- a genuine
        # inter-process lock (e.g. fcntl.flock, which is POSIX-only and
        # not portable to Windows without a separate code path) is a
        # larger, platform-specific addition than this class currently
        # needs. If a future caller genuinely needs multiple processes
        # appending to the same ledger file concurrently, that support
        # must be added deliberately, not assumed to already exist here.
        self._path = Path(path)
        self._lock = asyncio.Lock()

    async def record(self, record: OutboundDispatchRecord) -> None:
        """Append one record as a single JSON line, serialized under lock."""
        line = json.dumps(
            {
                "run_id": record.run_id,
                "outcome": record.outcome,
                "decision_ref": record.decision_ref,
                "provider_ref": record.provider_ref,
                "telos_policy_version": record.telos_policy_version,
                "error": record.error,
                "recorded_at": record.recorded_at,
            },
            ensure_ascii=False,
        )
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                # flush() only moves data out of Python's own buffers into
                # the OS page cache; a host crash before the OS itself
                # writes that page to disk can still lose the entry. This
                # class is documented as a durable audit log, so force the
                # write out with fsync rather than leaving that gap.
                os.fsync(handle.fileno())

    def read_all(self) -> list[OutboundDispatchRecord]:
        """Parse every record back, strictly. Raises ValueError on any malformed line."""
        if not self._path.exists():
            return []
        records: list[OutboundDispatchRecord] = []
        for line_number, line in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                payload: dict[str, Any] = json.loads(line)
                _validate_persisted_payload(payload)
                records.append(OutboundDispatchRecord(**payload))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"malformed ledger line {line_number} in {self._path}: {exc}"
                ) from exc
        return records


def default_ledger_path() -> Path:
    """Operator-overridable location for the durable ledger file."""
    override = os.environ.get("ORAMASYS_OUTBOUND_LEDGER")
    if override:
        return Path(override)
    return Path.home() / ".oramasys" / "outbound-decisions.jsonl"
