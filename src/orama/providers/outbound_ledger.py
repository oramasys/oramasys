"""Append-only outbound decision ledger.

Per-run audit journal of provider dispatches through the graph boundary:
enough to correlate who was called, under which Telos decision, with what
outcome, without becoming a second policy authority. It is deliberately not
the Tier-5 financial reservation/settlement ledger. The schema stays narrow
on purpose — routing and policy evaluation remain in the graph and Telos
respectively, while paid-call accounting remains a separate SQLite authority.

Records are JSON-lines, one per dispatch, written under an asyncio lock so
concurrent run_ids cannot interleave a line. ``read_all`` parses strictly: a
malformed line means tampering or disk corruption and must surface, not be
silently skipped — append-only evidence is only worth keeping if damage is
loud.

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
                records.append(OutboundDispatchRecord(**payload))
            except (json.JSONDecodeError, TypeError) as exc:
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
