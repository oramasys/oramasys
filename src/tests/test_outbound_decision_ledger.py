"""Durable JSON-lines outbound decision ledger tests.

Follow-up lane for the 2026-09-11 outbound-ledger coverage review
(references/2026-09-11-oramasys-consumer-pin-and-outbound-ledger-review.md,
Finding 2). Covers JsonlOutboundLedger in isolation: an append-only per-run
dispatch record persists to disk, survives concurrent writers without
interleaving corruption, and a malformed line surfaces loudly rather than
being silently skipped.

This class is not wired into build_graph -- the dispatch boundary already
records through orama.providers.ledger.OutboundLedger (a sync Protocol,
in-process by default). See src/tests/test_outbound_ledger.py for that
seam's own coverage, including the bounded-timeout and interrupt-handling
behavior this file originally duplicated against a different (superseded)
wiring design.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from orama.providers.outbound_ledger import JsonlOutboundLedger, OutboundDispatchRecord


def test_ledger_record_defaults_to_utc_timestamp() -> None:
    record = OutboundDispatchRecord(run_id="run-1", outcome="succeeded")

    parsed = datetime.fromisoformat(record.recorded_at)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.now(UTC).utcoffset()


def test_ledger_appends_and_reads_back_in_order(tmp_path: Path) -> None:
    ledger = JsonlOutboundLedger(tmp_path / "outbound.jsonl")
    first = OutboundDispatchRecord(
        run_id="run-1", outcome="succeeded",
        decision_ref="dec-1", provider_ref="prov-1",
    )
    second = OutboundDispatchRecord(run_id="run-2", outcome="failed", error="boom")

    asyncio.run(ledger.record(first))
    asyncio.run(ledger.record(second))

    lines = (tmp_path / "outbound.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["run_id"] for line in lines] == ["run-1", "run-2"]
    assert ledger.read_all() == [first, second]


def test_ledger_rejects_a_malformed_existing_line(tmp_path: Path) -> None:
    path = tmp_path / "outbound.jsonl"
    path.write_text('{"run_id": "run-1", "outcome": "succeeded", "recorded_at": "2026-09-11T00:00:00+00:00"}\nnot json\n', encoding="utf-8")
    ledger = JsonlOutboundLedger(path)

    with pytest.raises(ValueError, match="malformed"):
        ledger.read_all()


def test_ledger_record_calls_fsync_after_flush(tmp_path: Path) -> None:
    """handle.flush() only flushes Python's own buffers; a host failure can
    still lose the entry before it reaches disk without an explicit fsync."""
    ledger = JsonlOutboundLedger(tmp_path / "outbound.jsonl")

    with patch("orama.providers.outbound_ledger.os.fsync") as mock_fsync:
        asyncio.run(ledger.record(OutboundDispatchRecord(run_id="run-1", outcome="succeeded")))

    mock_fsync.assert_called_once()


@pytest.mark.parametrize(
    "bad_line",
    [
        '{"run_id": 7, "outcome": "succeeded", "recorded_at": "2026-09-11T00:00:00+00:00"}',
        '{"run_id": "run-1", "outcome": "sideways", "recorded_at": "2026-09-11T00:00:00+00:00"}',
        '{"run_id": "run-1", "outcome": "succeeded"}',
        '{"run_id": "run-1", "outcome": [], "recorded_at": "2026-09-11T00:00:00+00:00"}',
        '{"run_id": "run-1", "outcome": "succeeded", "recorded_at": "not-a-timestamp"}',
    ],
    ids=["run_id-not-str", "outcome-not-allowed", "missing-recorded_at", "outcome-not-str", "recorded_at-not-iso"],
)
def test_ledger_rejects_syntactically_valid_but_schema_invalid_line(
    tmp_path: Path, bad_line: str
) -> None:
    """A line that parses as JSON but violates the record schema (wrong
    field types, an outcome outside the allowed vocabulary, or a missing/
    invalid recorded_at) must be treated as tampering/corruption too, not
    silently accepted via the dataclass constructor's lack of runtime
    validation."""
    path = tmp_path / "outbound.jsonl"
    path.write_text(bad_line + "\n", encoding="utf-8")
    ledger = JsonlOutboundLedger(path)

    with pytest.raises(ValueError, match="malformed"):
        ledger.read_all()


@pytest.mark.asyncio
async def test_ledger_writes_are_serialized_under_concurrency(tmp_path: Path) -> None:
    ledger = JsonlOutboundLedger(tmp_path / "outbound.jsonl")

    await asyncio.gather(
        *(
            ledger.record(OutboundDispatchRecord(run_id=f"run-{i}", outcome="succeeded"))
            for i in range(16)
        )
    )

    lines = (tmp_path / "outbound.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 16
    run_ids = {json.loads(line)["run_id"] for line in lines}
    assert run_ids == {f"run-{i}" for i in range(16)}
