"""Adversarial and real-process qualification of the sealed inert driver (DRAFT, not a gate closure).

The crash cases run a fresh interpreter that dies with ``os._exit`` at a durable boundary; nothing
here mocks a crash. Same PYTHONPATH pattern as the #77 crash harness so the checkout under test is
what the child imports.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_reconciliation import startup_reconciliation_report
from orama.graph.final_boundary import FinalBoundaryRefused
from orama.graph.sealed_inert_driver import SealedDriverRefused
from tests.test_dispatch_attempts import ATTEMPT, ISSUER, NOW, Harness
from tests.test_effect_fencing import Operator
from tests.test_final_boundary import binding
from tests.test_inert_effect_integration import inert_harness
from tests.test_sealed_inert_driver import Recorder, driver, envelope, send

CRASH_EXIT = 77


def _crash_worker(directory: Path, boundary: str) -> None:
    """Run the sealed send and die without cleanup at the named durable boundary."""
    h = inert_harness(directory)
    h.store.grant_effect_approval(binding(), approver=Operator(), now=NOW)
    if boundary == "after_send_marker":
        h.store.begin_bound_send(binding(), NOW, issuer_id=ISSUER)
        os._exit(CRASH_EXIT)
    if boundary == "during_settle":
        touched = False

        def trace(sql: str) -> None:
            """Exit after the outcome write executes but before SQLite commits it."""
            nonlocal touched
            if "update outbox set outcome" in sql.lower():
                touched = True
            if touched and sql.strip().upper() == "COMMIT":
                os._exit(CRASH_EXIT)

        h.store._db.set_trace_callback(trace)

    def die(receipt) -> None:
        """Publisher that kills the process once the receipt is durable but unpublished."""
        os._exit(CRASH_EXIT)

    publisher = die if boundary == "after_receipt_write" else (
        (lambda receipt: None) if boundary == "after_receipt_publication" else None
    )
    d = driver(h, publisher=publisher)
    send(d)
    if boundary == "after_receipt_publication":
        os._exit(CRASH_EXIT)
    raise AssertionError(f"boundary not reached: {boundary}")


def _run(tmp_path: Path, boundary: str) -> None:
    """Run the crash worker in a fresh interpreter and require the crash exit code."""
    result = subprocess.run(
        [sys.executable, "-c",
         "from pathlib import Path; import sys; "
         "from tests.test_sealed_effect_qualification import _crash_worker; "
         "_crash_worker(Path(sys.argv[1]), sys.argv[2])", str(tmp_path), boundary],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == CRASH_EXIT, result.stderr


def _reopen(tmp_path: Path) -> Harness:
    """Reopen the crashed store with fresh fakes (the child's in-memory state is gone)."""
    from tests.test_dispatch_attempts import FakeGates, FakeRevocations, FakeVerifier

    path = tmp_path / "inert.sqlite"
    return Harness(SqliteAttemptStore(path, governed=True), path, FakeVerifier(), FakeGates(),
                   FakeRevocations())


@pytest.mark.parametrize("boundary", ["after_send_marker", "during_settle"])
def test_crash_after_dispatch_and_before_receipt_is_unknown_and_not_retried(
    tmp_path: Path, boundary: str
) -> None:
    """Death between the send marker and a committed receipt leaves unknown; restart reports it."""
    _run(tmp_path, boundary)
    h = _reopen(tmp_path)
    try:
        row = h.store.outbox_row(ATTEMPT)
        assert (row["send_started"], row["outcome"], row["outcome_evidence"]) == (1, "unknown", None)
        assert h.store.receipt(ATTEMPT) is None
        assert h.store.approval_state(ATTEMPT) == "consumed"
        assert len(startup_reconciliation_report(h.store).in_doubt) == 1
        sim = Recorder()
        with pytest.raises(FinalBoundaryRefused, match="send_already_started"):
            send(driver(h, simulation=sim))
        assert sim.calls == 0
    finally:
        h.store.close()


@pytest.mark.parametrize("boundary", ["after_receipt_write", "after_receipt_publication"])
def test_crash_after_receipt_write_or_publication_reconciles_to_the_durable_receipt(
    tmp_path: Path, boundary: str
) -> None:
    """Restart returns the stored receipt, dispatches nothing, and finishes pending publication."""
    _run(tmp_path, boundary)
    h = _reopen(tmp_path)
    try:
        stored = h.store.receipt(ATTEMPT)
        assert stored is not None and stored.receipt.outcome == "confirmed"
        assert (stored.published_at is not None) == (boundary == "after_receipt_publication")
        assert startup_reconciliation_report(h.store).in_doubt == ()
        sim, seen = Recorder(), []
        d = driver(h, simulation=sim, publisher=seen.append)
        assert send(d) == stored.receipt and sim.calls == 0
        assert d.publish_pending() == (0 if stored.published_at else 1)
        assert h.store.receipt(ATTEMPT).published_at is not None
        assert h.store._db.execute("SELECT count(*) FROM effect_receipts").fetchone() == (1,)
        with pytest.raises(SealedDriverRefused, match="replay_envelope_mismatch"):
            send(d, envelope(epoch=6))
        assert sim.calls == 0
    finally:
        h.store.close()


def test_stale_epoch_after_restart_refuses_and_never_dispatches(tmp_path: Path) -> None:
    """The fencing epoch advanced while the process was down; the old attempt is stale."""
    h = inert_harness(tmp_path)
    h.store.grant_effect_approval(binding(), approver=Operator(), now=NOW)
    h.store.close()
    h = _reopen(tmp_path)
    try:
        h.store.advance_fencing_epoch(6, operator=Operator(), now=NOW)
        sim = Recorder()
        with pytest.raises(FinalBoundaryRefused) as excinfo:
            send(driver(h, simulation=sim))
        assert excinfo.value.reason == "epoch_stale" and sim.calls == 0
        assert h.store.outbox_row(ATTEMPT)["send_started"] == 0
        assert h.store.approval_state(ATTEMPT) == "granted"
    finally:
        h.store.close()


def test_two_processes_double_submit_dispatch_exactly_once(tmp_path: Path) -> None:
    """Two fresh interpreters race the same sealed envelope; one send, one receipt."""
    h = inert_harness(tmp_path)
    h.store.grant_effect_approval(binding(), approver=Operator(), now=NOW)
    h.store.close()
    source = (
        "import sys; from pathlib import Path\n"
        "from tests.test_sealed_effect_qualification import _reopen, driver, send\n"
        "from orama.graph.effect_outcomes import OutcomeRefused\n"
        "h = _reopen(Path(sys.argv[1]))\n"
        "try:\n"
        "    print('sent' if send(driver(h)) else 'none')\n"
        "except OutcomeRefused:\n"
        "    print('refused')\n"
        "finally:\n"
        "    h.store.close()\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    workers = [subprocess.Popen([sys.executable, "-c", source, str(tmp_path)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
               for _ in range(2)]
    outputs = []
    try:
        for w in workers:
            out, err = w.communicate(timeout=60)
            assert w.returncode == 0, err
            outputs.append(out.strip())
    finally:
        for w in workers:
            if w.poll() is None:
                w.kill()
            w.wait(timeout=10)
    assert "sent" in outputs and set(outputs) <= {"sent", "refused"}
    reopened = _reopen(tmp_path)
    try:
        assert reopened.store.outbox_row(ATTEMPT)["outcome"] == "confirmed"
        assert reopened.store._db.execute("SELECT count(*) FROM effect_receipts").fetchone() == (1,)
    finally:
        reopened.store.close()
