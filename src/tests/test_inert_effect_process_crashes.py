"""Process-death evidence for the inert driver, not production grant qualification."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_outcomes import OutcomeRefused
from orama.graph.inert_effect_driver import InertEffectDriver
from tests.test_effect_seam import ATTEMPT, SCOPE, authorize
from tests.test_inert_effect_integration import inert_harness

CRASH_EXIT = 73


def _crash_worker(directory: Path, boundary: str) -> None:
    """Exit without connection cleanup at a real transaction or driver boundary."""
    h = inert_harness(directory, authorize_attempt=False)
    if boundary == "before_authorization":
        os._exit(CRASH_EXIT)
    statement = {
        "during_authorization": "INSERT INTO outbox",
        "during_begin_send": "UPDATE outbox SET send_started",
        "during_outcome": "UPDATE outbox SET outcome",
    }.get(boundary)
    if statement is not None:
        transaction_touched = False

        def crash_on_statement(sql: str) -> None:
            """Exit after the target write executes but before SQLite commits it."""
            nonlocal transaction_touched
            if statement.lower() in sql.lower():
                transaction_touched = True
            if transaction_touched and sql.strip().upper() == "COMMIT":
                os._exit(CRASH_EXIT)
        h.store._db.set_trace_callback(crash_on_statement)
    authorize(h, replace(SCOPE, destination="inert://simulation"))
    if boundary == "after_authorization":
        os._exit(CRASH_EXIT)
    if boundary == "after_begin_send":
        h.store.begin_send(ATTEMPT, inert_only=True)
        os._exit(CRASH_EXIT)
    InertEffectDriver(h.store).send(ATTEMPT)
    if boundary == "after_outcome":
        os._exit(CRASH_EXIT)
    raise AssertionError(f"crash boundary was not reached: {boundary}")


@pytest.mark.parametrize("boundary", [
    "before_authorization", "during_authorization", "after_authorization",
    "during_begin_send", "after_begin_send", "during_outcome", "after_outcome",
])
def test_inert_process_crash_preserves_atomicity_and_single_use(
    tmp_path: Path, boundary: str,
) -> None:
    """Reopen after abrupt process death; uncertain sends never become retryable."""
    result = subprocess.run(
        [sys.executable, "-c",
         "from pathlib import Path; import sys; "
         "from tests.test_inert_effect_process_crashes import _crash_worker; "
         "_crash_worker(Path(sys.argv[1]), sys.argv[2])", str(tmp_path), boundary],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == CRASH_EXIT, result.stderr
    store = SqliteAttemptStore(tmp_path / "inert.sqlite", governed=True)
    try:
        row = store.outbox_row(ATTEMPT)
        if boundary in {"before_authorization", "during_authorization"}:
            assert row is None
            assert store._db.execute("SELECT count(*) FROM grant_use").fetchone() == (0,)
            assert store._db.execute("SELECT count(*) FROM dispatch_intents").fetchone() == (0,)
            assert store._db.execute(
                "SELECT consumed_attempt_id FROM reservations"
            ).fetchone() == (None,)
            return
        assert row is not None
        assert store._db.execute("SELECT count(*) FROM grant_use").fetchone() == (1,)
        assert store._db.execute("SELECT count(*) FROM dispatch_intents").fetchone() == (1,)
        if boundary in {"after_authorization", "during_begin_send"}:
            assert row["send_started"] == 0
            assert row["outcome"] == "unknown"
            assert InertEffectDriver(store).send(ATTEMPT) == "inert-simulation:v1"
        else:
            assert row["send_started"] == 1
            assert row["outcome"] == (
                "confirmed" if boundary == "after_outcome" else "unknown"
            )
            if row["outcome"] == "unknown":
                assert row["outcome_evidence"] is None
        with pytest.raises(OutcomeRefused):
            InertEffectDriver(store).send(ATTEMPT)
    finally:
        store.close()


def test_two_processes_cannot_send_the_same_inert_attempt(tmp_path: Path) -> None:
    """SQLite serializes competing senders across separate process connections."""
    h = inert_harness(tmp_path)
    h.store.close()
    source = (
        "import sys; from orama.graph.dispatch_attempts import SqliteAttemptStore; "
        "from orama.graph.inert_effect_driver import InertEffectDriver; "
        "from orama.graph.effect_outcomes import OutcomeRefused; "
        "store = SqliteAttemptStore(sys.argv[1], governed=True)\n"
        "try:\n"
        "    InertEffectDriver(store).send(sys.argv[2])\n"
        "    print('sent')\n"
        "except OutcomeRefused:\n"
        "    print('refused')\n"
        "finally:\n"
        "    store.close()\n"
    )
    workers = []
    try:
        for _ in range(2):
            workers.append(subprocess.Popen(
                [sys.executable, "-c", source, str(h.path), ATTEMPT],
                # Same source path as the crash worker: without it a stale
                # non-editable install would be imported instead of src/.
                env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        outcomes = []
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=30)
            assert worker.returncode == 0, stderr
            outcomes.append(stdout.strip())
        assert sorted(outcomes) == ["refused", "sent"]
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=10)
    reopened = SqliteAttemptStore(h.path, governed=True)
    try:
        row = reopened.outbox_row(ATTEMPT)
        assert row["send_started"] == 1
        assert row["outcome"] == "confirmed"
    finally:
        reopened.close()
