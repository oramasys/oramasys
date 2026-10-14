"""Crash-window evidence: a real admitted run is SIGKILLed at named points.

Each test runs the production AdmissionGraphRunner, StepLedger and RunControl in a
child process, kills it at a window, then reopens the shared store from this
process. Assertions are on durable state and a witness file, never on mocks.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from orama.graph.execution_guard import LeaseFenced, StepLedger
from orama.graph.run_control import RunControl

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(signal, "SIGKILL"),
    reason="needs POSIX SIGKILL and signal.pause",
)

SRC_DIR = str(Path(__file__).resolve().parents[1])
DEADLINE_SECONDS = 15.0

CHILD = textwrap.dedent(
    """
    import asyncio, signal, sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    from perpetua_core import END, START, MiniGraph, PerpetuaState
    from tests.core_gate.test_admitted_observation_delivery import _runner
    tmp, window = Path(sys.argv[2]), sys.argv[3]

    def hold(marker):
        print(marker, flush=True)
        signal.pause()

    class Delivery:
        def __init__(self, run_id):
            print("RUN_ID", run_id, flush=True)
        def healthy(self):
            return True
        async def on_observation(self, observation):
            if window == "in-sink" and str(observation.event.kind) == "node.end":
                hold("AT-WINDOW")

    def node_a(state):
        with open(tmp / "calls.txt", "a") as handle:
            handle.write("a\\n")
        if window == "in-node":
            hold("AT-WINDOW")
        return {"scratchpad": {"a": True}}

    graph = MiniGraph()
    graph.add_node("a", node_a)
    graph.add_edge(START, "a").add_edge("a", END)
    runner, ledger, run_control, store = _runner(tmp, lambda run_id: Delivery(run_id))
    invoker = runner.for_authenticated_principal("control-plane")
    asyncio.run(invoker.invoke(graph.compile(), PerpetuaState(session_id="run-1")))
    print("COMPLETED", flush=True)
    """
)


def _read_until_marker(proc: subprocess.Popen[str]) -> tuple[str | None, str | None]:
    """Collect RUN_ID and the first window marker, bounded by DEADLINE_SECONDS."""
    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        """Forward child stdout lines, then a sentinel at EOF."""
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.put(line.rstrip("\n"))
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    run_id: str | None = None
    marker: str | None = None
    while True:
        try:
            line = lines.get(timeout=DEADLINE_SECONDS)
        except queue.Empty:
            return run_id, marker
        if line is None:
            return run_id, marker
        if line.startswith("RUN_ID "):
            run_id = line.split()[1]
        elif line in ("AT-WINDOW", "COMPLETED"):
            return run_id, line


def _run_child(tmp_path: Path, window: str, *, kill: bool) -> tuple[str, str | None]:
    """Run the child to a window, optionally SIGKILL it, and return run id and marker."""
    proc = subprocess.Popen(
        [sys.executable, "-I", "-u", "-c", CHILD, SRC_DIR, str(tmp_path), window],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=SRC_DIR,
        env={**os.environ, "PYTHONPATH": SRC_DIR},
    )
    run_id, marker = _read_until_marker(proc)
    if proc.poll() is None:
        if kill:
            os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=DEADLINE_SECONDS)
    assert run_id is not None, "child never reported a run id"
    return run_id, marker


def _witness(tmp_path: Path) -> list[str]:
    """Read the node-execution witness file (one line per execution)."""
    path = tmp_path / "calls.txt"
    return path.read_text().split() if path.exists() else []


def _hold_states(ledger: StepLedger, run_id: str) -> dict[str, str]:
    """Return attempt id to hold state for one run, straight from the store."""
    rows = ledger._db.execute(  # noqa: SLF001 - evidence read of the durable store
        "SELECT attempt_id, state FROM attempt_holds WHERE run_id=?", (run_id,)
    ).fetchall()
    return {attempt: state for attempt, state in rows}


def test_kill_inside_node_leaves_unknown_hold_and_no_terminal(tmp_path: Path) -> None:
    """A SIGKILL inside the node leaves a STARTED attempt that recovery marks unknown."""
    run_id, marker = _run_child(tmp_path, "in-node", kill=True)
    assert marker == "AT-WINDOW"
    store = tmp_path / "shared.sqlite3"
    run_control = RunControl(store_path=store)
    ledger = StepLedger(store)
    try:
        assert run_control.terminal_receipt(run_id) is None
        epoch = ledger.open_lease(run_id, max_steps=8)
        recovery = ledger.recover_accounting(run_id, epoch)
        assert list(recovery.unknown) == ["node::a::0"]
        assert list(recovery.released) == []
        assert _hold_states(ledger, run_id) == {"node::a::0": "unknown"}
        assert run_control.terminal_receipt(run_id) is None
        assert _witness(tmp_path) == ["a"]
    finally:
        ledger.close()
        run_control.close()


def test_kill_in_sink_after_node_end_settles_accounting_without_terminal(
    tmp_path: Path,
) -> None:
    """A SIGKILL in the observation sink leaves the node settled but no terminal."""
    run_id, marker = _run_child(tmp_path, "in-sink", kill=True)
    assert marker == "AT-WINDOW"
    store = tmp_path / "shared.sqlite3"
    run_control = RunControl(store_path=store)
    ledger = StepLedger(store)
    try:
        epoch = ledger.open_lease(run_id, max_steps=8)
        recovery = ledger.recover_accounting(run_id, epoch)
        assert list(recovery.unknown) == []
        assert _hold_states(ledger, run_id) == {"node::a::0": "settled"}
        assert run_control.terminal_receipt(run_id) is None
        assert _witness(tmp_path) == ["a"]
    finally:
        ledger.close()
        run_control.close()


def test_completed_run_lease_fences_takeover_and_terminal_is_unchanged(
    tmp_path: Path,
) -> None:
    """After a normal completion, take-over is fenced and the terminal stays put."""
    run_id, marker = _run_child(tmp_path, "none", kill=False)
    assert marker == "COMPLETED"
    store = tmp_path / "shared.sqlite3"
    run_control = RunControl(store_path=store)
    ledger = StepLedger(store)
    try:
        before = run_control.terminal_receipt(run_id)
        assert before is not None
        with pytest.raises(LeaseFenced):
            ledger.open_lease(run_id, max_steps=8)
        after = run_control.terminal_receipt(run_id)
        assert after == before
        assert _witness(tmp_path) == ["a"]
    finally:
        ledger.close()
        run_control.close()


def test_reopen_and_recovery_never_replays_a_node(tmp_path: Path) -> None:
    """Reopening and recovering accounting starts no node: one execution in total."""
    run_id, _ = _run_child(tmp_path, "in-node", kill=True)
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    try:
        epoch = ledger.open_lease(run_id, max_steps=8)
        ledger.recover_accounting(run_id, epoch)
        again = ledger.open_lease(run_id, max_steps=8)
        ledger.recover_accounting(run_id, again)
    finally:
        ledger.close()
    assert _witness(tmp_path) == ["a"]
