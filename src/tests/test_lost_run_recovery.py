"""Explicit, fenced takeover of a run whose process was lost.

A SIGKILLed run leaves no terminal receipt: only the running ``AdmissionGraphRunner`` writes one.
``recover_lost_run`` is the operator-invoked answer. It takes the lease over (fencing the old holder),
lets accounting recovery classify holds without invoking anything, and records a conservative
terminal. It never replays a node, never creates a lease for an unknown run, and is idempotent.
"""

from __future__ import annotations

import os
import queue
import signal
import sqlite3
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from orama.graph.execution_guard import LeaseFenced, StepLedger
from orama.graph.lost_run_recovery import LOST_RUN_REASON, LostRunRefused, recover_lost_run
from orama.graph.run_control import RunControl

ROOT = Path(__file__).resolve().parents[2]
OWNER = "control-plane"

CHILD = textwrap.dedent(
    """
    import asyncio, signal, sys
    from pathlib import Path
    from perpetua_core import END, START, MiniGraph, PerpetuaState
    from orama.graph.admission import AdmissionRequirements
    from orama.graph.admission_runtime import AdmissionGraphRunner
    from orama.graph.execution_guard import StepLedger
    from orama.graph.run_control import RunControl
    from tests.test_admission_decision import binding, context, providers

    store_dir, window = sys.argv[1:3]
    tmp = Path(store_dir)

    def mark(name):
        print(name, flush=True)
        signal.pause()

    class Delivery:
        def __init__(self, run_id):
            print("RUN_ID", run_id, flush=True)
        def healthy(self):
            return True
        async def on_observation(self, observation):
            if window == "in-sink" and str(observation.event.kind) == "node.end":
                mark("IN-SINK")

    def node_a(state):
        with open(tmp / "calls.txt", "a") as handle:
            handle.write("a\\n")
        if window == "in-node":
            mark("IN-NODE")
        return {"scratchpad": {"a": True}}

    graph = MiniGraph()
    graph.add_node("a", node_a)
    graph.add_edge(START, "a").add_edge("a", END)
    owner_providers, clock = providers()
    store = tmp / "shared.sqlite3"
    runner = AdmissionGraphRunner(
        binding=binding(), providers=owner_providers, ledger=StepLedger(store),
        run_control=RunControl(store_path=store), context_from_state=lambda _s: context(run_id="client-run"),
        max_steps=8,
        requirements=AdmissionRequirements.for_effects(model_dispatch=True, endpoint_purposes=("model_egress",)),
        clock=clock, run_delivery_factory=lambda run_id: Delivery(run_id),
    )
    asyncio.run(runner.for_authenticated_principal("control-plane").invoke(graph.compile(), PerpetuaState(session_id="run-1")))
    print("COMPLETED", flush=True)
    """
)


def _child_env() -> dict[str, str]:
    """Import this worktree's sources in the child, exactly as the other crash tests do."""
    env = os.environ.copy()
    paths = [str(ROOT / "src")]
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def _run_child(tmp_path: Path, window: str) -> tuple[str, str | None, int | None]:
    """Run the real runner until ``window`` blocks, SIGKILL it, and return (run_id, marker, rc)."""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", CHILD, str(tmp_path), window],
        cwd=ROOT, env=_child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        """Forward the child's stdout lines to the queue so the parent never blocks on a buffer."""
        assert process.stdout is not None
        for line in process.stdout:
            lines.put(line.rstrip("\n"))
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    run_id = marker = None
    try:
        while True:
            line = lines.get(timeout=30)
            if line is None:
                break
            if line.startswith("RUN_ID"):
                run_id = line.split()[1]
            elif line.startswith("IN-") or line == "COMPLETED":
                marker = line
                break
    except queue.Empty:
        pass
    if process.poll() is None and marker not in (None, "COMPLETED"):
        os.kill(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    assert run_id is not None, f"child never reported a run id: {process.stderr.read() if process.stderr else ''}"
    return run_id, marker, process.returncode


def _open(tmp_path: Path) -> tuple[StepLedger, RunControl]:
    """Open fresh handles on the shared store, as a recovering operator process would."""
    store = tmp_path / "shared.sqlite3"
    return StepLedger(store), RunControl(store_path=store)


def _node_calls(tmp_path: Path) -> list[str]:
    """Return the recorded node executions (the no-replay witness)."""
    marker = tmp_path / "calls.txt"
    return marker.read_text().split() if marker.exists() else []


def _lease_rows(tmp_path: Path) -> list[tuple[str, int]]:
    """Return (run_id, epoch) for every lease in the store."""
    with sqlite3.connect(tmp_path / "shared.sqlite3") as db:
        return [(str(r[0]), int(r[1])) for r in db.execute("SELECT run_id, epoch FROM leases")]


def test_a_run_killed_in_its_node_gets_a_conservative_terminal_without_replay(tmp_path: Path) -> None:
    """Real SIGKILL inside the node after durable START: unknown terminal, unresolved attempt, no replay."""
    run_id, marker, returncode = _run_child(tmp_path, "in-node")
    assert marker == "IN-NODE" and returncode == -signal.SIGKILL
    ledger, control = _open(tmp_path)
    assert control.terminal_receipt(run_id) is None  # the reported gap: no terminal exists

    receipt = recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER)

    assert receipt.outcome == "unknown"
    assert receipt.reason == LOST_RUN_REASON == "run.process_lost"
    assert receipt.unresolved_attempts == ("node::a::0",)
    assert receipt.epoch == 2
    assert ledger.hold_state(run_id, "node::a::0") == "unknown"
    assert _node_calls(tmp_path) == ["a"]  # takeover invoked nothing
    assert control.terminal_receipt(run_id) == receipt


def test_a_run_killed_during_critical_delivery_is_unknown_with_nothing_unresolved(tmp_path: Path) -> None:
    """All attempts settled but the run never finished: still unknown, never completed."""
    run_id, marker, _ = _run_child(tmp_path, "in-sink")
    assert marker == "IN-SINK"
    ledger, control = _open(tmp_path)

    receipt = recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER)

    assert receipt.outcome == "unknown" and receipt.reason == LOST_RUN_REASON
    assert receipt.unresolved_attempts == ()
    assert ledger.hold_state(run_id, "node::a::0") == "settled"
    assert _node_calls(tmp_path) == ["a"]


def test_recovery_is_idempotent_and_does_not_advance_the_epoch(tmp_path: Path) -> None:
    """A second call returns the same receipt; a retry must not fence anyone again."""
    run_id, _, _ = _run_child(tmp_path, "in-node")
    ledger, control = _open(tmp_path)
    first = recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER)

    ledger2, control2 = _open(tmp_path)
    second = recover_lost_run(ledger=ledger2, run_control=control2, run_id=run_id, principal=OWNER)

    assert second == first
    assert _lease_rows(tmp_path) == [(run_id, 2)]


def test_a_completed_run_is_returned_unchanged(tmp_path: Path) -> None:
    """Recovery never touches a run that already finished."""
    run_id, marker, returncode = _run_child(tmp_path, "none")
    assert marker == "COMPLETED" and returncode == 0
    ledger, control = _open(tmp_path)
    before = control.terminal_receipt(run_id)
    assert before is not None and before.outcome == "completed"

    receipt = recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER)

    assert receipt == before
    assert _lease_rows(tmp_path) == [(run_id, 1)]


def test_an_unknown_run_is_refused_and_no_lease_is_fabricated(tmp_path: Path) -> None:
    """open_lease would create a lease for any id; recovery must refuse before reaching it."""
    ledger, control = _open(tmp_path)

    with pytest.raises(LostRunRefused):
        recover_lost_run(ledger=ledger, run_control=control, run_id="never-existed", principal=OWNER)

    assert _lease_rows(tmp_path) == []
    assert control.terminal_receipt("never-existed") is None


def test_an_owned_run_with_no_lease_is_refused_and_no_lease_is_created(tmp_path: Path) -> None:
    """Killed between owner registration and lease open: nothing started, nothing to recover."""
    ledger, control = _open(tmp_path)
    control.register_run(run_id="owned-but-never-leased", owner_principal=OWNER)

    with pytest.raises(LostRunRefused) as refusal:
        recover_lost_run(ledger=ledger, run_control=control, run_id="owned-but-never-leased", principal=OWNER)

    assert refusal.value.code == "run.no_lease"
    assert _lease_rows(tmp_path) == []
    assert control.terminal_receipt("owned-but-never-leased") is None


def test_a_non_owner_is_refused_and_the_run_is_untouched(tmp_path: Path) -> None:
    """Same authority rule as stop: only the run's registered owner may take it over."""
    run_id, _, _ = _run_child(tmp_path, "in-node")
    ledger, control = _open(tmp_path)

    with pytest.raises(LostRunRefused):
        recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal="someone-else")

    assert _lease_rows(tmp_path) == [(run_id, 1)]
    assert control.terminal_receipt(run_id) is None
    assert ledger.hold_state(run_id, "node::a::0") != "unknown"  # recovery did not run


def test_the_original_holder_is_fenced_and_cannot_write_a_second_terminal(tmp_path: Path) -> None:
    """If the 'lost' process was merely slow, takeover must stop it from committing or terminating."""
    run_id, _, _ = _run_child(tmp_path, "in-node")
    ledger, control = _open(tmp_path)
    receipt = recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER)

    with pytest.raises(LeaseFenced):
        ledger.check(run_id, 1)  # the old holder's epoch
    with pytest.raises(ValueError):
        control.record_runtime_terminal(run_id=run_id, epoch=1, outcome="completed", reason="run.completed")
    assert control.terminal_receipt(run_id) == receipt


def test_two_concurrent_recoverers_converge_on_one_terminal(tmp_path: Path) -> None:
    """Racing operators must produce exactly one receipt, and both must see it."""
    run_id, _, _ = _run_child(tmp_path, "in-node")
    results: list[object] = []

    def attempt() -> None:
        """One competing recoverer on its own store handles."""
        ledger, control = _open(tmp_path)
        try:
            results.append(recover_lost_run(ledger=ledger, run_control=control, run_id=run_id, principal=OWNER))
        except Exception as error:  # noqa: BLE001 - a loser may legitimately see a retryable error
            results.append(error)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    _, control = _open(tmp_path)
    final = control.terminal_receipt(run_id)
    assert final is not None and final.outcome == "unknown"
    receipts = [r for r in results if not isinstance(r, Exception)]
    assert receipts and all(r == final for r in receipts)
    with sqlite3.connect(tmp_path / "shared.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM terminal_receipts WHERE run_id = ?", (run_id,)).fetchone()[0] == 1


def test_the_child_script_uses_the_real_runner() -> None:
    """Guard against this suite quietly degrading to the ledger-only harness."""
    assert "AdmissionGraphRunner" in CHILD and "run_with_plugins" not in CHILD
    assert "perpetua_core" in CHILD
