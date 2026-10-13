"""Ledger and API review hardening that holds on every pinned Core lane."""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from orama.graph.execution_guard import LeaseFenced, StepLedger
from orama.graph.run_control import RunControl


def test_legacy_reserve_is_fenced_after_the_run_is_terminal(tmp_path: Path) -> None:
    """A closed run cannot gain charges through the legacy step reserve."""
    store = tmp_path / "shared.sqlite3"
    ledger = StepLedger(store)
    run_control = RunControl(store_path=store)
    run_control.register_run(run_id="r1", owner_principal="p")
    epoch = ledger.open_lease("r1", max_steps=5)
    run_control.record_runtime_terminal(
        run_id="r1", epoch=epoch, outcome="completed", reason="run.completed"
    )
    used = ledger.used("r1")

    with pytest.raises(LeaseFenced):
        ledger.reserve("r1", epoch, 1)
    assert ledger.used("r1") == used
    ledger.close()
    run_control.close()


def test_time_observation_appends_one_anchor_event_not_one_per_boundary(tmp_path: Path) -> None:
    """The high-water row carries rollback state; the event log is not grown per call."""
    ledger = StepLedger(tmp_path / "ledger.sqlite3")
    epoch = ledger.open_lease("r1", max_steps=5)
    start = datetime(2026, 10, 12, tzinfo=UTC)
    for tick in range(5):
        ledger.observe_time("r1", epoch, start + timedelta(seconds=tick))

    count = ledger._db.execute(
        "SELECT COUNT(*) FROM accounting_events WHERE run_id = ? AND event_type = 'time_observed'",
        ("r1",),
    ).fetchone()[0]
    assert count == 1
    with pytest.raises(ValueError, match="rollback"):
        ledger.observe_time("r1", epoch, start)
    ledger.close()


def test_api_module_imports_when_core_has_no_gate_seam() -> None:
    """A pre-T1 Core pin still loads the API so it can refuse work safely."""
    import subprocess
    import sys
    import textwrap

    code = textwrap.dedent(
        """
        import importlib.abc, sys
        import perpetua_core.state, perpetua_core.graph.engine
        sys.modules.pop("perpetua_core.graph.gate", None)

        class Block(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):
                if name == "perpetua_core.graph.gate":
                    raise ImportError("simulated pre-T1 Core pin")

        sys.meta_path.insert(0, Block())
        import orama.api.server
        from orama.graph.execution_guard import CORE_GATE_AVAILABLE
        assert CORE_GATE_AVAILABLE is False
        """
    )
    # pytest's ``pythonpath`` only configures this process. The child inherits the
    # environment, so without the source root it can import ``orama`` only when the
    # package happens to be installed (CI installs it; a source checkout does not).
    # Keep any caller-supplied paths, such as a specific Core revision, behind it.
    source_root = str(Path(__file__).resolve().parents[1])
    inherited = [e for e in os.environ.get("PYTHONPATH", "").split(os.pathsep) if e]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([source_root, *inherited])}
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr
