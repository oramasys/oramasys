"""Gate-level runtime hardening, collected only where Core has the T1 gate."""
from __future__ import annotations

from pathlib import Path

from perpetua_core import END, START, MiniGraph, PerpetuaState
from tests.core_gate.support import runner_with_stores


async def test_trusted_run_identity_reaches_the_graph_state(tmp_path: Path) -> None:
    """Nodes see the server-minted run id, never the client's metadata run id."""
    runner, ledger, run_control = runner_with_stores(tmp_path)
    seen: list[str] = []
    graph = MiniGraph()
    graph.add_node("work", lambda state: seen.append(state.metadata["run_id"]) or {})
    graph.add_edge(START, "work").add_edge("work", END)

    await runner.for_authenticated_principal("control-plane").invoke(
        graph.compile(),
        PerpetuaState(session_id="client-session", metadata={"run_id": "client-meta"}),
    )

    assert seen and seen[0] not in {"client-meta", "client-session"}
    assert run_control.terminal_receipt(seen[0]) is not None
    ledger.close()
    run_control.close()
