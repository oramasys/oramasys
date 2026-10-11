"""Durable, standalone per-run stop control."""
from __future__ import annotations

import sqlite3

import pytest

from orama.graph.run_control import RunControl, StopNotAuthorized, StopRequest


def test_wrong_principal_cannot_stop_run(tmp_path) -> None:
    """Only the registered owner may request a stop for its run."""
    control = RunControl(store_path=tmp_path / "stop.sqlite3")
    control.register_run(run_id="run-1", owner_principal="owner-a")

    with pytest.raises(StopNotAuthorized):
        control.request_stop(StopRequest(run_id="run-1", principal="owner-b"))

    assert control.stop_for("run-1") is None


def test_restart_preserves_stop(tmp_path) -> None:
    """A persisted request remains visible to a fresh process instance."""
    path = tmp_path / "stop.sqlite3"
    control = RunControl(store_path=path)
    control.register_run(run_id="run-1", owner_principal="owner-a")
    control.request_stop(StopRequest(run_id="run-1", principal="owner-a", reason="operator_request"))
    control.close()

    reopened = RunControl(store_path=path)
    assert reopened.stop_for("run-1") == StopRequest(
        run_id="run-1", principal="owner-a", reason="operator_request"
    )


def test_stop_persists_before_notification(tmp_path) -> None:
    """A notifier sees the request through an independent database connection."""
    path = tmp_path / "stop.sqlite3"

    def notifier(request: StopRequest) -> None:
        with sqlite3.connect(path) as database:
            row = database.execute(
                "SELECT principal, reason FROM stop_requests WHERE run_id = ?", (request.run_id,)
            ).fetchone()
        assert row == ("owner-a", "operator_request")

    control = RunControl(store_path=path, notifier=notifier)
    control.register_run(run_id="run-1", owner_principal="owner-a")
    control.request_stop(StopRequest(run_id="run-1", principal="owner-a", reason="operator_request"))
