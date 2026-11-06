"""Opt-in expiry/release worker for the v2 controller (ratified D1, Part 3 item 3).

Nothing here runs unless a caller constructs an ``ExpiryWorker`` and calls ``start()``.
There is no import-time or install-time autostart. One worker owns one database scope,
enforced by the store's ``maintenance_owner`` row; each sweep is bounded by
``batch_limit`` and runs in one transaction that re-verifies that ownership, so a worker
whose epoch was superseded is fenced and stops. ``stop()`` cancels between sweeps: the
transaction in flight either commits or rolls back as a whole.

Staleness alone never proves work can be reassigned. Recovery uses only the controller
clock rule in the store and holds tasks with external effects for reconciliation.
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from orama.orchestrator_controller.refusals import ClaimRefused
from orama.orchestrator_controller.store import MAX_SWEEP_LIMIT, ControllerStore, RecoveryReceipt

WorkerState = Literal["stopped", "running", "stopping", "fenced", "failed"]


@dataclass(frozen=True, slots=True)
class WorkerStatus:
    """A snapshot of the worker for operators: state, ownership and counters."""

    state: WorkerState
    owner_id: str
    epoch: int | None
    sweeps: int
    recovered: int
    last_error_code: str | None


class ExpiryWorker:
    """Explicitly started, single-owner, bounded sweeper of expired job-claim leases."""

    def __init__(
        self,
        store: ControllerStore,
        *,
        interval: float = 1.0,
        batch_limit: int = 100,
        owner_ttl: timedelta = timedelta(seconds=30),
        owner_id: str | None = None,
    ) -> None:
        """Configure the worker without starting anything.

        ``interval`` is the pause between sweeps in seconds. ``batch_limit`` bounds the leases
        one sweep may expire. ``owner_ttl`` is how long ownership survives without a sweep; it
        must cover at least two intervals so a healthy worker never loses ownership between
        sweeps. ``owner_id`` defaults to a random opaque identifier.
        """
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval <= 0:
            raise ValueError("interval must be a positive number of seconds")
        if isinstance(batch_limit, bool) or not isinstance(batch_limit, int) or not 1 <= batch_limit <= MAX_SWEEP_LIMIT:
            raise ValueError(f"batch_limit must be an integer from 1 to {MAX_SWEEP_LIMIT}")
        if not isinstance(owner_ttl, timedelta) or owner_ttl < timedelta(seconds=2 * interval):
            raise ValueError("owner_ttl must cover at least two sweep intervals")
        self._store = store
        self._interval = float(interval)
        self._batch_limit = batch_limit
        self._owner_ttl = owner_ttl
        self._owner_id = owner_id or f"expiry-worker-{secrets.token_hex(8)}"
        self._state_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state: WorkerState = "stopped"
        self._epoch: int | None = None
        self._sweeps = 0
        self._recovered = 0
        self._last_error: str | None = None

    def start(self) -> None:
        """Acquire database ownership, then start the sweep thread.

        Raises ``RuntimeError`` if already running and ``ClaimRefused`` with
        ``worker.owner_conflict`` if another owner holds this database.
        """
        with self._state_lock:
            if self._state in ("running", "stopping"):
                raise RuntimeError("expiry worker is already running")
            epoch = self._store.acquire_maintenance(self._owner_id, ttl=self._owner_ttl)
            self._epoch = epoch
            self._state = "running"
            self._last_error = None
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="controller-expiry-worker", daemon=True)
            self._thread.start()

    def status(self) -> WorkerStatus:
        """Return the current state, owner epoch and counters."""
        with self._state_lock:
            return WorkerStatus(self._state, self._owner_id, self._epoch, self._sweeps,
                                self._recovered, self._last_error)

    def stop(self, timeout: float = 10.0) -> WorkerStatus:
        """Cancel between sweeps, wait up to ``timeout`` seconds, and release ownership.

        A fenced or failed worker keeps that state and releases nothing it no longer owns.
        If the thread does not finish in time the state is ``stopping``.
        """
        thread = self._thread
        self._stop.set()
        if thread is not None:
            thread.join(timeout)
        with self._state_lock:
            if thread is not None and thread.is_alive():
                self._state = "stopping"
            elif self._state in ("running", "stopping"):
                if self._epoch is not None:
                    try:
                        self._store.release_maintenance(self._owner_id, self._epoch)
                    except ClaimRefused as refusal:
                        self._last_error = refusal.code
                self._state = "stopped"
        return self.status()

    def sweep_once(self) -> tuple[RecoveryReceipt, ...]:
        """Run one bounded sweep now; the worker must have been started.

        Raises ``ClaimRefused`` (``worker.fenced``) when this worker no longer owns the
        database, and ``RuntimeError`` when it was never started.
        """
        with self._state_lock:
            if self._epoch is None or self._state != "running":
                raise RuntimeError("expiry worker is not running")
            epoch = self._epoch
        receipts = self._store.recover_expired(
            self._owner_id, epoch, limit=self._batch_limit, owner_ttl=self._owner_ttl
        )
        with self._state_lock:
            self._sweeps += 1
            self._recovered += len(receipts)
        return receipts

    def _run(self) -> None:
        """Sweep until stopped, fenced or failed; a busy database is retried next interval."""
        while not self._stop.is_set():
            try:
                self.sweep_once()
            except ClaimRefused as refusal:
                with self._state_lock:
                    self._last_error = refusal.code
                    if refusal.code == "worker.fenced":
                        self._state = "fenced"
                        return
            except RuntimeError:
                return
            except Exception as error:  # noqa: BLE001 - record and stop; never sweep blindly
                with self._state_lock:
                    self._last_error = type(error).__name__
                    self._state = "failed"
                return
            self._stop.wait(self._interval)
