"""Guarded foreign-provider invoker (T4), dark by default.

No network client lives here. The caller injects a Telos-backed ``DialPort``; all egress, DNS,
redirect and TLS decisions stay in Telos. This layer adds only: a mode switch (``disabled`` default,
``dry_run``, ``live``), a default-deny provider/model allowlist, a dry-run-before-live rule, and
durable call/cost holds that survive restarts and concurrent processes. Contract:
``docs/foreign-provider-transport.md``.
"""
from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol

from orama.providers.contracts import (
    ProviderInvocationRequest,
    ProviderInvocationResult,
)

Mode = Literal["disabled", "dry_run", "live"]
TRANSPORT_REFUSAL_CODES: Final = frozenset({
    "transport.disabled", "transport.not_allowlisted", "transport.dry_run_required",
    "transport.call_cap", "transport.cost_cap", "transport.dial_failed", "transport.bad_config",
})
_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS holds(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, target TEXT NOT NULL,
  cost INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('held','settled','released')));
CREATE TABLE IF NOT EXISTS dry_runs(target TEXT PRIMARY KEY, run_id TEXT NOT NULL);
"""


class TransportRefused(PermissionError):
    """Closed-vocabulary refusal carrying a stable ``code``."""

    def __init__(self, code: str) -> None:
        """Record the code, which must belong to the vocabulary."""
        if code not in TRANSPORT_REFUSAL_CODES:
            raise ValueError(f"unknown transport refusal code: {code}")
        super().__init__(code)
        self.code = code


class DialPort(Protocol):
    """Telos-backed outbound dial, injected by the host."""

    def __call__(self, request: ProviderInvocationRequest) -> Awaitable[ProviderInvocationResult]:
        """Perform the dial or raise; any raise is treated as a failed (still charged) call."""


@dataclass(frozen=True, slots=True)
class TransportConfig:
    """Operator-owned limits. The default is fully closed."""

    mode: Mode = "disabled"
    allow: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    max_calls: int = 0
    max_cost: int = 0
    cost_per_call: int = 1

    def __post_init__(self) -> None:
        """Reject malformed limits instead of silently widening them."""
        if (
            self.mode not in ("disabled", "dry_run", "live")
            or any(isinstance(v, bool) or not isinstance(v, int) or v < 0
                   for v in (self.max_calls, self.max_cost))
            or isinstance(self.cost_per_call, bool) or not isinstance(self.cost_per_call, int)
            or self.cost_per_call < 1
        ):
            raise TransportRefused("transport.bad_config")


class GuardedForeignInvoker:
    """``ProviderInvoker`` that refuses unless every operator gate is open."""

    def __init__(self, config: TransportConfig, dial: DialPort, db_path: str) -> None:
        """Open (or create) the durable hold store."""
        self._config, self._dial, self._db = config, dial, db_path
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield an autocommit connection (BEGIN IMMEDIATE controls transactions) and always close it."""
        with closing(sqlite3.connect(self._db, timeout=30, isolation_level=None)) as conn:
            conn.execute("PRAGMA busy_timeout=30000")
            yield conn

    @staticmethod
    def _target(request: ProviderInvocationRequest) -> str:
        """Return the allowlist key for the request."""
        backend = getattr(request.backend, "value", request.backend)
        return f"{backend}/{request.model}"

    def _reserve(self, request: ProviderInvocationRequest, target: str) -> int:
        """Atomically check caps and place a hold; unknown outcomes stay charged."""
        cfg = self._config
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            calls, cost = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(cost),0) FROM holds WHERE state!='released'").fetchone()
            if calls + 1 > cfg.max_calls:
                conn.execute("ROLLBACK")
                raise TransportRefused("transport.call_cap")
            if cost + cfg.cost_per_call > cfg.max_cost:
                conn.execute("ROLLBACK")
                raise TransportRefused("transport.cost_cap")
            cur = conn.execute("INSERT INTO holds(run_id,target,cost,state) VALUES(?,?,?,'held')",
                               (request.run_id, target, cfg.cost_per_call))
            conn.execute("COMMIT")
            return int(cur.lastrowid)

    def _finish(self, hold: int, state: str) -> None:
        """Move a hold to ``settled`` or ``released``."""
        with self._connect() as conn:
            conn.execute("UPDATE holds SET state=? WHERE id=?", (state, hold))

    def _record_dry_run(self, target: str, run_id: str) -> None:
        """Remember that ``target`` has been dry-run."""
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO dry_runs(target,run_id) VALUES(?,?)", (target, run_id))

    def _was_dry_run(self, target: str) -> bool:
        """Return whether ``target`` has a recorded dry run."""
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM dry_runs WHERE target=?", (target,)).fetchone() is not None

    async def invoke(self, request: ProviderInvocationRequest) -> ProviderInvocationResult:
        """Run the request through every gate; live calls require a prior dry run."""
        cfg = self._config
        if cfg.mode == "disabled":
            raise TransportRefused("transport.disabled")
        target = self._target(request)
        if (str(getattr(request.backend, "value", request.backend)), request.model) not in cfg.allow:
            raise TransportRefused("transport.not_allowlisted")
        if cfg.mode == "dry_run":
            await asyncio.to_thread(self._record_dry_run, target, request.run_id)
            return ProviderInvocationResult(content="", provider_ref="dry-run", decision_ref="dry-run")
        # SQLite can block on a cross-process write lock, so all store work runs off the event loop.
        if not await asyncio.to_thread(self._was_dry_run, target):
            raise TransportRefused("transport.dry_run_required")
        hold = await asyncio.to_thread(self._reserve, request, target)
        try:
            result = await self._dial(request)
        except Exception as exc:
            # Unknown outcome: the hold deliberately stays charged (never released on failure).
            # Cancellation and other control-flow exceptions are not Exceptions and propagate unchanged.
            raise TransportRefused("transport.dial_failed") from exc
        await asyncio.to_thread(self._finish, hold, "settled")
        return result

    async def abort(self, request: ProviderInvocationRequest) -> None:
        """Abortable-invoker hook; holds are intentionally left charged."""
        return
