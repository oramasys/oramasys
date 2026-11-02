"""Guarded foreign transport: dark by default, allowlisted, capped, durable, network-free."""
from __future__ import annotations

import ast
import asyncio
import inspect

import pytest

from orama.providers import foreign_transport as ft
from orama.providers.contracts import (
    ProviderInvocationRequest,
    ProviderInvocationResult,
    ProviderMessage,
)
from orama.providers.foreign_transport import (
    GuardedForeignInvoker,
    TransportConfig,
    TransportRefused,
)


class Dial:
    """Dial double counting calls."""

    def __init__(self, fail: bool = False) -> None:
        """Record failure mode."""
        self.calls, self.fail = 0, fail

    async def __call__(self, request):
        """Return a canned result or raise."""
        self.calls += 1
        if self.fail:
            raise ConnectionError("boom")
        return ProviderInvocationResult(content="ok", provider_ref="p", decision_ref="d")


def req(run_id="r1", model="m1"):
    """Build a request using a plain string backend."""
    return ProviderInvocationRequest(backend="acme", model=model, run_id=run_id,
                                     messages=(ProviderMessage("user", "hi"),))


def cfg(mode="live", **kw):
    """Build an open config for tests."""
    base = {"mode": mode, "allow": frozenset({("acme", "m1")}), "max_calls": 2, "max_cost": 2}
    base.update(kw)
    return TransportConfig(**base)


def run(inv, request):
    """Invoke synchronously."""
    return asyncio.run(inv.invoke(request))


def code(inv, request):
    """Return the refusal code."""
    with pytest.raises(TransportRefused) as caught:
        run(inv, request)
    return caught.value.code


def test_default_config_is_closed(tmp_path) -> None:
    """The zero-argument config refuses everything and never dials."""
    dial = Dial()
    inv = GuardedForeignInvoker(TransportConfig(), dial, str(tmp_path / "t.db"))
    assert code(inv, req()) == "transport.disabled" and dial.calls == 0


def test_allowlist_is_default_deny(tmp_path) -> None:
    """Unlisted provider/model pairs are refused before any hold or dial."""
    dial = Dial()
    inv = GuardedForeignInvoker(cfg("dry_run"), dial, str(tmp_path / "t.db"))
    assert code(inv, req(model="other")) == "transport.not_allowlisted" and dial.calls == 0


def test_dry_run_never_dials_and_unlocks_live(tmp_path) -> None:
    """Live is refused until a dry run for the same target was recorded."""
    db, dial = str(tmp_path / "t.db"), Dial()
    assert code(GuardedForeignInvoker(cfg("live"), dial, db), req()) == "transport.dry_run_required"
    assert run(GuardedForeignInvoker(cfg("dry_run"), dial, db), req()).provider_ref == "dry-run"
    assert dial.calls == 0
    assert run(GuardedForeignInvoker(cfg("live"), dial, db), req()).content == "ok" and dial.calls == 1


def test_call_cap_holds_across_instances(tmp_path) -> None:
    """The cap is durable: a fresh invoker on the same file sees earlier holds."""
    db, dial = str(tmp_path / "t.db"), Dial()
    run(GuardedForeignInvoker(cfg("dry_run"), dial, db), req())
    for i in range(2):
        run(GuardedForeignInvoker(cfg("live"), dial, db), req(f"r{i}"))
    assert code(GuardedForeignInvoker(cfg("live"), dial, db), req("r9")) == "transport.call_cap"
    assert dial.calls == 2


def test_cost_cap_refuses_before_dial(tmp_path) -> None:
    """A cost cap below the next call refuses without dialing."""
    db, dial = str(tmp_path / "t.db"), Dial()
    run(GuardedForeignInvoker(cfg("dry_run"), dial, db), req())
    inv = GuardedForeignInvoker(cfg("live", max_calls=5, max_cost=1, cost_per_call=2), dial, db)
    assert code(inv, req()) == "transport.cost_cap" and dial.calls == 0


def test_failed_dial_stays_charged(tmp_path) -> None:
    """An unknown outcome is never refunded, so retries cannot bypass the cap."""
    db = str(tmp_path / "t.db")
    run(GuardedForeignInvoker(cfg("dry_run"), Dial(), db), req())
    bad = GuardedForeignInvoker(cfg("live", max_calls=1, max_cost=1), Dial(fail=True), db)
    assert code(bad, req()) == "transport.dial_failed"
    assert code(GuardedForeignInvoker(cfg("live", max_calls=1, max_cost=1), Dial(), db), req("r2")) == "transport.call_cap"


def test_cancellation_propagates_and_stays_charged(tmp_path) -> None:
    """Cancelling an in-flight dial is not a provider failure; the hold is still charged."""
    db = str(tmp_path / "t.db")
    run(GuardedForeignInvoker(cfg("dry_run"), Dial(), db), req())

    async def hang(request):
        """Never finish, so the caller can cancel."""
        await asyncio.sleep(60)

    inv = GuardedForeignInvoker(cfg("live", max_calls=1, max_cost=1), hang, db)

    async def go() -> None:
        """Start the call, cancel it, and require CancelledError."""
        task = asyncio.ensure_future(inv.invoke(req()))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    assert code(GuardedForeignInvoker(cfg("live", max_calls=1, max_cost=1), Dial(), db), req("r2")) == "transport.call_cap"


def test_store_connections_are_closed(tmp_path, monkeypatch) -> None:
    """Every connection opened for the hold store is closed before the call returns."""
    import sqlite3

    opened: list[sqlite3.Connection] = []
    real = sqlite3.connect

    def tracking(*args, **kwargs):
        """Record each connection."""
        conn = real(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(ft.sqlite3, "connect", tracking)
    db = str(tmp_path / "t.db")
    run(GuardedForeignInvoker(cfg("dry_run"), Dial(), db), req())
    run(GuardedForeignInvoker(cfg("live"), Dial(), db), req())
    assert opened
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


def test_store_waits_do_not_block_the_event_loop(tmp_path) -> None:
    """A held write lock must not stall other tasks on the loop."""
    import sqlite3

    db = str(tmp_path / "t.db")
    run(GuardedForeignInvoker(cfg("dry_run"), Dial(), db), req())
    inv = GuardedForeignInvoker(cfg("live"), Dial(), db)
    locker = sqlite3.connect(db, isolation_level=None)
    locker.execute("BEGIN IMMEDIATE")

    async def go() -> int:
        """Count loop ticks while the invoke waits on the lock, then release it."""
        ticks = 0
        task = asyncio.ensure_future(inv.invoke(req("r3")))
        for _ in range(10):
            await asyncio.sleep(0.05)
            ticks += 1
        locker.execute("ROLLBACK")
        await task
        return ticks

    assert asyncio.run(go()) == 10
    locker.close()


def test_backend_objects_are_matched_by_name(tmp_path) -> None:
    """The graph passes a Backend object; its ``name`` is the allowlist identity."""
    from perpetua_core.discovery import Backend, BackendKind

    backend = Backend(name="acme", base_url="http://x", kind=next(iter(BackendKind)))
    request = ProviderInvocationRequest(backend=backend, model="m1", run_id="r1",
                                        messages=(ProviderMessage("user", "hi"),))
    inv = GuardedForeignInvoker(cfg("dry_run"), Dial(), str(tmp_path / "t.db"))
    assert run(inv, request).provider_ref == "dry-run"


def test_slash_in_names_cannot_share_a_dry_run(tmp_path) -> None:
    """('a', 'b/c') and ('a/b', 'c') are different targets and need separate dry runs."""
    db = str(tmp_path / "t.db")
    allow = frozenset({("a", "b/c"), ("a/b", "c")})

    def build(mode):
        """Build an invoker over the shared store."""
        return GuardedForeignInvoker(cfg(mode, allow=allow), Dial(), db)

    def make(backend, model):
        """Build a request for the pair."""
        return ProviderInvocationRequest(backend=backend, model=model, run_id="r",
                                         messages=(ProviderMessage("user", "hi"),))

    run(build("dry_run"), make("a", "b/c"))
    assert run(build("live"), make("a", "b/c")).content == "ok"
    assert code(build("live"), make("a/b", "c")) == "transport.dry_run_required"


def test_invoker_does_not_advertise_a_noop_abort() -> None:
    """A no-op abort would claim a capability the injected dial does not provide."""
    assert not hasattr(GuardedForeignInvoker, "abort")


@pytest.mark.parametrize("kw", [{"mode": "on"}, {"max_calls": -1}, {"max_cost": True}, {"cost_per_call": 0}])
def test_bad_config_is_refused(kw) -> None:
    """Malformed limits never silently widen the gate."""
    with pytest.raises(TransportRefused) as caught:
        TransportConfig(**kw)
    assert caught.value.code == "transport.bad_config"


def test_module_has_no_network_imports() -> None:
    """Egress belongs to Telos: only stdlib non-network and orama imports are allowed."""
    tree = ast.parse(inspect.getsource(ft))
    roots = {
        (n.module or "").split(".")[0] if isinstance(n, ast.ImportFrom) else a.name.split(".")[0]
        for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert roots <= {"__future__", "asyncio", "contextlib", "json", "sqlite3", "collections", "dataclasses", "typing", "orama"}
    with pytest.raises(ValueError):
        TransportRefused("transport.invented")
