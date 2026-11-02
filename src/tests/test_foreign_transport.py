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
    assert roots <= {"__future__", "sqlite3", "collections", "dataclasses", "typing", "orama"}
    with pytest.raises(ValueError):
        TransportRefused("transport.invented")
