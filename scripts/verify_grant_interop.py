"""Cross-repository interop probe: a Phylax-issued grant spent by the Oramasys ledger.

Oramasys never imports Phylax, so this cannot be a unit test here. Run it where
both packages and PyNaCl are importable (a composition or release environment):

    PYTHONPATH=<phylax>/src:<oramasys>/src python scripts/verify_grant_interop.py

Exit status is non-zero if any expectation fails, so it can gate a release job.
"""
from __future__ import annotations

import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from orama.graph.execution_guard import StepLedger, UnknownDisposition
from orama.graph.grant_verifier import AdjustmentGrantConsumer, AdjustmentGrantRefused
from phylax.adjustment_grant import (
    AdjustmentGrantRequest,
    PhylaxGrantAuthority,
    RotatingIssuerKeyring,
    SqliteGrantAuthorityStore,
)
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

RUN, ATTEMPT, PRINCIPAL = "run-1", "node::a::0", "op-1"


class _Seeds:
    def load_seed(self, ref: str) -> bytes:
        return b"s" * 32


def _world(tmp: str):
    clock = lambda: datetime.now(UTC)  # noqa: E731
    store = SqliteGrantAuthorityStore(Path(tmp) / "phylax.db")
    ring = RotatingIssuerKeyring(key_id="k1", seed_ref="r", seed_provider=_Seeds(), store=store)
    p5 = P5ApprovalAuthority(signing_key=b"p5", store=InMemoryP5ApprovalStore(), clock=clock)
    authority = PhylaxGrantAuthority(keyring=ring, p5_approval=p5, clock=clock)
    ledger = StepLedger(Path(tmp) / "ledger.sqlite3")
    return authority, ledger


def _unknown(ledger: StepLedger, *, units: int, state: str = "unknown"):
    epoch = ledger.open_lease(RUN, max_steps=10)
    hold = ledger.reserve_attempt(RUN, epoch, ATTEMPT, units=units)
    if state == "unknown":
        ledger.mark_unknown(RUN, UnknownDisposition(
            attempt_id=ATTEMPT, hold_id=hold.hold_id, fence_epoch=epoch,
            cause="crash_before_settle", stop_state="none", settlement_state="unsettled"))
    return epoch, hold


def _issue(authority, ledger, epoch, hold, *, kind="release", units=3, basis=None):
    request = AdjustmentGrantRequest(
        principal=PRINCIPAL, run_id=RUN, hold_id=hold.hold_id, kind=kind, units=units,
        units_basis="steps", ledger_cost_basis=basis or ledger.LEGACY_COST_BASIS,
        evidence_digest="a" * 64, hold_fence_epoch=hold.fence_epoch,
        consumer_lease_epoch=epoch, ledger_store_id=ledger.store_id,
        issuer_ref="phylax", revocation_ref="phylax://revocations/v1")
    return authority.issue(request, authenticated_principal=PRINCIPAL, operator_evidence_ref="ui://approval/1")


def _run(name: str, expect: str | None, body) -> bool:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            authority, ledger = _world(tmp)
            outcome = body(authority, ledger, AdjustmentGrantConsumer(ledger, authority.verifier_adapter()))
    except AdjustmentGrantRefused as refused:
        outcome = refused.code
    ok = outcome == expect
    print(f"{'ok  ' if ok else 'FAIL'} {name}: got {outcome!r}, want {expect!r}")
    return ok


def main() -> int:
    def spend(a, l, c, *, units=3, kind="release", basis=None, state="unknown"):
        epoch, hold = _unknown(l, units=3, state=state)
        g = _issue(a, l, epoch, hold, kind=kind, units=units, basis=basis)
        return c.consume(g.to_wire(), caller_principal=PRINCIPAL), l, g

    results = [
        _run("unknown hold, real hold id, release", "released",
             lambda a, l, c: (lambda r: l.hold_state(RUN, ATTEMPT))(spend(a, l, c))),
        _run("live HELD hold is never adjusted", "grant.hold_ineligible",
             lambda a, l, c: spend(a, l, c, state="held")),
        _run("foreign cost basis is refused", "grant.basis_mismatch",
             lambda a, l, c: spend(a, l, c, basis="usd_cents")),
        _run("exact retry returns the stored receipt", "same",
             lambda a, l, c: (lambda r: "same" if c.consume(r[2].to_wire(), caller_principal=PRINCIPAL) == r[0] else "diff")(spend(a, l, c))),
        _run("revoked grant is refused", "grant.revoked",
             lambda a, l, c: (lambda e_h: (a.revoke((g := _issue(a, l, *e_h)).grant_id), c.consume(g.to_wire(), caller_principal=PRINCIPAL))[1])(_unknown(l, units=3))),
        _run("tampered wire is refused", "grant.malformed",
             lambda a, l, c: (lambda e_h: c.consume(_issue(a, l, *e_h).to_wire().replace(b'"units":3', b'"units":4'), caller_principal=PRINCIPAL))(_unknown(l, units=3))),
        _run("partial grants 1 then 2 resolve a hold of 3", "settled",
             lambda a, l, c: (lambda e_h: (c.consume(_issue(a, l, *e_h, kind="release", units=1).to_wire(), caller_principal=PRINCIPAL),
                                           c.consume(_issue(a, l, *e_h, kind="settle", units=2).to_wire(), caller_principal=PRINCIPAL),
                                           l.hold_state(RUN, ATTEMPT))[2])(_unknown(l, units=3))),
    ]
    consumer_default = AdjustmentGrantConsumer(StepLedger(Path(tempfile.mkdtemp()) / "l.sqlite3"))
    try:
        consumer_default.consume(b"{}", caller_principal=PRINCIPAL)
        results.append(False)
        print("FAIL default composition did not deny")
    except AdjustmentGrantRefused as refused:
        ok = refused.code == "verifier.unavailable"
        print(f"{'ok  ' if ok else 'FAIL'} default composition denies: {refused.code!r}")
        results.append(ok)
    print("PASS" if all(results) else "FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
