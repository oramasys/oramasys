"""R0-R2 contract synthesis: immutable bound tuple, refusal fencing and in-transaction refusal."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from orama.graph.dispatch_attempts import SqliteAttemptStore
from orama.graph.effect_grant_composition import AttemptRefused, FinalBoundarySender
from orama.graph.effect_receipts import attempt_ref_for
from tests.test_dispatch_attempts import ATTEMPT, GRANT, ISSUER, RESERVATION
from tests.test_effect_grant_composition import (
    PRINCIPAL,
    Bound,
    Simulation,
    bound_harness,
    refuse_once,
    sealed,
    untouched,
)
from tests.test_final_boundary import Approvals


@pytest.fixture
def bound(tmp_path: Path) -> Bound:
    """A composer-bound attempt, authorized and approved for the final boundary."""
    b = bound_harness(tmp_path)
    yield b
    b.h.store.close()


# ------------------------------------------------------------ storage immutability triggers


def test_a_refused_attempt_cannot_start_a_send_even_by_raw_sql(bound: Bound) -> None:
    """The refusal overlay fences the attempt: ``send_started`` cannot be set once a refusal exists."""
    refuse_once(bound)
    with pytest.raises(sqlite3.DatabaseError, match="refused attempt cannot start a send"):
        bound.h.store._db.execute("UPDATE outbox SET send_started = 1 WHERE attempt_id = ?", (ATTEMPT,))
    untouched(bound)
    # the refusal does not release the reservation or delete the outbox row
    assert bound.h.store.outbox_row(ATTEMPT) is not None
    assert bound.h.store._db.execute(
        "SELECT consumed_attempt_id FROM reservations WHERE reservation_id = ?", (RESERVATION,)
    ).fetchone() == (ATTEMPT,)


def test_the_send_marker_of_an_unrefused_attempt_is_not_blocked_by_the_trigger(bound: Bound) -> None:
    """The fence applies only to refused attempts: a normal bound send still starts and settles."""
    receipt = bound.composer.send(sealed(bound), ATTEMPT, authenticated_principal=PRINCIPAL)
    assert receipt.outcome == "confirmed"


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE effect_grant_bindings SET context = '{}' WHERE attempt_id = ?",
        "UPDATE effect_grant_bindings SET grant_wire = x'00' WHERE attempt_id = ?",
        "DELETE FROM effect_grant_bindings WHERE attempt_id = ?",
    ],
)
def test_the_grant_binding_is_append_only(bound: Bound, statement: str) -> None:
    """The bound tuple cannot be rewritten or removed after it is recorded."""
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        bound.h.store._db.execute(statement, (ATTEMPT,))
    assert bound.h.store.effect_grant_binding(ATTEMPT)[0] == b"trusted-effect-grant"


def test_a_consumed_reservation_cannot_change_its_attempt(bound: Bound) -> None:
    """Once ``consumed_attempt_id`` is set it can be neither re-pointed nor cleared."""
    db = bound.h.store._db
    for value in ("someone-else", None):
        with pytest.raises(sqlite3.DatabaseError, match="cannot change its attempt"):
            db.execute(
                "UPDATE reservations SET consumed_attempt_id = ? WHERE reservation_id = ?",
                (value, RESERVATION),
            )
    assert db.execute(
        "SELECT consumed_attempt_id FROM reservations WHERE reservation_id = ?", (RESERVATION,)
    ).fetchone() == (ATTEMPT,)


def test_the_triggers_are_added_to_an_existing_database_on_open(tmp_path: Path) -> None:
    """A store created before the triggers existed gets them when it is opened again."""
    path = tmp_path / "old.sqlite"
    SqliteAttemptStore(path, governed=True).close()
    raw = sqlite3.connect(path)
    names = (
        "effect_grant_bindings_no_update", "effect_grant_bindings_no_delete",
        "reservations_consumer_immutable", "outbox_no_send_after_refusal",
    )
    for name in names:
        raw.execute(f"DROP TRIGGER {name}")
    raw.commit()
    raw.close()
    store = SqliteAttemptStore(path, governed=True)
    try:
        present = {
            row[0] for row in store._db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        assert set(names) <= present
    finally:
        store.close()


# ------------------------------------------------------------ F4: refusal in the begin-send transaction


def test_a_revocation_acknowledged_before_the_send_transaction_writes_the_refusal_row(
    bound: Bound,
) -> None:
    """A revocation that lands between the final boundary and begin_bound_send refuses terminally.

    The refusal row is written in the begin-send transaction, the replay answers with the same
    ``receipt_ref`` and the inert simulation never runs.
    """

    class Revoking(Approvals):
        """Approval verifier after which the issuer's revocation is acknowledged locally."""

        def verify(self, binding):
            """Approve, then record a grant revocation fact as an acknowledged event would."""
            answer = super().verify(binding)
            bound.h.store._db.execute(
                "INSERT INTO issuer_revocations VALUES (?, 1, 'grant', ?)", (ISSUER, GRANT)
            )
            return answer

    sim = Simulation()
    sender = FinalBoundarySender(bound.composer, sealed(bound, approvals=Revoking(), sim=sim))
    with pytest.raises(AttemptRefused) as first:
        sender(ATTEMPT, PRINCIPAL)
    assert first.value.code == "deny.revoked_grant"
    assert first.value.receipt_ref == attempt_ref_for(ATTEMPT)
    stored = bound.h.store.terminal_refusal(ATTEMPT)
    assert stored is not None and stored.kind == "final_boundary" and stored.reason == "grant_revoked"
    assert sim.calls == 0
    untouched(bound)
    assert bound.h.store.approval_state(ATTEMPT) == "granted"  # nothing was consumed
    with pytest.raises(AttemptRefused) as again:
        FinalBoundarySender(bound.composer, sealed(bound, sim=sim))(ATTEMPT, PRINCIPAL)
    assert (again.value.code, again.value.receipt_ref) == (first.value.code, first.value.receipt_ref)
    assert sim.calls == 0


def test_a_divergence_found_by_the_recheck_writes_the_refusal_row(bound: Bound) -> None:
    """Issuer divergence found in ``_recheck_send_authority`` is a terminal ``issuer_revoked`` row."""

    class Diverging(Approvals):
        """Approval verifier after which the issuer is flagged as diverged."""

        def verify(self, binding):
            """Approve, then flag divergence for the issuer."""
            answer = super().verify(binding)
            bound.h.store._db.execute(
                "INSERT INTO issuer_divergence VALUES (?, 1, 'a', 'b', '2026-10-26T00:00:00Z')",
                (ISSUER,),
            )
            return answer

    sim = Simulation()
    with pytest.raises(AttemptRefused) as refused:
        FinalBoundarySender(bound.composer, sealed(bound, approvals=Diverging(), sim=sim))(
            ATTEMPT, PRINCIPAL
        )
    assert refused.value.code == "deny.revoked_grant"
    assert bound.h.store.terminal_refusal(ATTEMPT).reason == "issuer_revoked"
    assert sim.calls == 0
    untouched(bound)


# ------------------------------------------------------------ F5: one closed error envelope

TOKEN = "test-control-plane-token-32b"


def _has_detail(value: object) -> bool:
    """Return True when a ``"detail"`` key occurs anywhere in a decoded JSON value."""
    if isinstance(value, dict):
        return "detail" in value or any(_has_detail(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_detail(v) for v in value)
    return False


@pytest.mark.parametrize("auth", ["none", "wrong", "good", "token-unconfigured"])
async def test_no_route_response_carries_a_detail_key(monkeypatch: pytest.MonkeyPatch, auth: str) -> None:
    """Every route, wrong method, unknown path and malformed body answers in the public envelope.

    Sweeps every registered route with every common method and bodies that fail validation (422 in
    stock FastAPI), plus unknown paths, under each authentication state.
    """
    from httpx import ASGITransport, AsyncClient

    from orama.api.public_errors import PUBLIC_CODES
    from orama.api.server import create_app

    if auth == "token-unconfigured":
        monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    else:
        monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    headers = {
        "none": {}, "wrong": {"Authorization": "Bearer wrong-token-0000000000000"},
        "good": {"Authorization": f"Bearer {TOKEN}"}, "token-unconfigured": {"Authorization": "Bearer x"},
    }[auth]
    app = create_app()
    paths = {getattr(route, "path", "") for route in app.routes} | {"/no/such/route", "/effects"}
    paths = {p.replace("{", "x").replace("}", "") for p in paths if p}
    bodies = [b"{}", b"not json", b'{"grant": 5}', b""]
    checked = 0
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1") as client:
        for path in sorted(paths):
            for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                for body in bodies:
                    response = await client.request(
                        method, path, content=body, headers={**headers, "Content-Type": "application/json"}
                    )
                    checked += 1
                    if response.status_code >= 400:
                        decoded = response.json()
                        assert not _has_detail(decoded), (method, path, response.text)
                        assert decoded["error"]["code"] in PUBLIC_CODES, (method, path, response.text)
    assert checked > 100


async def test_framework_validation_unknown_route_and_wrong_method_use_public_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """422 becomes 400 deny.malformed_grant; an unknown route or wrong method is 404 route_not_exposed."""
    from httpx import ASGITransport, AsyncClient

    from orama.api.server import create_app

    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://127.0.0.1") as client:
        invalid = await client.post("/run", json={"unexpected": 1}, headers=auth)
        unknown = await client.get("/no/such/route", headers=auth)
        wrong_method = await client.delete("/healthz", headers=auth)
    assert invalid.status_code == 400 and invalid.json()["error"]["code"] == "deny.malformed_grant"
    assert unknown.status_code == 404 and unknown.json()["error"]["code"] == "serving.route_not_exposed"
    assert wrong_method.status_code == 404
    assert wrong_method.json()["error"]["code"] == "serving.route_not_exposed"


async def test_an_unconfigured_token_is_not_ready_and_a_bad_bearer_is_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The middleware answers 503 serving.not_ready without a token and 401 with a wrong one."""
    from httpx import ASGITransport, AsyncClient

    from orama.api.server import create_app

    monkeypatch.delenv("ORAMA_INSECURE_DEV", raising=False)
    monkeypatch.delenv("ORAMA_CONTROL_PLANE_TOKEN", raising=False)
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://127.0.0.1") as client:
        unconfigured = await client.post("/run", json={})
        monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", TOKEN)
        wrong = await client.post("/run", json={}, headers={"Authorization": "Bearer nope"})
    assert unconfigured.status_code == 503
    assert unconfigured.json()["error"]["code"] == "serving.not_ready"
    assert wrong.status_code == 401 and wrong.json()["error"]["code"] == "deny.unauthorized_caller"


def test_the_public_vocabulary_drops_two_codes_and_adds_the_grant_conflict() -> None:
    """``serving.disabled`` and ``deny.attempt_binding_conflict`` are gone; ``deny.grant_conflict`` is 409."""
    from orama.api.public_errors import DENY_STATUS, PUBLIC_CODES

    assert "serving.disabled" not in PUBLIC_CODES
    assert "deny.attempt_binding_conflict" not in PUBLIC_CODES
    assert "deny.grant_conflict" in PUBLIC_CODES and DENY_STATUS["deny.grant_conflict"] == 409
    assert PUBLIC_CODES - {"deny.grant_conflict"} == {
        "serving.not_ready", "serving.route_not_exposed", "deny.revocation_stale", "deny.unknown_key",
        "deny.malformed_grant", "deny.revoked_grant", "deny.missing_capability_record",
        "deny.unauthorized_caller", "deny.verifier_unavailable",
    }
