"""E1 "C2" dispatch permit replay protection tests.

Covers the four explicit replay/crash test cases from the C2 spec, the
"no existing permit" issuance path, and the fail-closed guards on the store and
``issue_new`` collaborators, using an in-memory fake PermitStore.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from orama.graph.binding_digest import compute_binding_digest
from orama.graph.dispatch_permits import (
    DispatchPermit,
    ExpiredPermit,
    PermitRefused,
    PermitRequest,
    decide_permit,
)

GRANT_ID = "grant-1"


def now_utc() -> datetime:
    """Return a fixed reference instant for deterministic tests."""
    return datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)


def make_request(**overrides: object) -> PermitRequest:
    """Build a PermitRequest with sane defaults, overridable per field."""
    fields: dict[str, object] = {
        "grant_id": GRANT_ID,
        "grant_payload_digest": "a" * 64,
        "operation_id": "op-1",
        "request_digest": "b" * 64,
        "artifact_digest": "c" * 64,
        "reservation_id": "res-1",
        "ledger_store_id": "store-1",
        "configuration_policy_epoch": 1,
        "authority_epoch": 1,
        "requested_at": now_utc(),
    }
    fields.update(overrides)
    return PermitRequest(**fields)  # type: ignore[arg-type]


def make_permit(**overrides: object) -> DispatchPermit:
    """Build a DispatchPermit with sane defaults, overridable per field."""
    fields: dict[str, object] = {
        "permit_id": "permit-1",
        "grant_id": GRANT_ID,
        "binding_digest": "d" * 64,
        "reservation_id": "res-1",
        "request_digest": "b" * 64,
        "r_p": "opaque-token",
        "consumer_acked_through": "ack-0",
        "requested_at": now_utc(),
        "issued_at": now_utc(),
        "expires_at": now_utc() + timedelta(hours=1),
        "permit_bytes": "opaque-bytes",
        "state": "issued",
    }
    fields.update(overrides)
    return DispatchPermit(**fields)  # type: ignore[arg-type]


class FakePermitStore:
    """In-memory PermitStore fake: at most one nonterminal permit per grant."""

    def __init__(self) -> None:
        """Start with no stored permits."""
        self._by_grant: dict[str, DispatchPermit] = {}

    def get_nonterminal_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
        """Return the grant's stored nonterminal permit, if any."""
        return self._by_grant.get(grant_id)

    def insert_permit(self, permit: DispatchPermit) -> None:
        """Persist a brand-new permit, enforcing at most one per grant."""
        if permit.grant_id in self._by_grant:
            raise AssertionError("store invariant violated: nonterminal permit already exists")
        self._by_grant[permit.grant_id] = permit


def unexpected_issue_new(request: PermitRequest, digest: str) -> DispatchPermit:
    """issue_new stand-in that must never be called for an existing-permit path."""
    raise AssertionError("issue_new must not be called when a permit already exists")


def test_no_existing_permit_issues_and_stores_new_permit() -> None:
    """No existing permit for the grant: a new permit is issued and stored."""
    store = FakePermitStore()
    request = make_request()
    calls: list[tuple[PermitRequest, str]] = []

    def issue_new(req: PermitRequest, digest: str) -> DispatchPermit:
        calls.append((req, digest))
        return make_permit(binding_digest=digest)

    result = decide_permit(request, store, now=now_utc(), issue_new=issue_new)

    assert len(calls) == 1
    assert result.grant_id == GRANT_ID
    assert store.get_nonterminal_permit_for_grant(GRANT_ID) is result


def test_identical_retry_returns_same_stored_permit_unchanged() -> None:
    """Same request, equal binding digest, not expired: returns the SAME stored permit."""
    store = FakePermitStore()
    request = make_request()

    first = decide_permit(
        request,
        store,
        now=now_utc(),
        issue_new=lambda req, digest: make_permit(binding_digest=digest),
    )

    retry_request = make_request()  # identical fields
    second = decide_permit(
        retry_request,
        store,
        now=now_utc(),
        issue_new=unexpected_issue_new,
    )

    assert second is first
    assert second.issued_at == first.issued_at
    assert second.expires_at == first.expires_at
    assert second.requested_at == first.requested_at
    # No second permit was created.
    assert store.get_nonterminal_permit_for_grant(GRANT_ID) is first


def test_conflicting_binding_field_raises_permit_conflict() -> None:
    """One of the 9 immutable binding fields differs: refused with permit.conflict."""
    store = FakePermitStore()
    request = make_request()

    stored = decide_permit(
        request,
        store,
        now=now_utc(),
        issue_new=lambda req, digest: make_permit(binding_digest=digest),
    )

    conflicting_request = make_request(operation_id="op-2")  # one field differs

    with pytest.raises(PermitRefused) as exc_info:
        decide_permit(
            conflicting_request,
            store,
            now=now_utc(),
            issue_new=unexpected_issue_new,
        )

    assert exc_info.value.code == "permit.conflict"
    # The stored permit is unchanged; nothing was created or mutated.
    assert store.get_nonterminal_permit_for_grant(GRANT_ID) == stored


def test_different_requested_at_on_retry_is_ignored() -> None:
    """Identical binding, different requested_at: original requested_at is kept."""
    store = FakePermitStore()
    original_requested_at = now_utc()
    request = make_request(requested_at=original_requested_at)

    first = decide_permit(
        request,
        store,
        now=now_utc(),
        issue_new=lambda req, digest: make_permit(
            binding_digest=digest, requested_at=original_requested_at
        ),
    )

    later_requested_at = original_requested_at + timedelta(minutes=5)
    retry_request = make_request(requested_at=later_requested_at)

    second = decide_permit(
        retry_request,
        store,
        now=now_utc(),
        issue_new=unexpected_issue_new,
    )

    assert second is first
    assert second.requested_at == original_requested_at
    assert second.requested_at != later_requested_at


def test_expired_stored_permit_is_not_revived_as_identical_retry() -> None:
    """Identical binding digest but the stored permit is expired: not an identical retry."""
    store = FakePermitStore()
    request = make_request()

    issued_at = now_utc() - timedelta(hours=2)
    expires_at = now_utc() - timedelta(hours=1)  # already expired relative to `now` below

    decide_permit(
        request,
        store,
        now=issued_at,  # issue it while still "fresh" relative to that instant
        issue_new=lambda req, digest: make_permit(
            binding_digest=digest, issued_at=issued_at, expires_at=expires_at
        ),
    )

    retry_request = make_request()

    with pytest.raises(ExpiredPermit) as exc_info:
        decide_permit(
            retry_request,
            store,
            now=now_utc(),  # now > expires_at
            issue_new=unexpected_issue_new,
        )

    assert exc_info.value.permit.grant_id == GRANT_ID
    assert exc_info.value.permit.expires_at == expires_at


class FixedPermitStore(FakePermitStore):
    """Store that answers every lookup with one fixed permit, whatever the grant or state."""

    def __init__(self, permit: DispatchPermit) -> None:
        """Remember the permit to return no matter what is asked for."""
        super().__init__()
        self._fixed = permit

    def get_nonterminal_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
        """Return the fixed permit even when it belongs to another grant or is terminal."""
        return self._fixed


def test_store_returning_a_permit_for_another_grant_fails_closed() -> None:
    """A wrong-grant permit is never returned, even when its stored digest matches.

    The digest comparison alone would accept it as an identical retry, so the
    grant guard must reject it first and nothing may be issued.
    """
    request = make_request()
    matching_digest = compute_binding_digest(request.binding_fields())
    store = FixedPermitStore(make_permit(grant_id="other-grant", binding_digest=matching_digest))

    with pytest.raises(ValueError, match="different grant"):
        decide_permit(request, store, now=now_utc(), issue_new=unexpected_issue_new)


@pytest.mark.parametrize("terminal_state", ["expired", "abandoned"])
def test_store_returning_a_terminal_permit_fails_closed(terminal_state: str) -> None:
    """A terminal permit is never returned as the live one, even with a matching digest.

    An abandoned permit was superseded after a consumer attestation, so handing it
    back as an identical retry would let a dead permit be used again.
    """
    request = make_request()
    matching_digest = compute_binding_digest(request.binding_fields())
    store = FixedPermitStore(make_permit(binding_digest=matching_digest, state=terminal_state))

    with pytest.raises(ValueError, match="terminal permit"):
        decide_permit(request, store, now=now_utc(), issue_new=unexpected_issue_new)


def test_store_returning_a_finalized_permit_is_still_an_identical_retry() -> None:
    """finalized is nonterminal, so the state guard must not over-reject a live one."""
    request = make_request()
    matching_digest = compute_binding_digest(request.binding_fields())
    finalized = make_permit(binding_digest=matching_digest, state="finalized")

    result = decide_permit(
        request, FixedPermitStore(finalized), now=now_utc(), issue_new=unexpected_issue_new
    )

    assert result is finalized


def test_issue_new_returning_a_permit_for_another_grant_is_rejected_before_storing() -> None:
    """issue_new must mint a permit for the requested grant; a wrong one is never stored."""
    store = FakePermitStore()

    with pytest.raises(ValueError, match="requested grant and binding digest"):
        decide_permit(
            make_request(),
            store,
            now=now_utc(),
            issue_new=lambda req, digest: make_permit(
                grant_id="other-grant", binding_digest=digest
            ),
        )

    assert store.get_nonterminal_permit_for_grant(GRANT_ID) is None
    assert store.get_nonterminal_permit_for_grant("other-grant") is None


def test_issue_new_persisting_a_different_binding_digest_is_rejected_before_storing() -> None:
    """The stored digest is the retry-identity key; issue_new must persist the computed one."""
    store = FakePermitStore()

    with pytest.raises(ValueError, match="requested grant and binding digest"):
        decide_permit(
            make_request(),
            store,
            now=now_utc(),
            issue_new=lambda req, digest: make_permit(binding_digest="e" * 64),
        )

    assert store.get_nonterminal_permit_for_grant(GRANT_ID) is None
