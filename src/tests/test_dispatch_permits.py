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
ATTEMPT_ID = "attempt-1"


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
        "attempt_id": ATTEMPT_ID,
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
        "attempt_id": ATTEMPT_ID,
        "state": "issued",
    }
    fields.update(overrides)
    return DispatchPermit(**fields)  # type: ignore[arg-type]


class FakePermitStore:
    """In-memory PermitStore fake: holds any permit (terminal or not) per grant."""

    def __init__(self) -> None:
        """Start with no stored permits."""
        self._by_grant: dict[str, DispatchPermit] = {}

    def get_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
        """Return any stored permit for the grant, terminal or not."""
        return self._by_grant.get(grant_id)

    def insert_permit(self, permit: DispatchPermit) -> None:
        """Persist a brand-new permit, enforcing at most one per grant."""
        if permit.grant_id in self._by_grant:
            raise AssertionError("store invariant violated: a permit already exists")
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
        """Record the call and return a permit for the request."""
        calls.append((req, digest))
        return make_permit(binding_digest=digest)

    result = decide_permit(request, store, now=now_utc(), issue_new=issue_new)

    assert len(calls) == 1
    assert result.grant_id == GRANT_ID
    assert store.get_permit_for_grant(GRANT_ID) is result


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
    assert store.get_permit_for_grant(GRANT_ID) is first


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
    assert store.get_permit_for_grant(GRANT_ID) == stored


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

    def get_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
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
def test_ordinary_request_conflicts_with_terminal_history_instead_of_minting(
    terminal_state: str,
) -> None:
    """Terminal history is visible: a NEW attempt_id never mints a second permit."""
    store = FakePermitStore()
    request = make_request()
    store.insert_permit(
        make_permit(
            binding_digest=compute_binding_digest(request.binding_fields()),
            state=terminal_state,
        )
    )

    with pytest.raises(PermitRefused) as exc_info:
        decide_permit(
            make_request(attempt_id="attempt-2"),
            store,
            now=now_utc(),
            issue_new=unexpected_issue_new,
        )

    assert exc_info.value.code == "permit.conflict"


def test_store_with_expired_and_abandoned_history_never_mints_a_second_permit() -> None:
    """Expired and abandoned permits both on record: an ordinary request still conflicts."""

    class HistoryStore(FakePermitStore):
        """Exposes the latest of a terminal history (expired then abandoned)."""

        def __init__(self, history: list[DispatchPermit]) -> None:
            """Keep the whole history; the latest entry answers lookups."""
            super().__init__()
            self.history = history
            self.inserted: list[DispatchPermit] = []

        def get_permit_for_grant(self, grant_id: str) -> DispatchPermit | None:
            """Return the latest permit of the history regardless of state."""
            return self.history[-1]

        def insert_permit(self, permit: DispatchPermit) -> None:
            """Record any attempted insert so the test can prove none happened."""
            self.inserted.append(permit)

    request = make_request(attempt_id="attempt-3")
    digest = compute_binding_digest(request.binding_fields())
    store = HistoryStore(
        [
            make_permit(permit_id="p-old", binding_digest=digest, state="expired",
                        attempt_id="attempt-0"),
            make_permit(permit_id="p-new", binding_digest=digest, state="abandoned",
                        attempt_id="attempt-1"),
        ]
    )

    with pytest.raises(PermitRefused) as exc_info:
        decide_permit(request, store, now=now_utc(), issue_new=unexpected_issue_new)

    assert exc_info.value.code == "permit.conflict"
    assert store.inserted == []


def test_new_attempt_id_with_equal_binding_on_live_permit_conflicts() -> None:
    """Equal binding but a different attempt_id is not an identical retry."""
    store = FakePermitStore()
    decide_permit(
        make_request(),
        store,
        now=now_utc(),
        issue_new=lambda req, digest: make_permit(binding_digest=digest),
    )

    with pytest.raises(PermitRefused) as exc_info:
        decide_permit(
            make_request(attempt_id="attempt-2"),
            store,
            now=now_utc(),
            issue_new=unexpected_issue_new,
        )

    assert exc_info.value.code == "permit.conflict"


def test_identical_retry_on_abandoned_permit_is_refused_not_returned() -> None:
    """The same binding and attempt on an abandoned permit never returns the dead permit."""
    request = make_request()
    digest = compute_binding_digest(request.binding_fields())
    store = FixedPermitStore(make_permit(binding_digest=digest, state="abandoned"))

    with pytest.raises(PermitRefused):
        decide_permit(request, store, now=now_utc(), issue_new=unexpected_issue_new)


def test_identical_retry_on_expired_state_permit_raises_expired() -> None:
    """The same binding and attempt on a permit recorded expired stays ExpiredPermit."""
    request = make_request()
    digest = compute_binding_digest(request.binding_fields())
    store = FixedPermitStore(make_permit(binding_digest=digest, state="expired"))

    with pytest.raises(ExpiredPermit):
        decide_permit(request, store, now=now_utc(), issue_new=unexpected_issue_new)


@pytest.mark.parametrize("bad", ["", "   "])
def test_permit_request_requires_a_non_blank_attempt_id(bad: str) -> None:
    """attempt_id is required and non-blank."""
    with pytest.raises(ValueError, match="attempt_id"):
        make_request(attempt_id=bad)


def test_attempt_id_is_not_part_of_the_binding_digest() -> None:
    """attempt_id never enters the nine-field binding digest."""
    first = make_request(attempt_id="attempt-1")
    second = make_request(attempt_id="attempt-9")

    assert compute_binding_digest(first.binding_fields()) == compute_binding_digest(
        second.binding_fields()
    )


def test_issue_new_returning_a_permit_for_another_attempt_is_rejected() -> None:
    """issue_new must persist the request's attempt_id, the retry-identity half."""
    store = FakePermitStore()

    with pytest.raises(ValueError, match="attempt_id"):
        decide_permit(
            make_request(),
            store,
            now=now_utc(),
            issue_new=lambda req, digest: make_permit(binding_digest=digest, attempt_id="x"),
        )

    assert store.get_permit_for_grant(GRANT_ID) is None


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

    assert store.get_permit_for_grant(GRANT_ID) is None
    assert store.get_permit_for_grant("other-grant") is None


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

    assert store.get_permit_for_grant(GRANT_ID) is None
