"""Consumer view of the issuer's signed public revocation state (decision D3, consumer side).

Pure: no I/O, no clock of its own, no cryptography. The signature check goes through the injected
``StateSignatureVerifier`` port; production wires an adapter outside ``src/orama``, as for issuer
events. The state is a signed *summary* of the issuer chain; this view only ever adds refusals.

Fail closed: a state that is absent, unreadable, malformed, unsigned, for another issuer, stale,
or older than what the consumer has already acknowledged makes ``revoked`` answer ``True``.
"Unavailable" is never read as "nothing revoked". Contract:
``docs/consumer-revocation-state-view.md``.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from orama.graph.dispatch_consumer_wire import (
    GENESIS_EVENT_DIGEST,
    MAX_SAFE_INTEGER,
    SCHEMA_VERSION,
)

MAX_STATE_AGE_SECONDS: Final = 60
CLOCK_SKEW_SECONDS: Final = 5
MAX_STATE_BYTES: Final = 1_048_576
_ENVELOPE_FIELDS: Final = frozenset({"body", "signature", "issuer_key_id"})
_BODY_FIELDS: Final = frozenset({
    "schema_version", "issuer_id", "head_version", "head_event_digest", "generated_at",
    "issuer_revoked", "revoked_grants", "revoked_approvals", "cascades",
})
_CASCADE_FIELDS: Final = frozenset({"version", "approval_id", "issuer_authority_version", "grant_ids"})
VIEW_REFUSAL_CODES: Final = frozenset({
    "state.unavailable", "state.malformed", "state.signature", "state.issuer_mismatch",
    "state.stale", "state.behind_acknowledged", "state.head_conflict",
})


class StateSignatureVerifier(Protocol):
    """Injected port: verify an issuer state signature for a known key."""

    def verify_state(self, key_id: str, body: Mapping[str, Any], signature: str) -> bool:
        """Return True only if ``signature`` is the issuer's valid state signature over ``body``."""


class StateSource(Protocol):
    """Injected port: return the published state bytes, or None when it cannot be read."""

    def read(self) -> bytes | None:
        """Return the current published state bytes, or None if unavailable."""


class StateRefused(Exception):
    """A closed-vocabulary state refusal; every one means "treat as revoked"."""

    def __init__(self, code: str) -> None:
        """Record the stable machine-readable code."""
        if code not in VIEW_REFUSAL_CODES:
            raise ValueError(f"unknown state refusal code: {code}")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RevocationStateFacts:
    """The verified sets a state publishes."""

    head_version: int
    head_event_digest: str
    issuer_revoked: bool
    revoked_grants: frozenset[str]
    revoked_approvals: frozenset[str]
    cascade_grants: frozenset[str]


def reason_from_facts(
    facts: RevocationStateFacts, grant_id: str, approval_ref: str | None
) -> str | None:
    """Return the Rule 4 reason in the consumer's own order, or None.

    Order matches ``dispatch_revocations.refusal_reason``: issuer, grant, approval chain, cascade,
    undeclared approval. ``approval_ref`` ``""`` is a single approval; ``None`` is undeclared.
    """
    if facts.issuer_revoked:
        return "issuer_revoked"
    if grant_id in facts.revoked_grants:
        return "grant_revoked"
    if approval_ref and approval_ref in facts.revoked_approvals:
        return "approval_revoked"
    if grant_id in facts.cascade_grants:
        return "cascade_listed"
    if approval_ref is None and facts.revoked_approvals:
        return "approval_undeclared"
    return None


def _is_digest(value: object) -> bool:
    """Return True for 64 lowercase hexadecimal characters."""
    return (
        isinstance(value, str) and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _ids(value: object) -> frozenset[str]:
    """Return a strictly sorted, duplicate-free identifier list as a set, or refuse."""
    if not isinstance(value, list):
        raise StateRefused("state.malformed")
    if any(not isinstance(i, str) or not i or not i.isascii() or not i.isprintable() or " " in i for i in value):
        raise StateRefused("state.malformed")
    if value != sorted(set(value)):  # element types are known to be str here, so this cannot raise
        raise StateRefused("state.malformed")
    return frozenset(value)


def _cascade_grants(value: object) -> frozenset[str]:
    """Validate the closed cascade list and return every grant it names."""
    if not isinstance(value, list):
        raise StateRefused("state.malformed")
    out: set[str] = set()
    for cascade in value:
        if not isinstance(cascade, dict) or set(cascade) != _CASCADE_FIELDS:
            raise StateRefused("state.malformed")
        for number in (cascade["version"], cascade["issuer_authority_version"]):
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= MAX_SAFE_INTEGER:
                raise StateRefused("state.malformed")
        _ids([cascade["approval_id"]])  # a real, well-formed identifier string, never null
        out |= _ids(cascade["grant_ids"])
    return frozenset(out)


def _stamp(value: object) -> datetime:
    """Parse the fixed six-digit UTC wire timestamp or refuse."""
    if not isinstance(value, str) or len(value) != 27 or not value.endswith("Z"):
        raise StateRefused("state.malformed")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise StateRefused("state.malformed") from error


def verify_state(
    raw: object,
    *,
    verifier: StateSignatureVerifier,
    issuer_id: str,
    now: datetime,
    acknowledged: tuple[int, str] | None = None,
    max_age_seconds: int = MAX_STATE_AGE_SECONDS,
) -> RevocationStateFacts:
    """Verify a published state and return its facts, or raise :class:`StateRefused`."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_STATE_BYTES:
        raise StateRefused("state.malformed")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise StateRefused("state.malformed") from error
    if (
        not isinstance(document, dict) or set(document) != _ENVELOPE_FIELDS
        or json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") != bytes(raw)
    ):
        raise StateRefused("state.malformed")
    body, signature, key_id = document["body"], document["signature"], document["issuer_key_id"]
    if not isinstance(body, dict) or set(body) != _BODY_FIELDS or (
        type(body["schema_version"]) is not int or body["schema_version"] != SCHEMA_VERSION
    ):
        raise StateRefused("state.malformed")
    if not isinstance(signature, str) or not isinstance(key_id, str) or not key_id:
        raise StateRefused("state.malformed")
    generated = _stamp(body["generated_at"])
    head, digest = body["head_version"], body["head_event_digest"]
    if isinstance(head, bool) or not isinstance(head, int) or not 0 <= head <= MAX_SAFE_INTEGER or not _is_digest(digest):
        raise StateRefused("state.malformed")
    if (head == 0) != (digest == GENESIS_EVENT_DIGEST) or not isinstance(body["issuer_revoked"], bool):
        raise StateRefused("state.malformed")
    facts = RevocationStateFacts(
        head, digest, body["issuer_revoked"], _ids(body["revoked_grants"]),
        _ids(body["revoked_approvals"]), _cascade_grants(body["cascades"]),
    )
    if body["issuer_id"] != issuer_id:
        raise StateRefused("state.issuer_mismatch")
    try:
        valid = verifier.verify_state(key_id, body, signature)
    except Exception as error:
        raise StateRefused("state.signature") from error
    if valid is not True:
        raise StateRefused("state.signature")
    if now - generated > timedelta(seconds=max_age_seconds) or generated - now > timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise StateRefused("state.stale")
    if acknowledged is not None:
        ack_version, ack_digest = acknowledged
        if head < ack_version:
            raise StateRefused("state.behind_acknowledged")
        if head == ack_version and digest != ack_digest:
            raise StateRefused("state.head_conflict")
    return facts


class SignedStateRevocationView:
    """``RevocationLookup`` over the issuer's signed public state; fails closed to "revoked"."""

    def __init__(
        self,
        source: StateSource,
        verifier: StateSignatureVerifier,
        *,
        issuer_id: str,
        clock: Callable[[], datetime],
        acknowledged_head: Callable[[], tuple[int, str] | None] | None = None,
        approval_ref_for: Callable[[str], str | None] | None = None,
    ) -> None:
        """Bind the source, signature port, expected issuer and optional anti-rollback head."""
        if not isinstance(issuer_id, str) or not issuer_id.strip():
            raise ValueError("issuer_id must be non-blank text")
        self._source, self._verifier, self._issuer_id = source, verifier, issuer_id
        self._clock, self._acknowledged = clock, acknowledged_head
        self._approval_ref_for = approval_ref_for
        self.refusal: str | None = None

    def reason(self, grant_id: str, approval_ref: str | None) -> str | None:
        """Return the refusal reason, ``"state_unverified"`` when the state cannot be trusted."""
        facts = self._facts()
        if facts is None:
            return "state_unverified"
        return reason_from_facts(facts, grant_id, approval_ref)

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Return True when the state revokes the grant, its approval chain or issuer, or is unusable."""
        if issuer_id != self._issuer_id:
            self.refusal = "state.issuer_mismatch"
            return True
        try:
            approval = None if self._approval_ref_for is None else self._approval_ref_for(grant_id)
        except Exception:  # noqa: BLE001 - a resolver fault must fail closed, never propagate
            self.refusal = "state.unavailable"
            return True
        return self.reason(grant_id, approval) is not None

    def _facts(self) -> RevocationStateFacts | None:
        """Read and verify the state; any failure is recorded and returns None."""
        self.refusal = None
        try:
            raw = self._source.read()
            if raw is None:
                raise StateRefused("state.unavailable")
            acknowledged = None if self._acknowledged is None else self._acknowledged()
            return verify_state(
                raw, verifier=self._verifier, issuer_id=self._issuer_id, now=self._clock(),
                acknowledged=acknowledged,
            )
        except StateRefused as refusal:
            self.refusal = refusal.code
        except Exception:  # noqa: BLE001 - any fault must fail closed, never read as "not revoked"
            self.refusal = "state.unavailable"
        return None


class CompositeRevocationLookup:
    """Revoked unless EVERY member answers exactly ``False``.

    ``True``, ``None``, any other value and any exception all count as revoked, matching the final
    boundary, which accepts only an exact ``False``.
    """

    def __init__(self, *lookups: Any) -> None:
        """Hold at least one member lookup."""
        if not lookups:
            raise ValueError("at least one revocation lookup is required")
        self._lookups: Sequence[Any] = lookups

    def revoked(self, *, grant_id: str, issuer_id: str) -> bool:
        """Return True unless every member answers exactly False."""
        for lookup in self._lookups:
            try:
                if lookup.revoked(grant_id=grant_id, issuer_id=issuer_id) is not False:
                    return True
            except Exception:  # noqa: BLE001 - fail closed
                return True
        return False
