"""T2 Task 6: Oramasys consumer port for Phylax adjustment grant verification.

Per PHYLAX-ADJUSTMENT-GRANT-DESIGN-v2.md Section 13 (Ratified 2026-10-12):
- Oramasys OWNS the port and imports nothing from phylax and nothing from nacl.
- Verification and revocation evidence checks run strictly OUTSIDE the SQLite ledger transaction.
- Refusals raise AdjustmentGrantRefused with a CLOSED reason set.
- Default wiring is DenyAllGrantVerifier.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, TypeAlias

GrantKind: TypeAlias = Literal["settle", "release"]

RefusalCode: TypeAlias = Literal[
    # Verification outcomes: the vocabulary shared with the issuer's verifier.
    "grant.malformed",
    "grant.schema_unsupported",
    "grant.key_unknown",
    "grant.signature_invalid",
    "grant.expired",
    "grant.future_dated",
    "grant.revoked",
    "revocation.stale",
    "verifier.unavailable",
    # Consumption outcomes: decided by the ledger, never by the issuer.
    "grant.principal_mismatch",
    "grant.store_mismatch",
    "grant.epoch_fenced",
    "grant.hold_ineligible",
    "grant.basis_mismatch",
    "grant.units_exceed_remaining",
    "grant.digest_conflict",
    "grant.clock_regressed",
]

VERIFICATION_REFUSAL_CODES: frozenset[str] = frozenset({
    "grant.malformed",
    "grant.schema_unsupported",
    "grant.key_unknown",
    "grant.signature_invalid",
    "grant.expired",
    "grant.future_dated",
    "grant.revoked",
    "revocation.stale",
    "verifier.unavailable",
})

CONSUMPTION_REFUSAL_CODES: frozenset[str] = frozenset({
    "grant.principal_mismatch",
    "grant.store_mismatch",
    "grant.epoch_fenced",
    "grant.hold_ineligible",
    "grant.basis_mismatch",
    "grant.units_exceed_remaining",
    "grant.digest_conflict",
    "grant.clock_regressed",
})

CLOSED_REFUSAL_CODES: frozenset[str] = VERIFICATION_REFUSAL_CODES | CONSUMPTION_REFUSAL_CODES


class AdjustmentGrantRefused(Exception):
    """Fail-closed grant refusal with an explicit closed reason code."""

    def __init__(self, code: RefusalCode) -> None:
        """Initialize refusal with verified closed reason code."""
        if code not in CLOSED_REFUSAL_CODES:
            raise ValueError(f"invalid refusal code {code!r}; must be in closed vocabulary")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class VerifiedGrant:
    """The immutable verified grant facts passed to the ledger consumption boundary."""

    grant_id: str
    principal: str
    run_id: str
    hold_id: str
    kind: GrantKind
    units: int
    units_basis: str
    ledger_cost_basis: str
    hold_fence_epoch: int
    consumer_lease_epoch: int
    ledger_store_id: str
    issued_at: datetime
    expires_at: datetime
    payload_digest: str
    verifier_id: str

    def __post_init__(self) -> None:
        """Fail closed on invalid field invariants."""
        if not self.grant_id.strip():
            raise ValueError("grant_id is required")
        if not self.principal.strip():
            raise ValueError("principal is required")
        if not self.run_id.strip():
            raise ValueError("run_id is required")
        if not self.hold_id.strip():
            raise ValueError("hold_id is required")
        if self.kind not in ("settle", "release"):
            raise ValueError(f"invalid grant kind {self.kind!r}")
        if isinstance(self.units, bool) or not isinstance(self.units, int) or self.units <= 0:
            raise ValueError("units must be a positive integer")
        if not self.units_basis.strip():
            raise ValueError("units_basis is required")
        if not self.ledger_cost_basis.strip():
            raise ValueError("ledger_cost_basis is required")
        if isinstance(self.hold_fence_epoch, bool) or not isinstance(self.hold_fence_epoch, int) or self.hold_fence_epoch < 1:
            raise ValueError("hold_fence_epoch must be a positive integer")
        if isinstance(self.consumer_lease_epoch, bool) or not isinstance(self.consumer_lease_epoch, int) or self.consumer_lease_epoch < 1:
            raise ValueError("consumer_lease_epoch must be a positive integer")
        if not self.ledger_store_id.strip():
            raise ValueError("ledger_store_id is required")
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("issued_at must be an aware UTC datetime")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be an aware UTC datetime")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be strictly greater than issued_at")
        if not self.payload_digest.strip() or len(self.payload_digest) != 64:
            raise ValueError("payload_digest must be a 64-character hex digest")
        if not self.verifier_id.strip():
            raise ValueError("verifier_id is required")


@dataclass(frozen=True, slots=True)
class RevocationObservation:
    """Observed revocation state of a grant."""

    grant_id: str
    revoked: bool
    observed_at: datetime

    def __post_init__(self) -> None:
        """Validate observation fields at construction."""
        if not self.grant_id.strip():
            raise ValueError("grant_id is required")
        if type(self.revoked) is not bool:
            raise ValueError("revoked must be a boolean; a missing answer is not 'not revoked'")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must be an aware UTC datetime")


REVOCATION_MAX_AGE: timedelta = timedelta(seconds=60)
"""Oldest a revocation observation may be and still count as fresh; exactly this age is fresh."""
REVOCATION_MAX_FUTURE_SKEW: timedelta = timedelta(seconds=5)
"""How far in the future an observation's stamp may be (clock skew) before it is stale."""


def revocation_observation_fresh(now: datetime, observed_at: datetime) -> bool:
    """Return True when a revocation observation is fresh at ``now`` (the one shared rule).

    Stale means older than ``REVOCATION_MAX_AGE`` (a 60 s old observation is still fresh), more than
    ``REVOCATION_MAX_FUTURE_SKEW`` ahead of ``now``, or without a timezone (a naive stamp cannot be
    placed in time, so it never counts as fresh).
    """
    if (
        not isinstance(now, datetime) or not isinstance(observed_at, datetime)
        or now.tzinfo is None or observed_at.tzinfo is None
        or now.utcoffset() is None or observed_at.utcoffset() is None
    ):
        return False
    age = now - observed_at
    return -REVOCATION_MAX_FUTURE_SKEW <= age <= REVOCATION_MAX_AGE


class AdjustmentGrantVerifier(Protocol):
    """Consumer port for verifying adjustment grants and observing revocation."""

    def verify(self, wire: bytes) -> VerifiedGrant:
        """Verify the wire grant attestation and return verified facts or raise AdjustmentGrantRefused."""
        ...

    def revocation(self, grant_id: str) -> RevocationObservation:
        """Query revocation status of grant_id or raise AdjustmentGrantRefused."""
        ...


class DenyAllGrantVerifier:
    """Default fail-closed verifier when no authority is wired."""

    def verify(self, wire: bytes) -> VerifiedGrant:
        """Reject all verification attempts fail-closed."""
        raise AdjustmentGrantRefused("verifier.unavailable")

    def revocation(self, grant_id: str) -> RevocationObservation:
        """Reject all revocation queries fail-closed."""
        raise AdjustmentGrantRefused("verifier.unavailable")


@dataclass(frozen=True, slots=True)
class AdjustmentReceipt:
    """The immutable receipt produced when a verified grant is atomically consumed."""

    grant_id: str
    run_id: str
    hold_id: str
    principal: str
    ledger_store_id: str
    kind: GrantKind
    units_basis: str
    balance_delta: int
    consumed_at: datetime
    verifier_id: str
    payload_digest: str

    def to_json(self) -> str:
        """Serialize the receipt to canonical JSON string."""
        import json
        payload = {
            "grant_id": self.grant_id,
            "run_id": self.run_id,
            "hold_id": self.hold_id,
            "principal": self.principal,
            "ledger_store_id": self.ledger_store_id,
            "kind": self.kind,
            "units_basis": self.units_basis,
            "balance_delta": self.balance_delta,
            "consumed_at": self.consumed_at.isoformat(),
            "verifier_id": self.verifier_id,
            "payload_digest": self.payload_digest,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def from_json(cls, text: str) -> AdjustmentReceipt:
        """Deserialize an immutable AdjustmentReceipt from JSON text."""
        import json
        data = json.loads(text)
        return cls(
            grant_id=data["grant_id"],
            run_id=data["run_id"],
            hold_id=data["hold_id"],
            principal=data["principal"],
            ledger_store_id=data["ledger_store_id"],
            kind=data["kind"],
            units_basis=data["units_basis"],
            balance_delta=int(data["balance_delta"]),
            consumed_at=datetime.fromisoformat(data["consumed_at"]),
            verifier_id=data["verifier_id"],
            payload_digest=data["payload_digest"],
        )


def _refusal_from(exc: BaseException) -> AdjustmentGrantRefused:
    """Normalize any verifier failure into the closed vocabulary.

    A verifier lives behind an injected boundary and may raise its own type (the
    issuer's refusal enum, a transport error). Only a code that is in the
    verification vocabulary is honoured; anything else becomes
    ``verifier.unavailable`` so no free text or unknown reason crosses inward.
    """
    raw = getattr(exc, "reason", None) or getattr(exc, "code", None)
    code = str(getattr(raw, "value", raw)) if raw is not None else ""
    if code in VERIFICATION_REFUSAL_CODES:
        return AdjustmentGrantRefused(code)  # type: ignore[arg-type]
    return AdjustmentGrantRefused("verifier.unavailable")


def _rebuild(cls: type, source: Any) -> Any:
    """Copy a structurally compatible result into this module's own type."""
    try:
        return cls(**{f.name: getattr(source, f.name) for f in fields(cls)})
    except (AttributeError, TypeError, ValueError) as exc:
        raise AdjustmentGrantRefused("grant.malformed") from exc


class AdjustmentGrantConsumer:
    """The only supported way to spend a grant: verify, then consume atomically.

    Owns the injected verifier (deny-all when none is wired), normalizes its
    failures, rebuilds its results into Oramasys-owned types, answers an exact
    retry from the ledger, and performs every remote call before the ledger
    transaction opens.
    """

    def __init__(
        self,
        ledger: Any,
        verifier: AdjustmentGrantVerifier | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind a ledger and an optional verifier; absent verifier denies all."""
        self._ledger = ledger
        self._verifier: AdjustmentGrantVerifier = verifier or DenyAllGrantVerifier()
        self._clock = clock or (lambda: datetime.now(UTC))

    def consume(self, wire: bytes, *, caller_principal: str) -> AdjustmentReceipt:
        """Verify ``wire`` and spend it; an exact retry returns the stored receipt."""
        try:
            verified = _rebuild(VerifiedGrant, self._verifier.verify(wire))
        except Exception as exc:  # noqa: BLE001 - normalized below
            refusal = _refusal_from(exc)
            replay = self._replay_after_refusal(wire, caller_principal, refusal)
            if replay is not None:
                return replay
            raise refusal from exc
        stored = self._ledger.retry_adjustment_grant(
            grant_id=verified.grant_id,
            caller_principal=caller_principal,
            payload_digest=verified.payload_digest,
        )
        if stored is not None:
            return stored
        try:
            observation = _rebuild(
                RevocationObservation, self._verifier.revocation(verified.grant_id)
            )
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _refusal_from(exc) from exc
        return self._ledger.consume_adjustment_grant(
            verified, observation, caller_principal=caller_principal, clock=self._clock
        )

    def _replay_after_refusal(
        self, wire: bytes, caller_principal: str, refusal: AdjustmentGrantRefused
    ) -> AdjustmentReceipt | None:
        """Answer an exact retry whose grant has since expired or been revoked.

        The wire's grant id and digest are only lookup keys: the stored receipt
        was produced from a verified grant, and the ledger compares principal
        and digest before returning it. No other refusal is ever replayed.
        """
        if refusal.code not in {"grant.expired", "grant.revoked"}:
            return None
        try:
            body = json.loads(wire)
            return self._ledger.retry_adjustment_grant(
                grant_id=str(body["grant_id"]),
                caller_principal=caller_principal,
                payload_digest=str(body["payload_digest"]),
            )
        except (ValueError, KeyError, TypeError, AdjustmentGrantRefused):
            return None
