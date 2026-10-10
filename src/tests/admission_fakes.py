"""Deterministic owner fakes for T1 tests. Test-only: lives under src/tests, which the
wheel never ships (packages = ["src/orama"]). Production never selects these."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from orama.graph.admission import AdmissionContext, ArtifactBinding, OwnerDecision

T0 = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class FakePhylax:
    clock: FakeClock
    allow: bool = True
    reason: str = "allowed"
    ttl: float = 60
    evidence_class: str = "observed"
    epoch: int = 1
    raise_error: bool = False
    seen: list[str] = field(default_factory=list)

    def admit(self, binding: ArtifactBinding, context: AdmissionContext) -> OwnerDecision:
        if self.raise_error:
            raise ConnectionError("phylax down")
        self.seen.append(binding.digest())
        return OwnerDecision(
            owner="phylax",
            allowed=self.allow,
            reason_code=self.reason if not self.allow else "allowed",
            decision_ref="phylax-1",
            expires_at=self.clock.now + timedelta(seconds=self.ttl),
            authority_epoch=self.epoch,
            evidence_class=self.evidence_class,  # type: ignore[arg-type]
        )

    def revoke(self) -> None:
        self.epoch += 1

    def is_current(self, decision: OwnerDecision) -> bool:
        return (
            decision.allowed
            and decision.authority_epoch == self.epoch
            and decision.expires_at is not None
            and self.clock.now < decision.expires_at
        )


@dataclass
class FakeAgate:
    clock: FakeClock
    feasible: bool = True
    overridable: bool = False
    reason: str = "fit_allow"
    ttl: float = 60
    evidence_class: str = "observed"

    def assess(self, context: AdmissionContext) -> OwnerDecision:
        return OwnerDecision(
            owner="agate",
            allowed=self.feasible,
            reason_code=self.reason,
            decision_ref="agate-1",
            expires_at=self.clock.now + timedelta(seconds=self.ttl),
            evidence_class=self.evidence_class,  # type: ignore[arg-type]
            overridable=self.overridable,
        )

    def is_current(self, decision: OwnerDecision) -> bool:
        return decision.allowed and decision.expires_at is not None and self.clock.now < decision.expires_at


@dataclass
class FakeTelos:
    clock: FakeClock
    allow: bool = True
    ttl: float = 60
    no_expiry: bool = False

    def authorize(self, context: AdmissionContext) -> tuple[OwnerDecision, ...]:
        return tuple(
            OwnerDecision(
                owner="telos",
                allowed=self.allow,
                reason_code="allowed" if self.allow else "unknown_purpose",
                decision_ref=f"telos-{purpose}",
                expires_at=None if self.no_expiry else self.clock.now + timedelta(seconds=self.ttl),
            )
            for purpose in context.endpoint_purposes
        )

    def is_current(self, decision: OwnerDecision) -> bool:
        return decision.allowed and decision.expires_at is not None and self.clock.now < decision.expires_at
