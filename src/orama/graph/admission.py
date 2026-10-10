"""T1 slice 1: opaque callable keys and a frozen, digest-bound callable registry.

A ``CallableRef`` is a registry key, never a Python import expression. Trusted application
construction binds each key to a callable and a reviewed artifact digest, then freezes the
mapping for one invocation. Resolution is a plain dictionary lookup: no import, no
``getattr`` walk, no case folding, no alias, no fallback. Anything else refuses.

This is not a sandbox for trusted code; it only guarantees artifact strings never reach
dynamic imports.

The second half of the module is the T1 admission record: ``ArtifactBinding`` (one
immutable, domain-tagged digest per run), owner ports for Phylax, Agate and Telos, and
``admit_artifact``, which returns a discriminated ``AdmissionDecision`` built only from
actual owner decisions and fails closed on anything missing, stale or unavailable.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal, Protocol, TypeAlias

# Lowercase ASCII token: letter first, then letters, digits, '-' or '_'; at most 64 chars.
# fullmatch (not match with '$') so a trailing newline cannot slip through.
_KEY = re.compile(r"[a-z][a-z0-9_-]{0,63}")
# Domain-tagged digest: only sha256, lowercase hex, exact length.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# Core's GraphSpec.graph_id: bare, lowercase 64-hex -- no domain prefix. A
# separate pattern from _DIGEST on purpose: graph_id is Core's own identity,
# minted and owned by Core, never recomputed or re-prefixed here.
_GRAPH_ID = re.compile(r"[0-9a-f]{64}")


class AdmissionRefused(Exception):
    """Fail-closed refusal with a redacted, actionable reason code."""

    def __init__(self, reason: str) -> None:
        """Keep the machine-readable refusal reason."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CallableRef:
    """Opaque validated registry key. Every construction path validates the key."""

    key: str

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        if not isinstance(self.key, str) or _KEY.fullmatch(self.key) is None:
            raise AdmissionRefused("callable_ref.malformed")

    @classmethod
    def parse(cls, raw: object) -> CallableRef:
        """Parse a strict module:qualname key without importing anything."""
        return cls(raw)  # type: ignore[arg-type]

    def __str__(self) -> str:
        """Return the canonical module:qualname key."""
        return self.key


@dataclass(frozen=True, slots=True)
class CallableBinding:
    """A callable bound to the digest of the reviewed artifact that provides it."""

    target: Callable[..., Any]
    artifact_digest: str

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        if not callable(self.target):
            raise AdmissionRefused("callable_binding.not_callable")
        if not isinstance(self.artifact_digest, str) or _DIGEST.fullmatch(self.artifact_digest) is None:
            raise AdmissionRefused("callable_binding.bad_digest")


@dataclass(frozen=True, slots=True)
class CallableRegistry:
    """Read-only key-to-binding map, frozen for one invocation on every construction path."""

    bindings: Mapping[CallableRef, CallableBinding]

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        copied: dict[CallableRef, CallableBinding] = {}
        for ref, binding in self.bindings.items():
            if not isinstance(ref, CallableRef) or not isinstance(binding, CallableBinding):
                raise AdmissionRefused("callable_registry.bad_entry")
            copied[ref] = binding
        object.__setattr__(self, "bindings", MappingProxyType(copied))

    @classmethod
    def freeze(cls, source: Mapping[CallableRef, CallableBinding]) -> CallableRegistry:
        """Freeze a mapping into an immutable registry for one invocation."""
        return cls(source)

    def resolve(self, ref: object, *, expected_digest: str | None = None) -> Callable[..., Any]:
        """Resolve a key to its pinned callable, refusing unknown keys or changed digests."""
        if not isinstance(ref, CallableRef):
            raise AdmissionRefused("callable_ref.not_parsed")
        binding = self.bindings.get(ref)
        if binding is None:
            raise AdmissionRefused("callable_ref.unknown")
        if expected_digest is not None and binding.artifact_digest != expected_digest:
            raise AdmissionRefused("callable_binding.digest_changed")
        return binding.target


# --- T1: artifact identity and admission decisions ---------------------------
#
# Canonical encoding (frozen for T1): compact JSON, sorted keys, ASCII only, wrapped
# with a domain tag, a kind and a schema version, then SHA-256. A digest of one kind can
# never be replayed as another kind. Times are aware UTC datetimes from an injected
# clock; nothing here sleeps or reads the wall clock directly.

DIGEST_DOMAIN = "oramasys.admission"
DIGEST_SCHEMA = 1

EvidenceClass: TypeAlias = Literal["observed", "derived", "reconstructed"]
Owner: TypeAlias = Literal["phylax", "agate", "telos"]
Outcome: TypeAlias = Literal["allow", "refuse", "pending"]
Clock: TypeAlias = Callable[[], datetime]


def canonical_digest(kind: str, payload: Mapping[str, Any]) -> str:
    """Return the domain-tagged sha256 of a canonical JSON payload."""
    body = json.dumps(
        {"domain": DIGEST_DOMAIN, "schema": DIGEST_SCHEMA, "kind": kind, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(body.encode("ascii")).hexdigest()


def _digest(value: object, name: str) -> str:
    """Validate and return a lowercase sha256 hex digest."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionRefused(f"artifact_binding.bad_{name}")
    return value


def _graph_id(value: object) -> str:
    """Validate and return a bare sha256 hex graph id."""
    if not isinstance(value, str) or _GRAPH_ID.fullmatch(value) is None:
        raise AdmissionRefused("artifact_binding.bad_graph_id")
    return value


def _text(value: object, name: str) -> str:
    """Validate and return a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise AdmissionRefused(f"{name}.required")
    return value


def _utc_now(clock: Clock) -> datetime:
    """Read the clock and require an aware datetime in UTC."""
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise AdmissionRefused("clock.not_utc_aware")
    return now.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    """Immutable identity of everything one run executes (contract §2)."""

    graph_id: str
    implementation_digest: str
    state_schema_version: str
    policy_digest: str
    registry_profile_digest: str
    provider_contract_digests: tuple[str, ...]
    execution_semantics_version: str

    FIELDS = (
        "graph_id",
        "implementation_digest",
        "state_schema_version",
        "policy_digest",
        "registry_profile_digest",
        "provider_contract_digests",
        "execution_semantics_version",
    )

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        _graph_id(self.graph_id)
        for name in ("implementation_digest", "policy_digest", "registry_profile_digest"):
            _digest(getattr(self, name), name)
        _text(self.state_schema_version, "state_schema_version")
        _text(self.execution_semantics_version, "execution_semantics_version")
        providers = tuple(_digest(d, "provider_contract_digest") for d in self.provider_contract_digests)
        if len(set(providers)) != len(providers):
            raise AdmissionRefused("artifact_binding.duplicate_provider_contract")
        object.__setattr__(self, "provider_contract_digests", tuple(sorted(providers)))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> ArtifactBinding:
        """Build a binding from a mapping, rejecting unknown fields."""
        keys = set(raw)
        if keys != set(cls.FIELDS):
            raise AdmissionRefused("artifact_binding.fields_mismatch")
        values = dict(raw)
        values["provider_contract_digests"] = tuple(values["provider_contract_digests"])
        return cls(**values)

    def digest(self) -> str:
        """Return the domain-tagged digest that identifies this exact artifact."""
        payload = {name: getattr(self, name) for name in self.FIELDS}
        payload["provider_contract_digests"] = list(self.provider_contract_digests)
        return canonical_digest("artifact_binding", payload)


@dataclass(frozen=True, slots=True)
class AdmissionContext:
    """Who asks to run what. Authenticated upstream; never self-authorizing."""

    run_id: str
    principal_id: str
    capability: str
    model: str
    endpoint_purposes: tuple[str, ...]
    policy_summary_digest: str

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        for name in ("run_id", "principal_id", "capability", "model"):
            _text(getattr(self, name), name)
        _digest(self.policy_summary_digest, "policy_summary_digest")
        purposes = tuple(self.endpoint_purposes)
        if any(not isinstance(p, str) or not p for p in purposes) or len(set(purposes)) != len(purposes):
            raise AdmissionRefused("endpoint_purposes.invalid")
        object.__setattr__(self, "endpoint_purposes", tuple(sorted(purposes)))


@dataclass(frozen=True, slots=True)
class OwnerDecision:
    """One owner's actual decision, as reported by its adapter."""

    owner: Owner
    allowed: bool
    reason_code: str
    decision_ref: str
    expires_at: datetime | None
    authority_epoch: int | None = None
    evidence_class: EvidenceClass = "observed"
    overridable: bool = False


class PhylaxAdmission(Protocol):
    """Phylax admission provider used by the admission pipeline."""
    def admit(self, binding: ArtifactBinding, context: AdmissionContext) -> OwnerDecision:
        """Admit the bound artifact for the given context."""

    def is_current(self, decision: OwnerDecision) -> bool:
        """Report whether the decision is still current (unexpired and unrevoked)."""


class AgateFit(Protocol):
    """Agate fit provider used by the admission pipeline."""
    def assess(self, context: AdmissionContext) -> OwnerDecision:
        """Assess hardware fit for the given context."""

    def is_current(self, decision: OwnerDecision) -> bool:
        """Report whether the decision is still current (unexpired and unrevoked)."""


class TelosEndpoints(Protocol):
    """Telos endpoint provider used by the admission pipeline."""
    def authorize(self, context: AdmissionContext) -> tuple[OwnerDecision, ...]:
        """Authorize each declared endpoint purpose."""

    def is_current(self, decision: OwnerDecision) -> bool:
        """Report whether the decision is still current (unexpired and unrevoked)."""


@dataclass(frozen=True, slots=True)
class AdmissionProviders:
    """Owner providers supplied per invocation; production supplies none."""
    phylax: PhylaxAdmission | None
    agate: AgateFit | None
    telos: TelosEndpoints | None

    def checker(self, owner: Owner) -> Callable[[OwnerDecision], bool] | None:
        """Return the freshness checker for an owner, or None if unconfigured."""
        provider = getattr(self, owner)
        return None if provider is None else provider.is_current


def production_providers() -> AdmissionProviders | None:
    """Real owner adapters are wired by trusted application construction. Until they
    are, production has none, and admission refuses. Never a fake fallback."""
    return None


@dataclass(frozen=True, slots=True)
class AdmissionRequirements:
    """Which owners a given graph's declared effects actually require.

    Phylax is the mandatory generic admission authority for every graph,
    regardless of effects. Agate is required only for a model-dispatch
    effect; Telos only when the graph declares at least one endpoint
    purpose. An owner outside this set is never called for this admission
    (not merely ignored on refusal -- see build_admission_providers for the
    construction-time counterpart of this rule).
    """

    phylax: bool
    agate: bool
    telos: bool

    @classmethod
    def for_effects(cls, *, model_dispatch: bool, endpoint_purposes: tuple[str, ...]) -> AdmissionRequirements:
        """Derive required owners from the declared effects."""
        return cls(phylax=True, agate=model_dispatch, telos=bool(endpoint_purposes))


def build_admission_providers(
    *,
    phylax: PhylaxAdmission,
    agate: AgateFit | None = None,
    telos: TelosEndpoints | None = None,
) -> AdmissionProviders:
    """Wire real owner adapters for a deployment that has actually configured them.

    Unlike production_providers(), this never silently defaults every owner
    to None -- it raises immediately if the one unconditionally mandatory
    owner (Phylax; see AdmissionRequirements) is missing, instead of
    deferring that failure to the first admission call. Agate/Telos may be
    None for a deployment that genuinely never dispatches a model or an
    endpoint effect; admit_artifact() still refuses per-call if a graph
    that DOES declare such an effect finds its required owner unconfigured.
    """
    if phylax is None:
        raise AdmissionRefused("admission.misconfigured_phylax_mandatory")
    return AdmissionProviders(phylax=phylax, agate=agate, telos=telos)


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """Discriminated allow/refuse/pending result (contract §3). Never a Boolean."""

    outcome: Outcome
    reason_code: str
    decision_id: str
    binding_digest: str
    owner_decisions: tuple[OwnerDecision, ...]
    issued_at: datetime
    expires_at: datetime | None
    max_steps: int
    authority_epoch: int | None

    def covers(self, binding: ArtifactBinding) -> bool:
        """Report whether this decision admits exactly the given binding."""
        return self.binding_digest == binding.digest()


_DEFAULT_REQUIREMENTS: AdmissionRequirements = AdmissionRequirements(phylax=True, agate=True, telos=True)


def admit_artifact(
    binding: ArtifactBinding,
    context: AdmissionContext,
    providers: AdmissionProviders | None,
    *,
    clock: Clock,
    max_steps: int,
    requirements: AdmissionRequirements = _DEFAULT_REQUIREMENTS,
) -> AdmissionDecision:
    """Run the fixed-order admission pipeline and return allow, refuse or pending."""
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
        raise AdmissionRefused("admission.max_steps_invalid")
    now = _utc_now(clock)
    digest = binding.digest()
    collected: list[OwnerDecision] = []

    def result(outcome: Outcome, reason: str) -> AdmissionDecision:
        """Build the admission decision for an outcome and reason."""
        allowed = outcome == "allow"
        expiries = [d.expires_at for d in collected if d.expires_at is not None]
        epochs = [d.authority_epoch for d in collected if d.owner == "phylax"]
        return AdmissionDecision(
            outcome=outcome,
            reason_code=reason,
            decision_id=secrets.token_urlsafe(18),
            binding_digest=digest,
            owner_decisions=tuple(collected),
            issued_at=now,
            expires_at=min(expiries) if allowed and expiries else None,
            max_steps=max_steps,
            authority_epoch=epochs[0] if epochs else None,
        )

    if context.policy_summary_digest != binding.policy_digest:
        return result("refuse", "admission.stale_policy")
    if providers is None or providers.phylax is None:
        return result("refuse", "admission.enforcement_unavailable")
    if requirements.agate and providers.agate is None:
        return result("refuse", "admission.agate_unavailable")
    if requirements.telos and providers.telos is None:
        return result("refuse", "admission.telos_unavailable")
    # Requirements must agree with the context: Phylax is always required, and declared
    # endpoint purposes need Telos, or endpoint use would proceed with no Telos
    # decision for the gate to re-check (fail closed, never open).
    if not requirements.phylax or (context.endpoint_purposes and not requirements.telos):
        return result("refuse", "admission.requirements_mismatch")

    calls: list[tuple[Owner, Callable[[], Any]]] = [
        ("phylax", lambda: (providers.phylax.admit(binding, context),)),  # type: ignore[union-attr]
    ]
    if requirements.agate:
        calls.append(("agate", lambda: (providers.agate.assess(context),)))  # type: ignore[union-attr]
    if requirements.telos:
        calls.append(("telos", lambda: tuple(providers.telos.authorize(context))))  # type: ignore[union-attr]
    for owner, call in calls:
        try:
            decisions = call()
        except Exception:  # noqa: BLE001 - an unavailable owner refuses, never a default allow
            return result("refuse", f"admission.{owner}_unavailable")
        for decision in decisions:
            if not isinstance(decision, OwnerDecision) or decision.owner != owner:
                return result("refuse", f"admission.{owner}_bad_decision")
            collected.append(decision)
            if decision.evidence_class != "observed":
                return result("refuse", "admission.evidence_not_observed")
            if not decision.allowed:
                outcome: Outcome = "pending" if decision.overridable else "refuse"
                return result(outcome, f"{owner}.{decision.reason_code}")
            if decision.expires_at is None:
                return result("refuse", "admission.decision_without_expiry")
            if decision.expires_at <= now:
                return result("refuse", "admission.expired")
    if not any(d.owner == "phylax" and d.authority_epoch is not None for d in collected):
        return result("refuse", "admission.authority_epoch_missing")
    return result("allow", "admission.allowed")
