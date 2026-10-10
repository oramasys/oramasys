"""T1: real effect-scoped owner adapters, composed into ``AdmissionProviders``.

Each adapter wraps the actual owning package's instance (a real ``phylax.PhylaxAuthorizer``,
``telos.EndpointAuthorizer``, or ``agate`` module-level functions) and translates its real
decision into :class:`orama.graph.admission.OwnerDecision`. An adapter never recreates its
owner's policy, classification, expiry, or allow/refuse logic -- it only (a) builds the
owner's own request type from :class:`orama.graph.admission.AdmissionContext`, (b) calls the
owner's real method, and (c) translates the result. ``is_current`` always re-asks the owner
instance that actually issued the decision; it never re-derives freshness locally.

No fake/test double for any owner lives in this module or anywhere under ``src/orama/``;
those stay in ``src/tests/`` (see ``test_shipped_package_never_references_test_fakes`` in
``test_admission_decision.py``, which asserts the installed package contains no such
reference).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from orama.graph.admission import AdmissionContext, ArtifactBinding, Clock, OwnerDecision


# --- Agate: hardware-fit evidence, never authorization -----------------------


class AgateFitFn(Protocol):
    """The real ``agate.fit.assess_fit`` signature, duck-typed to avoid a hard
    module-level dependency on the agate package from this adapter's import
    path (it is still a real call, not a fake -- callers pass the actual
    function)."""

    def __call__(self, policy: Any, model: str, observation: Any, evidence: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class AgateAdapter:
    """Wraps real ``agate.assess_fit`` plus the data it needs to call it.

    ``observation_provider``/``evidence_provider`` are the integration seam:
    this adapter does not invent hardware facts or evidence classification --
    the deployment's own hardware-observation path (wherever it actually
    reads CPU/RAM/accelerator facts, and whatever collector attaches a real
    ``observed_at``/``collector`` identity to them) supplies both through
    these injected callables. See ``agate.evidence.FitEvidence``.

    ``fit_validity`` is an evidence-freshness window, not an authorization
    claim: a fit verdict is a pure function of policy + the hardware observed
    at assessment time, so it has no revocation concept of its own (see
    ``is_current`` below) -- but ``admit_artifact()`` requires every allowed
    owner decision to carry a real expiry so a stale assessment cannot be
    reused indefinitely across a long-lived admission decision. Re-admission
    on an actual hardware or policy change is a revalidation trigger
    (contract §4), handled by the admission layer re-calling
    ``admit_artifact()``, not by this expiry alone.
    """

    policy: Any  # agate.policy.PolicyStore
    assess_fit: AgateFitFn
    observation_provider: Callable[[AdmissionContext], Any]
    evidence_provider: Callable[[AdmissionContext, Any], Any]
    clock: Clock = field(default=lambda: datetime.now(UTC))
    fit_validity: timedelta = field(default_factory=lambda: timedelta(minutes=5))

    def assess(self, context: AdmissionContext) -> OwnerDecision:
        observation = self.observation_provider(context)
        evidence = self.evidence_provider(context, observation)
        decision = self.assess_fit(self.policy, context.model, observation, evidence)
        return OwnerDecision(
            owner="agate",
            allowed=decision.feasible,
            reason_code=decision.reason_code,
            decision_ref=f"agate:{context.run_id}:{context.model}",
            expires_at=self.clock() + self.fit_validity if decision.feasible else None,
            evidence_class=decision.evidence_class,
            overridable=False,
        )

    def is_current(self, decision: OwnerDecision) -> bool:
        # A fit decision is a pure function of policy + the hardware observed
        # at assessment time; it carries no expiry or revocation state of its
        # own (contract: "Agate is placement evidence, never claim/
        # authorization authority"). Re-admission on a genuine hardware or
        # policy change is a revalidation trigger handled by the admission
        # layer re-calling admit_artifact(), not by a per-boundary staleness
        # check here -- so once admitted, this adapter reports current.
        return True


# --- Telos: endpoint-use authorization, with real issuer-bound expiry --------


class TelosAuthorizer(Protocol):
    def authorize(self, request: Any) -> Any: ...

    def is_current(self, decision: Any) -> bool: ...


@dataclass
class TelosAdapter:
    """Wraps a real ``telos.EndpointAuthorizer`` instance.

    ``identity_resolver`` maps a declared endpoint purpose string to a real,
    already-resolved ``telos.contracts.EndpointIdentity`` -- resolution (DNS,
    address-class checks) is Telos's own transport-boundary concern
    (``telos.dialer.SecureDialer``), not something this adapter re-implements.
    ``request_builder`` assembles the real ``telos.contracts.EndpointUseRequest``
    from the admission context, the purpose, and its resolved identity.

    Maintains a short-lived ``decision_ref -> real decision`` cache so
    ``is_current`` can hand the *exact* object the authorizer issued back to
    ``authorizer.is_current()`` -- Telos's own freshness check is an equality
    comparison against its internally issued decisions, not a shape check, so
    a reconstructed stand-in object would never match.
    """

    authorizer: TelosAuthorizer
    identity_resolver: Callable[[AdmissionContext, str], Any]
    request_builder: Callable[[AdmissionContext, str, Any], Any]
    _issued: dict[str, Any] = field(default_factory=dict, repr=False)

    def authorize(self, context: AdmissionContext) -> tuple[OwnerDecision, ...]:
        decisions: list[OwnerDecision] = []
        for purpose in context.endpoint_purposes:
            identity = self.identity_resolver(context, purpose)
            request = self.request_builder(context, purpose, identity)
            real_decision = self.authorizer.authorize(request)
            self._issued[real_decision.decision_ref] = real_decision
            decisions.append(
                OwnerDecision(
                    owner="telos",
                    allowed=real_decision.allowed,
                    reason_code=real_decision.reason_code,
                    decision_ref=real_decision.decision_ref,
                    expires_at=real_decision.expires_at,
                    authority_epoch=real_decision.authority_epoch,
                    evidence_class="observed",
                    overridable=False,
                )
            )
        return tuple(decisions)

    def is_current(self, decision: OwnerDecision) -> bool:
        real_decision = self._issued.get(decision.decision_ref)
        if real_decision is None:
            return False
        return self.authorizer.is_current(real_decision)


# --- Phylax: principal, capability, provenance; the mandatory owner ---------


class PhylaxAuthorizer(Protocol):
    def compile(self, request: Any) -> Any: ...

    def admit(self, request: Any) -> Any: ...

    def is_current(self, decision: Any) -> bool: ...


@dataclass
class PhylaxAdapter:
    """Wraps a real ``phylax.PhylaxAuthorizer`` instance.

    Phylax's own protocol is two-phase: ``compile()`` binds an artifact and
    its requested capabilities to a ``compile_ref``; ``admit()`` then
    evaluates one capability for that compiled artifact. This adapter runs
    both phases per call rather than caching a compile_ref across calls --
    correctness (every admission re-proves compile-time admissibility) over
    a caching optimization this slice does not need.

    Field mapping from ``ArtifactBinding`` to Phylax's ``ArtifactRef`` is the
    one place this adapter makes a judgment call rather than following an
    exact 1:1 spec (the artifact-admission contract does not define a
    provenance_ref field on ArtifactBinding at all): ``graph_id`` is used as
    the artifact identity, ``implementation_digest`` (stripped of its
    ``sha256:`` domain prefix) as the code digest, and ``registry_profile_digest``
    as the provenance reference (the closest existing "where this artifact
    was vetted" signal). Confirm this mapping with Phylax's own maintainers
    before treating it as final; it is not dictated by the frozen contract.
    """

    authorizer: PhylaxAuthorizer
    artifact_ref_type: Callable[..., Any]  # phylax.contracts.ArtifactRef
    compile_request_type: Callable[..., Any]  # phylax.contracts.CompileRequest
    admit_request_type: Callable[..., Any]  # phylax.contracts.RuntimeAdmissionRequest
    evidence_class_for_principal: str | None = "observed"
    _issued: dict[str, Any] = field(default_factory=dict, repr=False)

    def _artifact_ref(self, binding: ArtifactBinding) -> Any:
        digest = binding.implementation_digest
        bare_digest = digest.removeprefix("sha256:")
        return self.artifact_ref_type(
            artifact_id=binding.graph_id,
            digest_sha256=bare_digest,
            provenance_ref=binding.registry_profile_digest,
        )

    def admit(self, binding: ArtifactBinding, context: AdmissionContext) -> OwnerDecision:
        artifact = self._artifact_ref(binding)
        compiled = self.authorizer.compile(
            self.compile_request_type(
                artifact=artifact,
                requested_capabilities=frozenset({context.capability}),
                actor_id=context.principal_id,
            )
        )
        if not compiled.allowed:
            return OwnerDecision(
                owner="phylax",
                allowed=False,
                reason_code=f"compile.{compiled.reason_code}",
                decision_ref=compiled.compile_ref,
                expires_at=None,
                evidence_class=self.evidence_class_for_principal or "derived",
                overridable=False,
            )
        real_decision = self.authorizer.admit(
            self.admit_request_type(
                compile_ref=compiled.compile_ref,
                artifact_id=artifact.artifact_id,
                digest_sha256=artifact.digest_sha256,
                capability=context.capability,
                run_id=context.run_id,
                actor_id=context.principal_id,
                evidence_class=self.evidence_class_for_principal,
            )
        )
        self._issued[real_decision.decision_id] = real_decision
        return OwnerDecision(
            owner="phylax",
            allowed=real_decision.allowed,
            reason_code=real_decision.reason_code,
            decision_ref=real_decision.decision_id,
            expires_at=real_decision.expires_at,
            authority_epoch=real_decision.authority_epoch,
            evidence_class=self.evidence_class_for_principal or "derived",
            overridable=False,
        )

    def is_current(self, decision: OwnerDecision) -> bool:
        real_decision = self._issued.get(decision.decision_ref)
        if real_decision is None:
            return False
        return self.authorizer.is_current(real_decision)
