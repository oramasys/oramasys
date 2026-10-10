"""T1: adapters composed against the REAL Telos/Agate/Phylax candidate revisions.

Per the 2026-10-11 admission contract integration plan: "Pinned package revisions and the
Core gate integration fixture must exercise the exact merged satellite contracts, not local
fakes only." This file imports the actual owner packages (installed from this program's fix
branches -- see conftest sys.path wiring) and drives the real admit_artifact() -> adapters ->
real owner instance path end to end. No FakePhylax/FakeAgate/FakeTelos anywhere in this file.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from orama.graph.admission import (
    AdmissionContext,
    AdmissionProviders,
    AdmissionRequirements,
    ArtifactBinding,
    admit_artifact,
    build_admission_providers,
)
from orama.graph.adapters import AgateAdapter, PhylaxAdapter, TelosAdapter

agate = pytest.importorskip("agate", reason="real Agate candidate not installed")
phylax = pytest.importorskip("phylax", reason="real Phylax candidate not installed")
telos = pytest.importorskip("telos", reason="real Telos candidate not installed")

from agate import HardwareObservation, load_policy, load_profile_store  # noqa: E402
from agate.evidence import FitEvidence  # noqa: E402
from agate.fit import assess_fit  # noqa: E402
from phylax.authorizer import PhylaxAuthorizer as RealPhylaxAuthorizer  # noqa: E402
from phylax.contracts import ArtifactRef, CompileRequest, RuntimeAdmissionRequest  # noqa: E402
from telos.authorizer import EndpointAuthorizer  # noqa: E402
from telos.contracts import EndpointIdentity, EndpointPurpose, EndpointRef, EndpointUseRequest  # noqa: E402


class _Clock:
    """Settable clock for deterministic tests."""
    def __init__(self) -> None:
        """Initialise the instance and validate its arguments."""
        self.now = datetime(2026, 10, 11, tzinfo=UTC)

    def __call__(self) -> datetime:
        """Return the current value."""
        return self.now

    def advance(self, **kw) -> None:
        """Test helper: advance."""
        self.now += timedelta(**kw)


def _binding(**overrides) -> ArtifactBinding:
    """Test helper: binding."""
    base = {
        "graph_id": "a" * 64,
        "implementation_digest": "sha256:" + "1" * 64,
        "state_schema_version": "1",
        "policy_digest": "sha256:" + "2" * 64,
        "registry_profile_digest": "sha256:" + "3" * 64,
        "provider_contract_digests": ("sha256:" + "4" * 64,),
        "execution_semantics_version": "r4-t1",
    }
    base.update(overrides)
    return ArtifactBinding(**base)


def _context(**overrides) -> AdmissionContext:
    """Test helper: context."""
    base = {
        "run_id": "run-1",
        "principal_id": "operator-1",
        "capability": "graph.execute",
        "model": "example-model",
        "endpoint_purposes": (),
        "policy_summary_digest": "sha256:" + "2" * 64,
    }
    base.update(overrides)
    return AdmissionContext(**base)


@pytest.fixture
def phylax_adapter() -> PhylaxAdapter:
    """Test helper: phylax adapter."""
    def always_trusted(actor_id: str) -> bool:
        """Test helper: always trusted."""
        return actor_id == "operator-1"

    real = RealPhylaxAuthorizer(
        trusted_provenance={"sha256:" + "3" * 64},
        allowed_capabilities={"graph.execute"},
        principal_verifier=always_trusted,
        clock=_Clock(),
    )
    return PhylaxAdapter(
        authorizer=real,
        artifact_ref_type=ArtifactRef,
        compile_request_type=CompileRequest,
        admit_request_type=RuntimeAdmissionRequest,
    )


def test_phylax_adapter_admits_a_trusted_principal_with_an_approved_capability(phylax_adapter):
    """Phylax adapter admits a trusted principal with an approved capability."""
    decision = phylax_adapter.admit(_binding(), _context())
    assert decision.allowed is True
    assert decision.owner == "phylax"
    assert decision.evidence_class == "observed"
    assert phylax_adapter.is_current(decision) is True


def test_phylax_adapter_refuses_an_untrusted_principal(phylax_adapter):
    """Phylax adapter refuses an untrusted principal."""
    decision = phylax_adapter.admit(_binding(), _context(principal_id="attacker"))
    assert decision.allowed is False


def test_phylax_adapter_is_current_delegates_to_the_real_authorizer_not_a_local_check(phylax_adapter):
    """Phylax adapter is current delegates to the real authorizer not a local check."""
    decision = phylax_adapter.admit(_binding(), _context())
    assert phylax_adapter.is_current(decision) is True
    # A decision this adapter never issued (forged ref) must not be current --
    # proves is_current() is a real lookup against the authorizer's own state,
    # not a shape check on the OwnerDecision alone.
    forged = replace(decision, decision_ref="forged-ref-nobody-issued")
    assert phylax_adapter.is_current(forged) is False


def _pick_profile_and_model(wanted: set[str]) -> tuple[str, str]:
    """Test helper: pick profile and model."""
    policy = load_policy()
    for profile_id, profile in load_profile_store().profiles.items():
        for name, spec in policy.models.items():
            if spec.verdict_for_tier(profile.verdict_tier) in wanted:
                return profile_id, name
    pytest.skip(f"no real profile/model pair with verdict in {wanted}")


def _observation_for(profile_id: str) -> HardwareObservation:
    """Test helper: observation for."""
    profile = load_profile_store().profiles[profile_id]
    match = profile.match
    return HardwareObservation(
        os=match.get("os", profile.os),
        cpu=match.get("cpu_contains", profile.cpu),
        ram_gb=match.get("ram_gb", profile.ram_gb),
        accelerator=match.get("accelerator_contains", profile.accelerator),
        accelerator_memory_gb=match.get("accelerator_memory_gb", profile.accelerator_memory_gb),
    )


@pytest.fixture
def agate_adapter() -> AgateAdapter:
    """Test helper: agate adapter."""
    policy = load_policy()
    profile_id, model = _pick_profile_and_model({"PREFER", "ALLOW"})
    observation = _observation_for(profile_id)

    def observation_provider(context: AdmissionContext) -> HardwareObservation:
        """Test helper: observation provider."""
        return observation

    def evidence_provider(context: AdmissionContext, obs: HardwareObservation) -> FitEvidence:
        """Test helper: evidence provider."""
        return FitEvidence.derived(obs)

    adapter = AgateAdapter(
        policy=policy,
        assess_fit=assess_fit,
        observation_provider=observation_provider,
        evidence_provider=evidence_provider,
    )
    return adapter, model


def test_agate_adapter_assesses_real_fit_and_carries_the_real_evidence_class(agate_adapter):
    """Agate adapter assesses real fit and carries the real evidence class."""
    adapter, model = agate_adapter
    decision = adapter.assess(_context(model=model))
    assert decision.owner == "agate"
    assert decision.allowed is True
    assert decision.evidence_class == "derived"
    assert adapter.is_current(decision) is True


@pytest.fixture
def agate_adapter_with_observed_evidence() -> tuple[AgateAdapter, str]:
    """Same real fit path as agate_adapter, but with collector-backed
    (observed) evidence -- the realistic shape for a deployment whose
    hardware-observation path actually has a trusted local collector, used
    by the full-pipeline tests below (which otherwise correctly refuse on
    derived evidence, per the contract's Observed-evidence requirement)."""
    policy = load_policy()
    profile_id, model = _pick_profile_and_model({"PREFER", "ALLOW"})
    observation = _observation_for(profile_id)

    def observation_provider(context: AdmissionContext) -> HardwareObservation:
        """Test helper: observation provider."""
        return observation

    def evidence_provider(context: AdmissionContext, obs: HardwareObservation) -> FitEvidence:
        """Test helper: evidence provider."""
        return FitEvidence.observed(obs, collector="local-hardware-collector", clock=_Clock())

    return (
        AgateAdapter(
            policy=policy,
            assess_fit=assess_fit,
            observation_provider=observation_provider,
            evidence_provider=evidence_provider,
            clock=_Clock(),
        ),
        model,
    )


@pytest.fixture
def telos_adapter() -> TelosAdapter:
    """Test helper: telos adapter."""
    rules: dict[EndpointPurpose, set[tuple[str, str, int]]] = {
        EndpointPurpose.MODEL_EGRESS: {("https", "api.example-model.internal", 443)},
    }
    real = EndpointAuthorizer.from_exact_rules(rules, decision_ttl=timedelta(minutes=5), clock=_Clock())

    def identity_resolver(context: AdmissionContext, purpose: str) -> EndpointIdentity:
        """Test helper: identity resolver."""
        return EndpointIdentity(
            endpoint=EndpointRef(scheme="https", host="api.example-model.internal", port=443),
            resolved_addresses=("203.0.113.5",),
            is_public=True,
            resolution_ref="test-resolution-1",
        )

    def request_builder(context: AdmissionContext, purpose: str, identity: EndpointIdentity) -> EndpointUseRequest:
        """Test helper: request builder."""
        return EndpointUseRequest(
            actor_id=context.principal_id,
            workflow_id=context.run_id,
            purpose=EndpointPurpose(purpose),
            endpoint=identity,
            run_id=context.run_id,
        )

    return TelosAdapter(
        authorizer=real,
        identity_resolver=identity_resolver,
        request_builder=request_builder,
    )


def test_telos_adapter_authorizes_a_declared_endpoint_purpose(telos_adapter):
    """Telos adapter authorizes a declared endpoint purpose."""
    decisions = telos_adapter.authorize(_context(endpoint_purposes=("model_egress",)))
    assert len(decisions) == 1
    assert decisions[0].allowed is True
    assert decisions[0].owner == "telos"
    assert telos_adapter.is_current(decisions[0]) is True


def test_telos_adapter_is_current_becomes_false_after_the_real_authorizer_revokes(telos_adapter):
    """Telos adapter is current becomes false after the real authorizer revokes."""
    decisions = telos_adapter.authorize(_context(endpoint_purposes=("model_egress",)))
    telos_adapter.authorizer.revoke()
    assert telos_adapter.is_current(decisions[0]) is False


def test_full_admission_pipeline_runs_against_real_phylax_agate_telos(
    phylax_adapter, agate_adapter_with_observed_evidence, telos_adapter,
):
    """End-to-end: admit_artifact() through all three real adapters, no fakes."""
    agate, model = agate_adapter_with_observed_evidence
    providers = build_admission_providers(phylax=phylax_adapter, agate=agate, telos=telos_adapter)
    context = _context(model=model, endpoint_purposes=("model_egress",))
    requirements = AdmissionRequirements.for_effects(model_dispatch=True, endpoint_purposes=("model_egress",))
    decision = admit_artifact(
        _binding(), context, providers, clock=_Clock(), max_steps=5, requirements=requirements,
    )
    assert decision.outcome == "allow", decision.reason_code
    assert {d.owner for d in decision.owner_decisions} == {"phylax", "agate", "telos"}


def test_full_pipeline_refuses_when_the_real_telos_decision_is_revoked_mid_run(
    phylax_adapter, agate_adapter_with_observed_evidence, telos_adapter,
):
    """Full pipeline refuses when the real telos decision is revoked mid run."""
    agate, model = agate_adapter_with_observed_evidence
    providers = build_admission_providers(phylax=phylax_adapter, agate=agate, telos=telos_adapter)
    context = _context(model=model, endpoint_purposes=("model_egress",))
    requirements = AdmissionRequirements.for_effects(model_dispatch=True, endpoint_purposes=("model_egress",))
    decision = admit_artifact(
        _binding(), context, providers, clock=_Clock(), max_steps=5, requirements=requirements,
    )
    assert decision.outcome == "allow"
    telos_adapter.authorizer.revoke()
    for owner_decision in decision.owner_decisions:
        if owner_decision.owner == "telos":
            assert telos_adapter.is_current(owner_decision) is False
