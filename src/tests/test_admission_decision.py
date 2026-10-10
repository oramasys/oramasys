"""T1: ArtifactBinding identity and admit_artifact (artifact-admission contract §2, §3, §5).

Admission returns a discriminated decision bound to one artifact digest, built only
from actual owner decisions (Phylax, Agate, Telos). Missing owners, owner failures,
non-Observed evidence and decisions without expiry all fail closed.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from orama.graph.admission import (
    AdmissionContext,
    AdmissionProviders,
    AdmissionRefused,
    ArtifactBinding,
    admit_artifact,
    canonical_digest,
    production_providers,
)
from tests.admission_fakes import FakeAgate, FakeClock, FakePhylax, FakeTelos

D = "sha256:" + "1" * 64
P = "sha256:" + "2" * 64


def binding(**overrides) -> ArtifactBinding:
    base = {
        "graph_id": "sha256:" + "0" * 64,
        "implementation_digest": D,
        "state_schema_version": "1",
        "policy_digest": P,
        "registry_profile_digest": "sha256:" + "3" * 64,
        "provider_contract_digests": ("sha256:" + "4" * 64,),
        "execution_semantics_version": "r4-t1",
    }
    base.update(overrides)
    return ArtifactBinding(**base)


def context(**overrides) -> AdmissionContext:
    base = {
        "run_id": "run-1",
        "principal_id": "operator",
        "capability": "graph.execute",
        "model": "example-model",
        "endpoint_purposes": ("model_egress",),
        "policy_summary_digest": P,
    }
    base.update(overrides)
    return AdmissionContext(**base)


def providers(clock=None, **kw):
    clock = clock or FakeClock()
    return AdmissionProviders(
        phylax=kw.get("phylax") or FakePhylax(clock),
        agate=kw.get("agate") or FakeAgate(clock),
        telos=kw.get("telos") or FakeTelos(clock),
    ), clock


# --- canonical identity ----------------------------------------------------


def test_digest_is_domain_tagged_and_kind_separated():
    payload = {"a": "1"}
    assert canonical_digest("artifact_binding", payload) != canonical_digest("policy", payload)
    assert canonical_digest("artifact_binding", payload).startswith("sha256:")


def test_binding_digest_is_stable_and_order_insensitive_for_provider_contracts():
    a = binding(provider_contract_digests=(D, P))
    b = binding(provider_contract_digests=(P, D))
    assert a.digest() == b.digest()


def test_binding_rejects_bad_digests_and_duplicates():
    with pytest.raises(AdmissionRefused):
        binding(implementation_digest="md5:abc")
    with pytest.raises(AdmissionRefused):
        binding(provider_contract_digests=(D, D))
    with pytest.raises(AdmissionRefused):
        binding(state_schema_version="")


def test_binding_from_mapping_fails_closed_on_unknown_fields():
    raw = {
        "graph_id": "sha256:" + "0" * 64,
        "implementation_digest": D,
        "state_schema_version": "1",
        "policy_digest": P,
        "registry_profile_digest": "sha256:" + "3" * 64,
        "provider_contract_digests": [D],
        "execution_semantics_version": "r4-t1",
    }
    assert ArtifactBinding.from_mapping(raw).implementation_digest == D
    with pytest.raises(AdmissionRefused):
        ArtifactBinding.from_mapping({**raw, "authority": "root"})
    with pytest.raises(AdmissionRefused):
        ArtifactBinding.from_mapping({k: v for k, v in raw.items() if k != "policy_digest"})


# --- admission outcomes ------------------------------------------------------


def test_allowed_admission_binds_digest_epoch_and_earliest_expiry():
    provs, clock = providers()
    provs.telos.ttl = 30
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "allow"
    assert decision.binding_digest == binding().digest()
    assert decision.authority_epoch == 1
    assert decision.max_steps == 5
    assert (decision.expires_at - clock.now).total_seconds() == 30
    assert {d.owner for d in decision.owner_decisions} == {"phylax", "agate", "telos"}
    assert decision.decision_id


def test_same_graph_changed_code_invalidates_admission():
    provs, clock = providers()
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    changed = binding(implementation_digest="sha256:" + "9" * 64)
    assert changed.graph_id == binding().graph_id
    assert decision.covers(binding())
    assert not decision.covers(changed)


def test_stale_policy_summary_refused():
    provs, clock = providers()
    decision = admit_artifact(binding(), context(policy_summary_digest="sha256:" + "8" * 64),
                              provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "admission.stale_policy"


@pytest.mark.parametrize("owner", ["phylax", "agate"])
def test_nonobserved_source_cannot_admit(owner):
    clock = FakeClock()
    fake = FakePhylax(clock, evidence_class="derived") if owner == "phylax" else FakeAgate(clock, evidence_class="reconstructed")
    provs, _ = providers(clock, **{owner: fake})
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "admission.evidence_not_observed"


def test_missing_hardware_or_principal_refused():
    provs, clock = providers()
    with pytest.raises(AdmissionRefused):
        context(principal_id="")
    no_hw = admit_artifact(binding(), context(), replace(provs, agate=None), clock=clock, max_steps=5)
    assert no_hw.outcome == "refuse"
    assert no_hw.reason_code == "admission.enforcement_unavailable"


def test_absent_enforcement_service_fails_closed():
    clock = FakeClock()
    assert admit_artifact(binding(), context(), None, clock=clock, max_steps=5).outcome == "refuse"
    provs, _ = providers(clock, phylax=FakePhylax(clock, raise_error=True))
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "admission.phylax_unavailable"


def test_owner_refusals_carry_their_reason():
    clock = FakeClock()
    provs, _ = providers(clock, phylax=FakePhylax(clock, allow=False, reason="digest_mismatch"))
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "phylax.digest_mismatch"


def test_impossible_hardware_is_not_overridable():
    clock = FakeClock()
    provs, _ = providers(clock, agate=FakeAgate(clock, feasible=False, reason="model_forbidden_on_profile"))
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "agate.model_forbidden_on_profile"


def test_only_an_explicitly_overridable_refusal_is_pending():
    clock = FakeClock()
    provs, _ = providers(clock, agate=FakeAgate(clock, feasible=False, overridable=True, reason="fit_borderline"))
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "pending"
    assert decision.reason_code == "agate.fit_borderline"


def test_telos_denial_refuses():
    clock = FakeClock()
    provs, _ = providers(clock, telos=FakeTelos(clock, allow=False))
    assert admit_artifact(binding(), context(), provs, clock=clock, max_steps=5).reason_code == "telos.unknown_purpose"


def test_allowed_owner_decision_without_expiry_fails_closed():
    clock = FakeClock()
    provs, _ = providers(clock, telos=FakeTelos(clock, no_expiry=True))
    decision = admit_artifact(binding(), context(), provs, clock=clock, max_steps=5)
    assert decision.outcome == "refuse"
    assert decision.reason_code == "admission.decision_without_expiry"


def test_max_steps_and_clock_are_validated():
    provs, clock = providers()
    with pytest.raises(AdmissionRefused):
        admit_artifact(binding(), context(), provs, clock=clock, max_steps=0)
    from datetime import datetime
    with pytest.raises(AdmissionRefused):
        admit_artifact(binding(), context(), provs, clock=lambda: datetime(2026, 1, 1), max_steps=1)


def test_production_has_no_providers_and_therefore_refuses():
    assert production_providers() is None
    decision = admit_artifact(binding(), context(), production_providers(), clock=FakeClock(), max_steps=1)
    assert decision.outcome == "refuse"


def test_shipped_package_never_references_test_fakes():
    from pathlib import Path

    import orama

    root = Path(orama.__file__).parent
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "admission_fakes" not in text, path
        assert "from tests" not in text and "import tests" not in text, path
