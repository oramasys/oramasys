"""Behavioural tests for the interaction-risk receipt validator."""

from __future__ import annotations

import copy

import json
from pathlib import Path

from orama.compat.interaction_risk_receipt import (
    MANDATORY_SCENARIOS,
    validate_receipt,
    validate_set,
)

FIXTURE = Path(__file__).parent / "fixtures" / "interaction_risk" / "scenario_register.json"
POPULATIONS = ("development_agents", "runtime_workers")

MANDATORY = list(MANDATORY_SCENARIOS)


def good() -> dict:
    """A structurally complete runtime-worker receipt."""
    return {
        "scenario_id": "POP-CASCADE-1",
        "population_kind": "runtime_workers",
        "manifest_sha256": "a" * 64,
        "interaction_ids": ["run-1:node::a::0"],
        "exposed_count": 3,
        "counts": {"accepted": 1, "rejected": 0, "pending": 0, "unknown": 2},
        "interaction_total": 3,
    }


def test_a_complete_receipt_has_no_problems() -> None:
    """The baseline fixture is clean, so every later failure is caused by its mutation."""
    assert validate_receipt(good(), mandatory_scenarios=MANDATORY) == []


def test_pre_freeze_receipts_may_lack_a_digest_but_not_a_complete_one() -> None:
    """Exploratory results are allowed without a digest; a complete receipt is not."""
    r = good()
    del r["manifest_sha256"]
    assert validate_receipt(r, mandatory_scenarios=MANDATORY, complete=False) == []
    assert "manifest.digest_missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_an_unknown_scenario_id_is_rejected() -> None:
    """Only frozen scenario ids can be reported."""
    r = good()
    r["scenario_id"] = "POP-INVENTED-9"
    assert "scenario.unknown" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_a_missing_mandatory_scenario_makes_the_set_incomplete() -> None:
    """Five good receipts out of six is not a complete set."""
    receipts = []
    for sid in MANDATORY[:-1]:
        r = good()
        r["scenario_id"] = sid
        if sid in ("POP-COMMON-1", "POP-CONFORM-1", "POP-MOTIVE-1"):
            r["population_kind"] = "development_agents"
            r["correlation_groups"] = ["same-source"]
        receipts.append(r)
    report = validate_set(receipts, mandatory_scenarios=MANDATORY)
    assert report["POP-MOTIVE-1"] == ["scenario.missing"]


def test_unknown_outcomes_cannot_be_omitted() -> None:
    """Dropping the unknown count would hide the uncertain cases; it is a structural error."""
    r = good()
    del r["counts"]["unknown"]
    assert "counts.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_counts_must_sum_to_the_interaction_total() -> None:
    """Silently dropping interactions is detectable."""
    r = good()
    r["interaction_total"] = 10
    assert "counts.inconsistent" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_a_zero_denominator_needs_a_stated_reason() -> None:
    """Zero events in a small fixture is not zero risk, and must say why exposure was zero."""
    r = good()
    r["exposed_count"] = 0
    assert "denominator.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r["zero_exposure_reason"] = "fixture injected no concurrent attempts"
    assert "denominator.missing" not in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_a_trace_is_required() -> None:
    """A receipt with no interaction ids and no trace digest evidences nothing."""
    r = good()
    r["interaction_ids"] = []
    assert "trace.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_an_uncalibrated_probability_is_rejected_and_unknown_is_allowed() -> None:
    """A number needs its estimator and calibration; 'unknown' is simply absence."""
    r = good()
    r["probability"] = {"value": 0.02}
    assert "probability.uncalibrated" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r["probability"] = {"value": 0.02, "estimator_version": "e1", "calibration_method": "holdout",
                        "sample_count": 400, "uncertainty": [0.01, 0.04]}
    assert validate_receipt(r, mandatory_scenarios=MANDATORY) == []
    assert validate_receipt(good(), mandatory_scenarios=MANDATORY) == []  # no probability at all


def test_a_probability_can_never_authorize_dispatch() -> None:
    """Soft risk evidence never relaxes a hard gate: the claim itself is a defect."""
    r = good()
    r["risk_authorizes_dispatch"] = True
    assert "probability.authorizes" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r = good()
    r["probability"] = {"value": 0.001, "estimator_version": "e1", "calibration_method": "m",
                                    "sample_count": 1000, "uncertainty": [0, 0.01], "authorizes_dispatch": True}
    assert "probability.authorizes" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_independent_witnesses_cannot_exceed_distinct_lineages() -> None:
    """Three readers of one source are one witness, however many agents they are."""
    r = good()
    r["population_kind"] = "development_agents"
    r["correlation_groups"] = ["shared-source"]
    r["evidence_lineages"] = ["source-A", "source-A", "source-A"]
    r["independent_witnesses"] = 3
    assert "independence.overclaimed" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r["evidence_lineages"] = ["source-A", "tree-count", "junit-run"]
    assert "independence.overclaimed" not in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_development_agent_receipts_must_name_correlation_groups() -> None:
    """Common model, source, host or credential dependencies must be recorded."""
    r = good()
    r["population_kind"] = "development_agents"
    assert "correlation.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_a_governance_variant_that_weakens_a_gate_is_invalid() -> None:
    """Interventions are compared only while every mandatory gate is preserved."""
    r = good()
    r["gates_weakened"] = ["exact-head-review"]
    assert "governance.weakened" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_an_unknown_scenario_inside_a_set_is_flagged_and_does_not_hide_missing() -> None:
    """A stray id is reported as unknown while every mandatory id is still checked."""
    stray = good()
    stray["scenario_id"] = "POP-INVENTED-9"
    report = validate_set([stray], mandatory_scenarios=MANDATORY)
    assert "scenario.unknown" in report["POP-INVENTED-9"]
    assert all(report[sid] == ["scenario.missing"] for sid in MANDATORY)


def test_boolean_counts_are_rejected() -> None:
    """True/False are not counts, in the denominator, the outcome counts or the total."""
    r = good()
    r["exposed_count"] = True
    assert "denominator.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r = good()
    r["counts"]["unknown"] = True
    assert "counts.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)
    r = good()
    r["interaction_total"] = True
    assert "counts.missing" in validate_receipt(r, mandatory_scenarios=MANDATORY)


def test_a_duplicated_scenario_id_in_a_set_is_flagged() -> None:
    """Two receipts for one scenario cannot silently overwrite each other."""
    a = good()
    b = good()
    report = validate_set([a, b], mandatory_scenarios=MANDATORY)
    assert "scenario.duplicate" in report["POP-CASCADE-1"]


def _register() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_register_covers_every_mandatory_scenario_for_both_populations() -> None:
    """Each mandatory scenario plus governance latency has an entry per population."""
    entries = _register()["entries"]
    pairs = {(e["id"], e["population_kind"]) for e in entries}
    assert len(pairs) == len(entries)
    for sid in [*MANDATORY, "GOV-LATENCY-1"]:
        for pop in POPULATIONS:
            assert (sid, pop) in pairs


def test_every_register_entry_is_complete_and_carries_no_invented_probability() -> None:
    """Definition, measurement, trigger fixture present; probability is null."""
    for e in _register()["entries"]:
        assert e["definition"].strip() and e["trigger_fixture"].strip()
        assert e["measurement"]["counted"].strip() and e["measurement"]["denominator"].strip()
        assert e["probability"] is None


def test_worked_example_receipts_validate_per_population() -> None:
    """One worked receipt per population passes the validator as declared."""
    examples = _register()["worked_examples"]
    assert {x["receipt"]["population_kind"] for x in examples} == set(POPULATIONS)
    for x in examples:
        problems = validate_receipt(
            x["receipt"], mandatory_scenarios=MANDATORY, complete=x["complete"]
        )
        assert problems == [], (x["receipt"]["scenario_id"], problems)
        assert "probability" not in x["receipt"]


def test_validation_does_not_mutate_its_input() -> None:
    """A pure function: the receipt is unchanged after validation."""
    r = good()
    before = copy.deepcopy(r)
    validate_receipt(r, mandatory_scenarios=MANDATORY)
    assert r == before
