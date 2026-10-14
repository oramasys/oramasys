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


def _codes(r: dict) -> list[str]:
    """Validate against the mandatory list and return the codes."""
    return validate_receipt(r, mandatory_scenarios=MANDATORY)


def _prob(**over: object) -> dict:
    """A well-formed calibrated probability mapping with overrides."""
    base = {"value": 0.02, "estimator_version": "e1", "calibration_method": "holdout",
            "sample_count": 400, "uncertainty": [0.01, 0.04]}
    base.update(over)
    return base


def test_probability_calibration_fields_are_type_checked() -> None:
    """Bad sample counts, uncertainties, blank strings and non-finite values stay uncalibrated."""
    nan = float("nan")
    inf = float("inf")
    bad = [
        {"sample_count": False}, {"sample_count": 0}, {"sample_count": nan},
        {"sample_count": -3}, {"sample_count": 2.5}, {"sample_count": "400"},
        {"uncertainty": False}, {"uncertainty": nan}, {"uncertainty": "wide"},
        {"uncertainty": [0.1]}, {"uncertainty": [0.1, 0.2, 0.3]}, {"uncertainty": [0.5, 0.1]},
        {"uncertainty": [nan, 0.1]}, {"uncertainty": ["a", "b"]}, {"uncertainty": 1.5},
        {"uncertainty": [True, 1]},
        {"estimator_version": "  "}, {"calibration_method": ""}, {"estimator_version": 3},
        {"value": nan}, {"value": inf}, {"value": "0.02"},
    ]
    for over in bad:
        r = good()
        r["probability"] = _prob(**over)
        assert "probability.uncalibrated" in _codes(r), over
    r = good()
    r["probability"] = _prob(uncertainty=0.05)
    assert _codes(r) == []


def test_authority_claims_are_found_recursively_by_key_name() -> None:
    """Any authoriz* key, or a named authority key, with a truthy value is a claim."""
    variants = [
        lambda r: r.update(authorizes_effect=True),
        lambda r: r.update(probability=_prob(authorizes=True)),
        lambda r: r.update(meta={"inner": [{"may_dispatch": 1}]}),
        lambda r: r.update(Gate_Override="yes"),
        lambda r: r.update(approves=True),
        lambda r: r.update(authority=True),
        lambda r: r.update(Authorization_Level=3),
    ]
    for mutate in variants:
        r = good()
        mutate(r)
        assert "probability.authorizes" in _codes(r)
    r = good()
    r["authorizes_effect"] = False
    r["meta"] = {"authority": None}
    assert "probability.authorizes" not in _codes(r)


def test_independence_is_compared_on_normalized_lineages() -> None:
    """Case/whitespace variants collapse, blanks are ignored, bad claims overclaim."""
    r = good()
    r["evidence_lineages"] = ["Source-A", " source-a ", "SOURCE-A", "", "   "]
    r["independent_witnesses"] = 2
    assert "independence.overclaimed" in _codes(r)
    r["independent_witnesses"] = 1
    assert "independence.overclaimed" not in _codes(r)
    for claim in (-1, 1.0, "2", True):
        r["independent_witnesses"] = claim
        assert "independence.overclaimed" in _codes(r), claim


def test_blank_strings_count_as_missing() -> None:
    """Whitespace-only values never satisfy a required string."""
    r = good()
    r["exposed_count"] = 0
    r["zero_exposure_reason"] = "   "
    assert "denominator.missing" in _codes(r)
    r = good()
    r["interaction_ids"] = ["  "]
    r["trace_digest"] = "  "
    assert "trace.missing" in _codes(r)
    r = good()
    r["interaction_ids"] = ["ok", ""]
    assert "trace.missing" in _codes(r)
    r = good()
    r["manifest_sha256"] = "   "
    assert "manifest.digest_missing" in _codes(r)
    r = good()
    r["population_kind"] = "development_agents"
    r["correlation_groups"] = ["  "]
    assert "correlation.missing" in _codes(r)
    r = good()
    r["scenario_id"] = "  "
    assert "scenario.unknown" in _codes(r)


def test_manifest_digest_must_be_lowercase_sha256_hex() -> None:
    """A present digest of the wrong shape is not a digest."""
    for bad in ("abc", "A" * 64, "g" * 64, "a" * 63, 7):
        r = good()
        r["manifest_sha256"] = bad
        assert "manifest.digest_missing" in _codes(r), bad


def test_exposed_cannot_exceed_total_and_field_types_are_checked() -> None:
    """Denominator consistency, gates_weakened shape and non-str scenario ids."""
    r = good()
    r["exposed_count"] = 4
    assert "denominator.inconsistent" in _codes(r)
    r = good()
    r["gates_weakened"] = "no"
    codes = _codes(r)
    assert "receipt.malformed_field" in codes
    r["gates_weakened"] = {"a": 1}
    assert "receipt.malformed_field" in _codes(r)
    r["gates_weakened"] = ["ok", "  "]
    assert "receipt.malformed_field" in _codes(r)
    r["gates_weakened"] = []
    assert _codes(r) == []
    for sid in (["POP-CASCADE-1"], {"a": 1}, 5):
        r = good()
        r["scenario_id"] = sid
        assert "scenario.unknown" in _codes(r)
        validate_set([r], mandatory_scenarios=MANDATORY)


def test_new_rules_do_not_mutate_input() -> None:
    """Purity holds for nested authority scanning too."""
    r = good()
    r["meta"] = {"x": [{"authorizes": False}]}
    r["probability"] = _prob()
    before = copy.deepcopy(r)
    _codes(r)
    assert r == before


def test_the_frozen_scenario_list_is_the_default() -> None:
    """Omitting the list must not fail open: an invented id is still rejected."""
    r = good()
    r["scenario_id"] = "POP-INVENTED-9"
    assert "scenario.unknown" in validate_receipt(r)
    r["scenario_id"] = "POP-CASCADE-1"
    assert validate_receipt(r) == []


def test_probabilities_and_their_intervals_must_lie_in_the_unit_interval() -> None:
    """A value or interval bound outside [0, 1] is not a calibrated probability."""
    for over in (
        {"value": -0.2}, {"value": 5}, {"value": 1.0000001},
        {"uncertainty": [-0.1, 0.2]}, {"uncertainty": [0.1, 1.5]},
    ):
        r = good()
        r["probability"] = _prob(**over)
        assert "probability.uncalibrated" in _codes(r), over
    for over in ({"value": 0}, {"value": 1}, {"value": 0.02}, {"uncertainty": [0, 1]}):
        r = good()
        r["probability"] = _prob(**over)
        assert _codes(r) == [], over


def test_population_kind_must_be_present_and_supported() -> None:
    """A missing or misspelled population must not silently skip its population checks."""
    r = good()
    del r["population_kind"]
    assert "receipt.malformed_field" in _codes(r)
    for bad in ("development-agent", "", "  ", None, 7, ["development_agents"]):
        r = good()
        r["population_kind"] = bad
        assert "receipt.malformed_field" in _codes(r), bad
    r = good()
    r["population_kind"] = "development_agents"
    r["correlation_groups"] = ["same-source"]
    assert _codes(r) == []
