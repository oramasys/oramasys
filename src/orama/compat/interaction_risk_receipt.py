"""Interaction-risk assessment receipt validator (stdlib only, not wired anywhere).

Encodes the measurement rules of the assessment contract (S-A1 section 18.3/18.4) as pure functions so a
receipt can be judged structurally complete or incomplete mechanically. The assessment frame is
interaction-risk assessment (six modes + governance latency).

Scope limits, stated once and binding:
  * It judges STRUCTURE and honesty of reporting only.
  * It never produces a risk number, and nothing it returns can authorize an effect or a dispatch.

Rules (problem codes):
  scenario.unknown          scenario id not in the frozen mandatory list
  scenario.missing          a mandatory scenario has no receipt (checked by validate_set)
  scenario.duplicate        a set holds more than one receipt for the same scenario id (validate_set)
  manifest.digest_missing   a COMPLETE receipt must be bound to a frozen manifest digest
  trace.missing             no interaction ids / trace digest
  denominator.missing       exposed count absent, or zero without a stated reason
  counts.missing            accepted/rejected/pending/unknown and the total must be present (unknown is never omitted)
  counts.inconsistent       the four counts do not sum to the interaction total
  denominator.inconsistent  exposed count exceeds the interaction total
  receipt.malformed_field   a field has the wrong container type or holds blank entries, or population_kind
                            is missing or not a supported population
  probability.uncalibrated  a probability needs estimator version, calibration method, sample count, uncertainty
  probability.authorizes    a probability (or any soft risk value) claims authority over a gate
  independence.overclaimed  independent witnesses claimed exceed distinct evidence lineages
  correlation.missing       development-agent receipts must name their correlation groups
  governance.weakened       a governance variant relaxed a mandatory gate
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

MANDATORY_SCENARIOS: tuple[str, ...] = (
    "POP-CASCADE-1",
    "POP-COMMS-1",
    "POP-COMMON-1",
    "POP-CONFORM-1",
    "POP-CAPABILITY-1",
    "POP-MOTIVE-1",
)
POPULATION_KINDS: tuple[str, ...] = ("development_agents", "runtime_workers")
COUNT_KEYS = ("accepted", "rejected", "pending", "unknown")
PROB_REQUIRED = ("estimator_version", "calibration_method", "sample_count", "uncertainty")


def _is_int(value: Any) -> bool:
    """Return True for a real integer; booleans are not counts."""
    return isinstance(value, int) and not isinstance(value, bool)


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_AUTHORITY_NAMES = frozenset({"authority", "may_dispatch", "gate_override", "approves"})


def _nonblank(value: Any) -> bool:
    """Return True for a string with at least one non-whitespace character."""
    return isinstance(value, str) and bool(value.strip())


def _finite(value: Any) -> bool:
    """Return True for a real, finite number (booleans are not numbers here)."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _unit_interval(value: Any) -> bool:
    """Return True for a finite number in [0, 1], the only range a probability may take."""
    return _finite(value) and 0 <= value <= 1


def _nonblank_list(value: Any) -> bool:
    """Return True for a non-empty list/tuple whose entries are all non-blank strings."""
    return isinstance(value, (list, tuple)) and bool(value) and all(_nonblank(x) for x in value)


def _is_authority_key(key: Any) -> bool:
    """Return True when a key name asserts authority over a gate or dispatch."""
    name = str(key).strip().lower()
    return "authoriz" in name or name in _AUTHORITY_NAMES


def _claims_authority(node: Any) -> bool:
    """Return True when any nested mapping key claims authority with a truthy value."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            if _is_authority_key(key) and value:
                return True
            if _claims_authority(value):
                return True
    elif isinstance(node, (list, tuple)):
        return any(_claims_authority(item) for item in node)
    return False


def _denominator_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return denominator.* codes: absent/invalid/unexplained zero, or exceeding the total."""
    exposed = receipt.get("exposed_count")
    if not _is_int(exposed) or exposed < 0:
        return ["denominator.missing"]
    if exposed == 0 and not _nonblank(receipt.get("zero_exposure_reason")):
        return ["denominator.missing"]
    total = receipt.get("interaction_total")
    if _is_int(total) and exposed > total:
        return ["denominator.inconsistent"]
    return []


def _count_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return counts.* problem codes for the outcome counts and interaction total."""
    counts = receipt.get("counts")
    total = receipt.get("interaction_total")
    if not isinstance(counts, Mapping) or any(
        not _is_int(counts.get(k)) or counts[k] < 0 for k in COUNT_KEYS
    ):
        return ["counts.missing"]
    if not _is_int(total):
        return ["counts.missing"]
    if sum(counts[k] for k in COUNT_KEYS) != total:
        return ["counts.inconsistent"]
    return []


def _uncertainty_ok(value: Any) -> bool:
    """Return True for a scalar in [0, 1] or an ordered (lo, hi) pair inside [0, 1]."""
    if _finite(value):
        return _unit_interval(value)
    if isinstance(value, (list, tuple)) and len(value) == 2 and all(_unit_interval(x) for x in value):
        return value[0] <= value[1]
    return False


def _calibrated(probability: Any) -> bool:
    """Return True when a probability mapping carries a complete, well-typed calibration."""
    if not isinstance(probability, Mapping):
        return False
    value = probability.get("value")
    return (
        _nonblank(probability.get("estimator_version"))
        and _nonblank(probability.get("calibration_method"))
        and _is_int(probability.get("sample_count"))
        and probability["sample_count"] > 0
        and _uncertainty_ok(probability.get("uncertainty"))
        and (value is None or _unit_interval(value))
    )


def _probability_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return probability.* problem codes; an absent probability is fine (unknown)."""
    problems: list[str] = []
    probability = receipt.get("probability")
    if probability is not None and not _calibrated(probability):
        problems.append("probability.uncalibrated")
    if _claims_authority(receipt):
        problems.append("probability.authorizes")
    return problems


def _independence_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return independence.overclaimed when witnesses exceed normalized distinct lineages."""
    claimed = receipt.get("independent_witnesses")
    if claimed is None:
        return []
    lineages = receipt.get("evidence_lineages")
    items = lineages if isinstance(lineages, (list, tuple)) else []
    distinct = {x.strip().casefold() for x in items if _nonblank(x)}
    if not _is_int(claimed) or claimed < 0 or claimed > len(distinct):
        return ["independence.overclaimed"]
    return []


def _governance_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return governance.weakened / receipt.malformed_field for gates_weakened."""
    gates = receipt.get("gates_weakened")
    if gates is None or gates == []:
        return []
    if isinstance(gates, str):
        return ["receipt.malformed_field", "governance.weakened"] if gates.strip() else [
            "receipt.malformed_field"
        ]
    if not isinstance(gates, (list, tuple)):
        return ["receipt.malformed_field"]
    problems = ["governance.weakened"] if gates else []
    if not all(_nonblank(x) for x in gates):
        problems.insert(0, "receipt.malformed_field")
    return problems


def validate_receipt(
    receipt: Mapping[str, Any],
    *,
    mandatory_scenarios: Sequence[str] | None = None,
    complete: bool = True,
) -> list[str]:
    """Return the problem codes for one receipt; an empty list means structurally complete.

    ``complete=False`` allows a pre-freeze exploratory receipt to omit the manifest digest.
    The result is a structural judgement only; it is never a risk value or an authorization.
    The input is never mutated.
    """
    problems: list[str] = []
    scenarios = MANDATORY_SCENARIOS if mandatory_scenarios is None else mandatory_scenarios
    sid = receipt.get("scenario_id")
    if not _nonblank(sid) or sid not in scenarios:
        problems.append("scenario.unknown")
    digest = receipt.get("manifest_sha256")
    if digest is None:
        digest_bad = complete
    else:
        digest_bad = not (isinstance(digest, str) and _SHA256_RE.fullmatch(digest))
    if digest_bad:
        problems.append("manifest.digest_missing")
    if not _nonblank_list(receipt.get("interaction_ids")) and not _nonblank(
        receipt.get("trace_digest")
    ):
        problems.append("trace.missing")
    problems.extend(_denominator_problems(receipt))
    problems.extend(_count_problems(receipt))
    problems.extend(_probability_problems(receipt))
    problems.extend(_independence_problems(receipt))
    population = receipt.get("population_kind")
    if not _nonblank(population) or population not in POPULATION_KINDS:
        problems.append("receipt.malformed_field")
    elif population == "development_agents" and not _nonblank_list(
        receipt.get("correlation_groups")
    ):
        problems.append("correlation.missing")
    problems.extend(_governance_problems(receipt))
    return problems


def validate_set(
    receipts: Sequence[Mapping[str, Any]],
    *,
    mandatory_scenarios: Sequence[str],
    complete: bool = True,
) -> dict[str, list[str]]:
    """Validate every receipt, keyed by scenario id.

    Adds ``scenario.missing`` for any mandatory scenario with no receipt and
    ``scenario.duplicate`` (alongside the merged per-receipt problems) when one
    scenario id appears more than once. Structural judgement only.
    """
    report: dict[str, list[str]] = {}
    for receipt in receipts:
        sid = str(receipt.get("scenario_id"))
        found = validate_receipt(receipt, mandatory_scenarios=mandatory_scenarios, complete=complete)
        if sid in report:
            merged = [*report[sid], *(p for p in found if p not in report[sid])]
            if "scenario.duplicate" not in merged:
                merged.append("scenario.duplicate")
            report[sid] = merged
        else:
            report[sid] = found
    for scenario in mandatory_scenarios:
        if scenario not in report:
            report[scenario] = ["scenario.missing"]
    return report
