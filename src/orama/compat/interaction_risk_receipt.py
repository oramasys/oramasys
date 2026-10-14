"""Interaction-risk assessment receipt validator (stdlib only, not wired anywhere).

Encodes the measurement rules of the assessment contract (S-A1 section 18.3/18.4) as pure functions so a
receipt can be judged structurally complete or incomplete mechanically. The assessment frame is layered
threat coverage; impact-ranked attack paths; interaction-risk assessment (six modes + governance latency).

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
  probability.uncalibrated  a probability needs estimator version, calibration method, sample count, uncertainty
  probability.authorizes    a probability (or any soft risk value) claims authority over a gate
  independence.overclaimed  independent witnesses claimed exceed distinct evidence lineages
  correlation.missing       development-agent receipts must name their correlation groups
  governance.weakened       a governance variant relaxed a mandatory gate
"""

from __future__ import annotations

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
COUNT_KEYS = ("accepted", "rejected", "pending", "unknown")
PROB_REQUIRED = ("estimator_version", "calibration_method", "sample_count", "uncertainty")


def _is_int(value: Any) -> bool:
    """Return True for a real integer; booleans are not counts."""
    return isinstance(value, int) and not isinstance(value, bool)


def _denominator_problem(receipt: Mapping[str, Any]) -> bool:
    """Return True when the exposed count is absent, invalid, or zero without a reason."""
    exposed = receipt.get("exposed_count")
    if not isinstance(exposed, int) or isinstance(exposed, bool) or exposed < 0:
        return True
    return exposed == 0 and not receipt.get("zero_exposure_reason")


def _count_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return counts.* problem codes for the outcome counts and interaction total."""
    counts = receipt.get("counts")
    total = receipt.get("interaction_total")
    if not isinstance(counts, Mapping) or any(
        not _is_int(counts.get(k)) or counts[k] < 0 for k in COUNT_KEYS
    ):
        return ["counts.missing"]
    if not isinstance(total, int) or isinstance(total, bool):
        return ["counts.missing"]
    if sum(counts[k] for k in COUNT_KEYS) != total:
        return ["counts.inconsistent"]
    return []


def _probability_problems(receipt: Mapping[str, Any]) -> list[str]:
    """Return probability.* problem codes; an absent probability is fine (unknown)."""
    problems: list[str] = []
    probability = receipt.get("probability")
    if probability is not None:
        if not isinstance(probability, Mapping) or any(
            probability.get(k) in (None, "") for k in PROB_REQUIRED
        ):
            problems.append("probability.uncalibrated")
        if isinstance(probability, Mapping) and probability.get("authorizes_dispatch"):
            problems.append("probability.authorizes")
    if receipt.get("risk_authorizes_dispatch"):
        problems.append("probability.authorizes")
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
    """
    problems: list[str] = []
    if mandatory_scenarios is not None and receipt.get("scenario_id") not in mandatory_scenarios:
        problems.append("scenario.unknown")
    if complete and not receipt.get("manifest_sha256"):
        problems.append("manifest.digest_missing")
    if not receipt.get("interaction_ids") and not receipt.get("trace_digest"):
        problems.append("trace.missing")
    if _denominator_problem(receipt):
        problems.append("denominator.missing")
    problems.extend(_count_problems(receipt))
    problems.extend(_probability_problems(receipt))

    lineages = receipt.get("evidence_lineages")
    claimed = receipt.get("independent_witnesses")
    if claimed is not None:
        distinct = len({str(x) for x in lineages}) if isinstance(lineages, (list, tuple)) else 0
        if not _is_int(claimed) or claimed > distinct:
            problems.append("independence.overclaimed")

    if receipt.get("population_kind") == "development_agents" and not receipt.get("correlation_groups"):
        problems.append("correlation.missing")
    if receipt.get("gates_weakened"):
        problems.append("governance.weakened")
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
