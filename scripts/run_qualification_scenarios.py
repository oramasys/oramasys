"""Emit deterministic synthetic interaction-risk receipts for the six frozen scenarios.

This command produces machine-checkable fixture evidence only.  It never measures a
live population, calculates a probability, approves a gate, or qualifies M1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

from orama.compat.interaction_risk_receipt import MANDATORY_SCENARIOS, validate_set

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_LIMITATION = (
    "Deterministic synthetic fixture only; no live population, calibrated risk, "
    "dispatch authority, or M1 qualification is asserted."
)


def _canonical_digest(value: str, label: str) -> str:
    """Accept only a lower-case full SHA-256 supplied by a prior gate."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"invalid {label} digest")
    return value


def _write_trace(destination: Path, payload: dict[str, Any]) -> str:
    """Create one immutable trace file and return its content digest."""
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("trace destination already exists")
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    with destination.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
    return hashlib.sha256(encoded).hexdigest()


def run(manifest_digest: str, coverage_digest: str, trace_dir: Path) -> dict[str, Any]:
    """Run each fixed scenario once and return unapproved bounded evidence."""
    manifest_digest = _canonical_digest(manifest_digest, "manifest")
    coverage_digest = _canonical_digest(coverage_digest, "coverage")
    trace_dir = Path(trace_dir)
    if trace_dir.exists() and not trace_dir.is_dir():
        raise ValueError("trace destination is not a directory")
    trace_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    scenarios: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    for scenario_id in MANDATORY_SCENARIOS:
        trace_payload = {
            "schema": 1,
            "scenario_id": scenario_id,
            "fixture_outcome": "refused",
            "scope": "deterministic-synthetic",
        }
        trace_digest = _write_trace(trace_dir / f"{scenario_id}.json", trace_payload)
        receipt = {
            "scenario_id": scenario_id,
            "population_kind": "runtime_workers",
            "manifest_sha256": manifest_digest,
            "trace_digest": trace_digest,
            "exposed_count": 1,
            "counts": {"accepted": 0, "rejected": 1, "pending": 0, "unknown": 0},
            "interaction_total": 1,
        }
        receipts.append(receipt)
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "passed": True,
                "denominator": 1,
                "blocked": 1,
                "unknowns": 0,
                "trace_digest": trace_digest,
                "limitations": [_LIMITATION],
            }
        )
    report = validate_set(
        receipts, mandatory_scenarios=MANDATORY_SCENARIOS, complete=True
    )
    if any(report.values()):
        raise ValueError("synthetic receipt validation failed")
    return {
        "schema": 1,
        "qualification_status": "unapproved",
        "scope": "deterministic-synthetic",
        "manifest_digest": manifest_digest,
        "coverage_digest": coverage_digest,
        "complete": True,
        "scenarios": scenarios,
        "limitations": [_LIMITATION],
    }


def main(argv: list[str] | None = None) -> int:
    """Write one sanitized evidence document, or refuse malformed inputs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--coverage-digest", required=True)
    parser.add_argument("--trace-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        output = Path(args.output)
        if output.exists() or output.is_symlink():
            raise FileExistsError("output already exists")
        result = run(args.manifest_digest, args.coverage_digest, Path(args.trace_dir))
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0
    except (OSError, ValueError, TypeError):
        print("scenario-evidence-refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
