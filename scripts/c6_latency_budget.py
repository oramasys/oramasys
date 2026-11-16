"""Check a C6 availability-harness result against the platform-keyed latency budget.

Source of the budgets: docs/revocation-availability-budget-proposal-2026-11-06.md, the
2026-11-07 operator amendment (scheduled and successful-call send p95 <= 60 ms, scheduled
p99 <= 250 ms) and the 2026-11-16 operator amendment (native Windows scheduled p95 <= 150 ms,
provisional until re-measured in the service-account context).

A budget check is evidence for one run. It qualifies nothing: the operator-run passes,
native Windows qualification and the separate release gates still apply.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Mapping

BUDGETS: dict[str, dict[str, Any]] = {
    "posix": {
        "scheduled_p95_ms": 60,
        "send_p95_ms": 60,
        "scheduled_p99_ms": 250,
        "status": "ratified",
        "source": "operator amendment 2026-11-07",
        "pending": "",
    },
    "windows-native": {
        "scheduled_p95_ms": 150,
        "send_p95_ms": 60,
        "scheduled_p99_ms": 250,
        "status": "provisional",
        "source": "operator decision 2026-11-16; evidence oramasys PR 100 (four runs, "
                  "scheduled p95 136.3-139.2 ms, p99 162.8-168.5 ms)",
        "pending": "re-measure in the service-account context before treating as final",
    },
}

_MEASURES = (
    ("scheduled_p95_ms", "scheduled_latency", "p95_ms"),
    ("send_p95_ms", "send_latency", "p95_ms"),
    ("scheduled_p99_ms", "scheduled_latency", "p99_ms"),
)


def platform_key(os_name: str = os.name) -> str:
    """Map a Python ``os.name`` to its budget key; only native Windows differs."""
    return "windows-native" if os_name == "nt" else "posix"


def violations(result: Mapping[str, Any], key: str) -> list[str]:
    """Return every budget breach; a missing measurement is a breach (fail closed)."""
    if key not in BUDGETS:
        raise ValueError(f"unknown budget key {key!r}; expected one of {sorted(BUDGETS)}")
    budget = BUDGETS[key]
    found: list[str] = []
    for name, section, field in _MEASURES:
        value = (result.get(section) or {}).get(field)
        if value is None:
            found.append(f"{name} missing")
        elif float(value) > budget[name]:
            found.append(f"{name} {float(value)} > {budget[name]}")
    return found


def main(argv: list[str] | None = None) -> int:
    """Print a JSON verdict for one harness result; exit 1 when out of budget."""
    parser = argparse.ArgumentParser(description="Check a C6 harness result against the platform-keyed latency budget.")
    parser.add_argument("result", type=Path, help="benchmark_revocation_availability JSON")
    parser.add_argument("--platform", choices=sorted(BUDGETS), default=platform_key())
    args = parser.parse_args(argv)
    found = violations(json.loads(args.result.read_text(encoding="utf-8")), args.platform)
    print(json.dumps({
        "platform": args.platform,
        "budget": BUDGETS[args.platform],
        "violations": found,
        "within_budget": not found,
        "qualifies_run": False,
    }, indent=2))
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
