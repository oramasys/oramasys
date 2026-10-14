"""Validate or emit the manifest-bound final producer installation plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

CONSUMER_COMMIT = "f8898b35d5249e483b2f4a68c097957e675a0ef4"
CONSUMER = {
    "repository": "oramasys/oramasys",
    "commit": CONSUMER_COMMIT,
    "distribution": "oramasys",
    "module": "orama",
    "install_mode": "built-wheel",
}
PRODUCERS = {
    "neutral-mechanics": (
        "perpetua-core",
        "perpetua_core",
        "https://github.com/oramasys/perpetua-core.git",
    ),
    "endpoint-policy": (
        "oramasys-telos",
        "telos",
        "https://github.com/oramasys/telos.git",
    ),
    "hardware-eligibility": (
        "oramasys-agate",
        "agate",
        "https://github.com/oramasys/agate.git",
    ),
    "grant-authority": (
        "oramasys-phylax",
        "phylax",
        "https://github.com/oramasys/phylax.git",
    ),
}
SHA = re.compile(r"[0-9a-f]{40}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def validate_structure(plan):
    if not isinstance(plan, dict) or set(plan) != {"schema", "consumer", "producers"}:
        raise ValueError("invalid plan fields")
    if (
        type(plan["schema"]) is not int
        or plan["schema"] != 1
        or plan["consumer"] != CONSUMER
    ):
        raise ValueError("invalid schema or consumer tuple")
    entries = plan["producers"]
    if not isinstance(entries, dict) or set(entries) != set(PRODUCERS):
        raise ValueError("invalid producer roles")
    commits = set()
    for role, (distribution, module, url) in PRODUCERS.items():
        entry = entries[role]
        if not isinstance(entry, dict) or set(entry) != {
            "distribution",
            "module",
            "url",
            "commit",
            "install_mode",
        }:
            raise ValueError("invalid producer fields")
        if (
            entry["distribution"],
            entry["module"],
            entry["url"],
            entry["install_mode"],
        ) != (distribution, module, url, "vcs"):
            raise ValueError("invalid producer identity tuple")
        commit = entry["commit"]
        if (
            not isinstance(commit, str)
            or not SHA.fullmatch(commit)
            or commit in commits
        ):
            raise ValueError("invalid or duplicate producer commit")
        commits.add(commit)
    return plan


def validate_plan(plan, manifest):
    validate_structure(plan)
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema")) is not int
        or manifest["schema"] != 3
    ):
        raise ValueError("invalid manifest schema")
    if manifest.get("consumer") != {
        "repository": CONSUMER["repository"],
        "sha": CONSUMER_COMMIT,
    }:
        raise ValueError("manifest consumer mismatch")
    producers = manifest.get("producers")
    if not isinstance(producers, dict) or set(producers) != set(PRODUCERS):
        raise ValueError("manifest producer roles mismatch")
    expected = {role: entry["commit"] for role, entry in plan["producers"].items()}
    for role, commit in expected.items():
        if (
            not isinstance(producers[role], dict)
            or producers[role].get("candidate") != commit
        ):
            raise ValueError("manifest candidate mismatch")
    cells = manifest.get("cells")
    if not isinstance(cells, list) or not all(isinstance(cell, dict) for cell in cells):
        raise ValueError("invalid manifest cells")
    final_cells = [cell for cell in cells if cell.get("profile") == "final-producers"]
    if not final_cells or any(
        cell.get("candidate_set") != expected for cell in final_cells
    ):
        raise ValueError("final-producers cell tuple mismatch")
    return plan


def emit_requirements(plan, manifest):
    validate_plan(plan, manifest)
    return [
        f"{plan['producers'][role]['distribution']} @ git+{plan['producers'][role]['url']}@{plan['producers'][role]['commit']}"
        for role in PRODUCERS
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "emit"))
    parser.add_argument("plan")
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    try:
        plan, manifest = load_json(args.plan), load_json(args.manifest)
        output = (
            emit_requirements(plan, manifest)
            if args.command == "emit"
            else {"valid": True, "schema": 1, "plan": validate_plan(plan, manifest)}
        )
    except (OSError, ValueError, TypeError):
        print(json.dumps({"valid": False, "classification": "invalid-plan"}))
        return 1
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
