"""Compare the manifest's registry_profiles with the Core pins the reviewed registries declare.

Usage: compare_registry_pins.py <manifest.json> [--fixtures-dir DIR] [--production-registry FILE]

Each profile's pin is read from a registry snapshot's ``qualification_profile.core_pin``. The
production pin is **externally anchored** only when ``--production-registry`` names a file read from
the pinned producer-registry checkout; otherwise it, like the two candidate profiles, is anchored by
the digest-pinned fixture snapshot in this repository. The output states which anchor each
comparison used, so a fixture comparison is never presented as an external one.
Exit 0 on agreement, 1 on a mismatch or a missing pin, 2 on a usage or read error.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

PROFILE_FIXTURES = {
    "production": "graph-ownership-registry.json",
    "policy-r3": "graph-ownership-registry-policy-r3.json",
    "core-r3": "graph-ownership-registry-core-r3.json",
}
DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "src" / "tests" / "fixtures"


def registry_core_pin(registry: object) -> str | None:
    """Return qualification_profile.core_pin, or None when it is absent or not a string."""
    if not isinstance(registry, Mapping):
        return None
    profile = registry.get("qualification_profile")
    pin = profile.get("core_pin") if isinstance(profile, Mapping) else None
    return pin if isinstance(pin, str) else None


def compare(
    declared: Mapping[str, str], registries: Mapping[str, object], external: frozenset[str]
) -> dict[str, object]:
    """Return per-profile results and the problem list for the declared pins."""
    results: dict[str, dict[str, str]] = {}
    problems: list[str] = []
    for profile in PROFILE_FIXTURES:
        pin = registry_core_pin(registries.get(profile))
        anchor = "external-registry" if profile in external else "fixture-snapshot"
        want = declared.get(profile)
        results[profile] = {"declared": str(want), "registry": str(pin), "anchor": anchor}
        if pin is None:
            problems.append(f"{profile}: registry pin missing")
        elif pin != want:
            problems.append(f"{profile}: declared pin differs from the registry pin")
    return {"results": results, "problems": problems}


def main(argv: Sequence[str]) -> int:
    """Read the manifest and registries, compare, and print the verdict."""
    args = list(argv[1:])

    def take(flag: str) -> str | None:
        if flag in args:
            index = args.index(flag)
            value = args[index + 1] if index + 1 < len(args) else None
            del args[index:index + 2]
            return value
        return None

    fixtures = Path(take("--fixtures-dir") or DEFAULT_FIXTURES)
    production = take("--production-registry")
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        manifest = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        declared = manifest["registry_profiles"]
        registries = {name: json.loads((fixtures / file).read_text(encoding="utf-8"))
                      for name, file in PROFILE_FIXTURES.items()}
        external: frozenset[str] = frozenset()
        if production:
            registries["production"] = json.loads(Path(production).read_text(encoding="utf-8"))
            external = frozenset({"production"})
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"unreadable: {type(error).__name__}", file=sys.stderr)
        return 2
    verdict = compare(declared, registries, external)
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if not verdict["problems"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
