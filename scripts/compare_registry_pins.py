"""Compare the manifest's registry_profiles with the Core pins the reviewed registries declare.

Usage: compare_registry_pins.py <manifest.json> [--fixtures-dir DIR] [--production-registry FILE]

Each profile's pin is read from a registry snapshot's ``qualification_profile.core_pin``. A supplied
``--production-registry`` is accepted as an **external anchor** only when its exact bytes hash to
``PINNED_PRODUCTION_REGISTRY_SHA256``, the digest of the reviewed registry at the manifest's pinned
producer ref (the digest is a constant of this tool, never taken from the input). Matching a pin is
not enough: changed bytes that repeat the same ``core_pin`` are refused. Without the flag, and for
the two candidate profiles, the anchor is the digest-pinned fixture snapshot in this repository and
is labelled as such. This is pin equality over reviewed bytes; it is not a structural audit of the
registry. Every JSON input is parsed strictly (duplicate keys and NaN/Infinity are refused).
Exit 0 on agreement, 1 on a mismatch, a missing pin or refused bytes, 2 on a usage or read error
(including a flag with no value, or a repeated flag).
"""
from __future__ import annotations

import hashlib
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
# sha256 of docs/v2/references/loop-graph-compatibility-2026-10-09/ownership-registry.json at
# diazMelgarejo/orama-system 65ec365293c6a892cd4f978e656cfb61c0d04b9a (the manifest's producer
# registry ref). A test asserts it equals the digest of the production fixture snapshot.
PINNED_PRODUCTION_REGISTRY_SHA256 = (
    "91d3c74b5cd9aea1d176dd87115f09151fc1e3a6155292aa58a32d8f7bb40787"
)
PINNED_PRODUCTION_REGISTRY_PATH = (
    "docs/v2/references/loop-graph-compatibility-2026-10-09/ownership-registry.json"
)


class InputError(ValueError):
    """An input could not be read or parsed strictly."""


def _reject_constant(name: str) -> None:
    raise InputError(f"non-finite number {name} is not allowed")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    duplicated = sorted({key for key in keys if keys.count(key) > 1})
    if duplicated:
        raise InputError(f"duplicate JSON keys {duplicated}")
    return dict(pairs)


def strict_loads(text: str) -> object:
    """Parse JSON refusing duplicate object keys and non-finite numbers."""
    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)


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


def _take(args: list[str], flag: str) -> str | None:
    """Pop ``flag VALUE`` from args; a repeated flag or a missing value is a usage error."""
    count = args.count(flag)
    if count == 0:
        return None
    if count > 1:
        raise InputError(f"{flag} given more than once")
    index = args.index(flag)
    if index + 1 >= len(args) or args[index + 1].startswith("--"):
        raise InputError(f"{flag} requires a value")
    value = args[index + 1]
    del args[index:index + 2]
    return value


def main(argv: Sequence[str]) -> int:
    """Read the manifest and registries, compare, and print the verdict."""
    args = list(argv[1:])
    try:
        fixtures = Path(_take(args, "--fixtures-dir") or DEFAULT_FIXTURES)
        production = _take(args, "--production-registry")
        if len(args) != 1:
            raise InputError("expected exactly one manifest path")
        manifest = strict_loads(Path(args[0]).read_text(encoding="utf-8"))
        if not isinstance(manifest, Mapping):
            raise InputError("manifest must be an object")
        declared = manifest["registry_profiles"]
        producer = manifest.get("producer_registry", {})
        registries = {name: strict_loads((fixtures / file).read_text(encoding="utf-8"))
                      for name, file in PROFILE_FIXTURES.items()}
        external: frozenset[str] = frozenset()
        anchor: dict[str, str] | None = None
        if production is not None:
            raw = Path(production).read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != PINNED_PRODUCTION_REGISTRY_SHA256:
                print(json.dumps({"results": {}, "problems": [
                    "production registry bytes differ from the pinned reviewed bytes "
                    f"(sha256 {digest})"]}, indent=2, sort_keys=True))
                return 1
            registries["production"] = strict_loads(raw.decode("utf-8"))
            external = frozenset({"production"})
            anchor = {
                "repository": str(producer.get("repository")), "ref": str(producer.get("ref")),
                "path": PINNED_PRODUCTION_REGISTRY_PATH, "sha256": digest,
            }
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError) as error:
        print(f"unreadable: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    verdict = compare(declared, registries, external)
    if anchor is not None:
        verdict["external_anchor"] = anchor
    verdict["scope"] = "pin equality over reviewed bytes; not a structural registry audit"
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if not verdict["problems"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
