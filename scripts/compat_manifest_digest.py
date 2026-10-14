"""Validate a schema-3 compatibility manifest and print its canonical sha256 digest.

Usage: compat_manifest_digest.py <manifest.json> --producer-ref SHA
           [--expected-digest HEX] [--consumer-sha SHA] [--allow-unbound]

--producer-ref is the workflow's own producer SHA; the manifest's registry ref is
compared against it, so a manifest can never vouch for its own producer.

Exit 0 and print the digest on success; exit 1 and print the stable ManifestError code
on a refusal; exit 2 on a usage or read error; exit 3 when the digest was printed but
was not compared with a frozen value (pass --allow-unbound to accept that and exit 0;
"UNBOUND: ..." is always written to stderr in that case). Duplicate JSON keys and
NaN/Infinity are refused so the digest is unambiguous. Lane files are read from the
repository's requirements directory; the registry core pins come from the manifest's
own ``registry_profiles`` (each historical cell is still checked against its lane file).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from orama.compat.manifest import (
    CODE_SCHEMA_MISMATCH,
    CODE_SCHEMA_UNKNOWN,
    SCHEMA_V3,
    SUPPORTED_SCHEMAS,
    ManifestError,
    canonical_digest,
    validate_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
LANE_FILES = {
    "production": "compatibility-core-production.txt",
    "policy-r3": "compatibility-core-policy-r3.txt",
    "core-r3": "compatibility-core-candidate.txt",
}


def lane_files() -> dict[str, dict[str, str]]:
    """Return each historical lane file's path and pinned SHA from requirements/."""
    return {
        profile: {"path": f"requirements/{name}",
                  "sha": (ROOT / "requirements" / name).read_text(encoding="utf-8").strip()}
        for profile, name in LANE_FILES.items()
    }


VALUE_OPTIONS = ("--expected-digest", "--producer-ref", "--consumer-sha")
EXIT_UNBOUND = 3


def parse_args(argv: list[str]) -> tuple[str, dict[str, str | None], bool] | None:
    """Return (path, value options, allow_unbound), or None when usage is wrong."""
    args = argv[1:]
    options: dict[str, str | None] = dict.fromkeys(VALUE_OPTIONS)
    allow_unbound = False
    positional: list[str] = []
    while args:
        item = args.pop(0)
        if item == "--allow-unbound":
            allow_unbound = True
        elif item in options:
            if not args or args[0].startswith("--"):
                return None
            options[item] = args.pop(0)
        else:
            positional.append(item)
    if len(positional) != 1:
        return None
    return positional[0], options, allow_unbound


def _reject_constant(name: str) -> None:
    """json parse_constant hook: NaN/Infinity are not valid manifest values."""
    raise ManifestError(f"non-finite number {name} is not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """json object_pairs_hook: refuse an object that repeats a key."""
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ManifestError(f"duplicate JSON keys {duplicates}")
    return dict(pairs)


def load_manifest(path: str) -> dict:
    """Read a manifest strictly: no duplicate keys, no NaN/Infinity."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text, parse_constant=_reject_constant,
                      object_pairs_hook=_no_duplicate_keys)


def main(argv: list[str]) -> int:
    """Validate the manifest and print its digest; return the process exit code."""
    parsed = parse_args(argv)
    if parsed is None:
        print(__doc__, file=sys.stderr)
        return 2
    path, options, allow_unbound = parsed
    expected = options["--expected-digest"]
    try:
        manifest = load_manifest(path)
        if not isinstance(manifest, dict):
            raise ManifestError("manifest root must be an object")
        schema = manifest.get("schema")
        if type(schema) is not int:
            raise ManifestError("manifest schema must be an integer")
        if schema not in SUPPORTED_SCHEMAS:
            raise ManifestError("unsupported manifest schema", CODE_SCHEMA_UNKNOWN)
        if schema != SCHEMA_V3:
            raise ManifestError("digest command requires schema 3", CODE_SCHEMA_MISMATCH)
        profiles = manifest.get("registry_profiles")
        registry = manifest.get("producer_registry")
        if not isinstance(profiles, dict) or not isinstance(registry, dict):
            raise ManifestError("schema-3 registry data must be objects")
        pins = dict(profiles)
        ref = options["--producer-ref"]
        if ref is None:
            raise ManifestError("--producer-ref is required to bind the registry ref")
        validate_manifest(manifest, core_pins=pins, lane_files=lane_files(),
                          producer_ref=ref, expected_digest=expected,
                          consumer_sha=options["--consumer-sha"])
        digest = canonical_digest(manifest)
    except ManifestError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"unreadable manifest: {error}", file=sys.stderr)
        return 2
    print(digest)
    if expected is None:
        print("UNBOUND: digest not compared with a frozen value", file=sys.stderr)
        return 0 if allow_unbound else EXIT_UNBOUND
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
