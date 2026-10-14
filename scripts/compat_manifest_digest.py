"""Validate a schema-3 compatibility manifest and print its canonical sha256 digest.

Usage: compat_manifest_digest.py <manifest.json> [--expected-digest HEX] [--producer-ref SHA]

Exit 0 and print the digest on success; exit 1 and print the stable ManifestError code
on a refusal; exit 2 on a usage or read error. Lane files are read from the repository's
requirements directory; the registry core pins come from the manifest's own
``registry_profiles`` (each historical cell is still checked against its lane file).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from orama.compat.manifest import ManifestError, canonical_digest, validate_manifest

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


def parse_args(argv: list[str]) -> tuple[str, str | None, str | None] | None:
    """Return (path, expected_digest, producer_ref), or None when usage is wrong."""
    args = argv[1:]
    options = {"--expected-digest": None, "--producer-ref": None}
    positional: list[str] = []
    while args:
        item = args.pop(0)
        if item in options:
            if not args:
                return None
            options[item] = args.pop(0)
            continue
        positional.append(item)
    if len(positional) != 1:
        return None
    return positional[0], options["--expected-digest"], options["--producer-ref"]


def main(argv: list[str]) -> int:
    """Validate the manifest and print its digest; return the process exit code."""
    parsed = parse_args(argv)
    if parsed is None:
        print(__doc__, file=sys.stderr)
        return 2
    path, expected, producer_ref = parsed
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        pins = dict(manifest.get("registry_profiles", {}))
        ref = producer_ref or manifest["producer_registry"]["ref"]
        validate_manifest(manifest, core_pins=pins, lane_files=lane_files(),
                          producer_ref=ref, expected_digest=expected)
    except ManifestError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"unreadable manifest: {error}", file=sys.stderr)
        return 2
    print(canonical_digest(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
