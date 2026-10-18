"""Check declared consumers against one immutable generation (G2, Option A: a check only).

Usage: check_generation_pointer.py [--root DIR]

Every consumer in ``requirements/generation-consumers.json`` declares a concrete generation id or
``edge``. Only ``edge`` resolves ``requirements/ACTIVE-GENERATION.json``. A missing, blank,
ambiguous or unknown declaration is refused; nothing falls back to the active pointer or to the
newest folder. Each declared consumer's own pins and identities are compared with its selected
generation. Historical and inactive generations keep their own identities and are never forced to
match the active one. Every reviewed generation is verified byte for byte on every run, and a
generation folder that is not in the reviewed index is refused (the index is never extended here).

The check is pure: it reads files and prints a JSON report. It never writes, installs, resolves
dependencies, switches an environment or changes a pointer, and it makes no claim about whether a
pointer transition was authorized (that is the separate transition validator). Exit 0 when every
check holds, 1 on any refusal, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

GENERATIONS = Path("requirements/generations")
POINTER = Path("requirements/ACTIVE-GENERATION.json")
CONSUMERS = Path("requirements/generation-consumers.json")
REVIEWED = GENERATIONS / "reviewed.json"
RECEIPTS = GENERATIONS / "transitions"
EDGE = "edge"
ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KINDS = frozenset({"package", "lane", "ci", "installer"})
CHECK_TYPES = frozenset({"regex-pin", "json-value", "file-sha256"})
POINTER_KEYS = {"schema", "generation", "record_sha256", "transition_receipt"}
CONSUMER_KEYS = {"id", "kind", "generation", "checks"}


class Refusal(Exception):
    """A typed refusal: a stable code, the subject it concerns and a short detail."""

    def __init__(self, code: str, subject: str, detail: str) -> None:
        super().__init__(f"{code}: {subject}: {detail}")
        self.code, self.subject, self.detail = code, subject, detail


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-finite constant {name}")


def load_json(root: Path, relative: Path | str, code: str = "file.unreadable") -> Any:
    """Read strict JSON under ``root``: no duplicate keys, no NaN, no symlink, object root."""
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise Refusal(code, str(relative), "missing or not a regular file")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (OSError, ValueError) as error:
        raise Refusal("json.invalid", str(relative), str(error)) from error
    if not isinstance(value, dict):
        raise Refusal("json.invalid", str(relative), "root must be an object")
    return value


def canonical_digest(value: Any) -> str:
    """Digest under the manifest encoding rules (sorted keys, no spaces, no non-finite numbers)."""
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(text.encode()).hexdigest()


def safe_relative(value: object, subject: str) -> Path:
    """Require a normal relative path with no traversal."""
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
    ):
        raise Refusal("path.unsafe", subject, "must be a relative path")
    path = Path(value)
    if ".." in path.parts or path.is_absolute():
        raise Refusal("path.unsafe", subject, "must not traverse")
    return path


def dotted(value: dict[str, Any], path: str, subject: str) -> Any:
    """Follow a dotted key path through nested objects."""
    node: Any = value
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise Refusal("declaration.invalid", subject, f"no value at {path}")
        node = node[part]
    return node


def verify_generation(root: Path, generation: str, reviewed_sha: str) -> dict[str, Any]:
    """Verify one reviewed generation folder against its reviewed record digest."""
    folder = root / GENERATIONS / generation
    if folder.is_symlink() or not folder.is_dir():
        raise Refusal(
            "generation.unknown", generation, "reviewed generation folder is missing"
        )
    record_path = folder / "generation.json"
    if record_path.is_symlink() or not record_path.is_file():
        raise Refusal("generation.integrity", generation, "generation.json is missing")
    if hashlib.sha256(record_path.read_bytes()).hexdigest() != reviewed_sha:
        raise Refusal(
            "generation.integrity", generation, "generation.json differs from review"
        )
    record = load_json(root, GENERATIONS / generation / "generation.json")
    inventory = record.get("inventory")
    if (
        record.get("id") != generation
        or not isinstance(inventory, list)
        or not inventory
    ):
        raise Refusal(
            "generation.integrity", generation, "record id or inventory is wrong"
        )
    paths = [str(entry.get("path")) for entry in inventory if isinstance(entry, dict)]
    if (
        len(paths) != len(inventory)
        or paths != sorted(paths)
        or len(set(paths)) != len(paths)
    ):
        raise Refusal(
            "generation.integrity", generation, "inventory is unsorted or duplicated"
        )
    if record.get("inventory_digest") != canonical_digest(inventory):
        raise Refusal("generation.integrity", generation, "inventory digest differs")
    for entry in inventory:
        relative = safe_relative(entry.get("path"), generation)
        target = folder / relative
        if target.is_symlink() or not target.is_file():
            raise Refusal("generation.integrity", generation, f"{relative} is missing")
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.get("sha256") or len(
            data
        ) != entry.get("bytes"):
            raise Refusal("generation.integrity", generation, f"{relative} differs")
    present = {
        p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()
    }
    if present - set(paths) - {"generation.json"}:
        raise Refusal(
            "generation.integrity", generation, "a file is not in the inventory"
        )
    return record


def load_reviewed_index(root: Path) -> dict[str, Any]:
    """Read the reviewed index: reviewed record digests plus the reviewed consumer-registry digest."""
    index = load_json(root, REVIEWED, "generation.index_missing")
    entries = index.get("generations")
    registry = index.get("consumers_registry_sha256")
    if (
        index.get("schema") != 1
        or set(index) != {"schema", "generations", "consumers_registry_sha256"}
        or not isinstance(entries, dict)
        or not isinstance(registry, str)
        or not SHA256_PATTERN.match(registry)
    ):
        raise Refusal("generation.index_invalid", str(REVIEWED), "wrong shape")
    for key, digest in entries.items():
        if (
            not ID_PATTERN.match(key)
            or not isinstance(digest, str)
            or not SHA256_PATTERN.match(digest)
        ):
            raise Refusal(
                "generation.index_invalid", str(REVIEWED), f"bad entry {key!r}"
            )
    return {"generations": dict(entries), "consumers_registry_sha256": registry}


def load_reviewed(root: Path) -> dict[str, str]:
    """Read the reviewed index: generation id to the reviewed record sha256."""
    return load_reviewed_index(root)["generations"]


def registry_digest(root: Path) -> str:
    """Raw sha256 of the consumer registry file; the registry is a reviewed input, not just data."""
    path = root / CONSUMERS
    if path.is_symlink() or not path.is_file():
        raise Refusal("declaration.missing", str(CONSUMERS), "missing or not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_pointer(root: Path, reviewed: dict[str, str]) -> dict[str, Any]:
    """Validate the active pointer structurally. Authorization is not judged here."""
    try:
        pointer = load_json(root, POINTER, "pointer.missing")
    except Refusal as error:
        raise Refusal(
            "pointer.invalid" if error.code == "json.invalid" else error.code,
            str(POINTER),
            error.detail,
        ) from error
    if set(pointer) != POINTER_KEYS or pointer["schema"] != 1:
        raise Refusal("pointer.invalid", str(POINTER), "wrong shape or schema")
    generation = pointer["generation"]
    if not isinstance(generation, str) or not ID_PATTERN.match(generation):
        raise Refusal("pointer.invalid", str(POINTER), "generation id is invalid")
    if generation not in reviewed:
        raise Refusal(
            "generation.unknown", generation, "pointer names an unreviewed generation"
        )
    if pointer["record_sha256"] != reviewed[generation]:
        raise Refusal(
            "pointer.invalid", str(POINTER), "record digest differs from the review"
        )
    receipt = safe_relative(pointer["transition_receipt"], "transition_receipt")
    if receipt.parent != RECEIPTS or receipt.suffix != ".json":
        raise Refusal(
            "pointer.invalid",
            str(POINTER),
            "receipt must sit in the transitions folder",
        )
    try:
        body = load_json(root, receipt, "pointer.receipt_missing")
    except Refusal as error:
        raise Refusal(
            "pointer.receipt_missing"
            if error.code == "pointer.receipt_missing"
            else "pointer.invalid",
            str(receipt),
            error.detail,
        ) from error
    if body.get("generation") != generation:
        raise Refusal(
            "pointer.invalid", str(receipt), "receipt names another generation"
        )
    return pointer


def select(declared: object, subject: str) -> str:
    """Validate a selector before any generation file is touched."""
    if not isinstance(declared, str) or not declared:
        raise Refusal(
            "declaration.invalid", subject, "selector must be a non-empty string"
        )
    if declared != EDGE and not ID_PATTERN.match(declared):
        raise Refusal(
            "declaration.invalid", subject, "selector is not a generation id or edge"
        )
    if len(declared) > 64:
        raise Refusal("declaration.invalid", subject, "selector is too long")
    return declared


def run_check(
    root: Path, check: dict[str, Any], record: dict[str, Any], subject: str
) -> None:
    """Run one declared check of a consumer against its resolved generation record."""
    kind = check.get("type")
    if kind not in CHECK_TYPES:
        raise Refusal("declaration.invalid", subject, f"unknown check type {kind!r}")
    file = safe_relative(check.get("file"), subject)
    if kind == "file-sha256":
        target = root / file
        if target.is_symlink() or not target.is_file():
            raise Refusal("file.unreadable", f"{subject}:{file}", "missing")
        want = dotted(record, str(check.get("expect")), subject)
        if hashlib.sha256(target.read_bytes()).hexdigest() != want:
            raise Refusal(
                "identity.mismatch",
                f"{subject}:{file}",
                "file digest differs from the generation",
            )
        return
    if kind == "json-value":
        value = dotted(load_json(root, file), str(check.get("path")), subject)
        if value != dotted(record, str(check.get("expect")), subject):
            raise Refusal(
                "identity.mismatch", f"{subject}:{file}", f"{check['path']} differs"
            )
        return
    target = root / file
    if target.is_symlink() or not target.is_file():
        raise Refusal("file.unreadable", f"{subject}:{file}", "missing")
    try:
        pattern = re.compile(str(check.get("pattern")), re.MULTILINE)
    except re.error as error:
        raise Refusal(
            "declaration.invalid", subject, "pattern does not compile"
        ) from error
    role, field, count = check.get("role"), check.get("field"), check.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise Refusal(
            "declaration.invalid", subject, "count must be a positive integer"
        )
    if "expect" in check:
        expected = dotted(record, str(check["expect"]), subject)
    else:
        pins = record.get("pins", {}).get(role) if isinstance(role, str) else None
        expected = (
            pins.get(field)
            if isinstance(pins, dict) and isinstance(field, str)
            else None
        )
    if not isinstance(expected, str):
        raise Refusal(
            "declaration.invalid", subject, "the generation has no such pin or value"
        )
    found = [
        match.group(1) for match in pattern.finditer(target.read_text(encoding="utf-8"))
    ]
    if len(found) != count:
        raise Refusal(
            "pin.count", f"{subject}:{file}", f"{len(found)} matches, expected {count}"
        )
    drifted = sorted({sha for sha in found if sha != expected})
    if drifted:
        raise Refusal(
            "pin.drift",
            f"{subject}:{file}",
            "a pinned value differs from the generation",
        )


def check_repository(root: Path) -> dict[str, Any]:
    """Run every check and return the report; ``problems`` is empty when all hold."""
    problems: list[dict[str, str]] = []

    def note(error: Refusal) -> None:
        problems.append(
            {"code": error.code, "subject": error.subject, "detail": error.detail}
        )

    report: dict[str, Any] = {"generations": {}, "consumers": [], "pointer": None}
    reviewed: dict[str, str] = {}
    reviewed_registry = ""
    try:
        index = load_reviewed_index(root)
        reviewed, reviewed_registry = index["generations"], index["consumers_registry_sha256"]
    except Refusal as error:
        note(error)
    records: dict[str, dict[str, Any]] = {}
    for generation, digest in sorted(reviewed.items()):
        try:
            records[generation] = verify_generation(root, generation, digest)
            report["generations"][generation] = "intact"
        except Refusal as error:
            note(error)
            report["generations"][generation] = "refused"
    folder = root / GENERATIONS
    if folder.is_dir() and reviewed:
        for child in sorted(
            p for p in folder.iterdir() if p.is_dir() and p.name != RECEIPTS.name
        ):
            if child.name not in reviewed:
                note(
                    Refusal(
                        "generation.unreviewed",
                        child.name,
                        "folder is not in the reviewed index",
                    )
                )
    try:
        actual_registry = registry_digest(root)
    except Refusal as error:
        note(error)
        return _finish(report, problems)
    if not reviewed_registry:
        note(Refusal("declaration.digest_mismatch", str(CONSUMERS), "no reviewed registry digest"))
        return _finish(report, problems)
    if actual_registry != reviewed_registry:
        note(
            Refusal(
                "declaration.digest_mismatch",
                str(CONSUMERS),
                "the consumer registry differs from its reviewed digest",
            )
        )
        return _finish(report, problems)
    report["consumers_registry_sha256"] = actual_registry
    try:
        declarations = load_json(root, CONSUMERS, "declaration.missing")
    except Refusal as error:
        duplicate = error.code == "json.invalid" and "duplicate" in error.detail
        note(
            Refusal(
                "declaration.ambiguous" if duplicate else error.code,
                error.subject,
                error.detail,
            )
        )
        return _finish(report, problems)
    entries = declarations.get("consumers")
    if (
        declarations.get("schema") != 1
        or set(declarations) != {"schema", "consumers"}
        or not isinstance(entries, list)
    ):
        note(Refusal("declaration.invalid", str(CONSUMERS), "wrong shape or schema"))
        return _finish(report, problems)
    if not entries:
        note(Refusal("declaration.invalid", str(CONSUMERS), "the registry declares no consumers"))
        return _finish(report, problems)
    seen: set[str] = set()
    pointer_cache: list[dict[str, Any] | Refusal] = []
    for entry in entries:
        subject = str(entry.get("id")) if isinstance(entry, dict) else "?"
        row = {"id": subject, "declared": None, "resolved": None, "ok": False}
        report["consumers"].append(row)
        try:
            if not isinstance(entry, dict):
                raise Refusal(
                    "declaration.invalid", subject, "consumer must be an object"
                )
            if "generation" in entry and "edge" in entry:
                raise Refusal(
                    "declaration.ambiguous",
                    subject,
                    "both generation and edge are present",
                )
            if "generation" not in entry:
                raise Refusal(
                    "declaration.missing", subject, "no generation declaration"
                )
            if (
                set(entry) != CONSUMER_KEYS
                or entry["kind"] not in KINDS
                or subject in seen
            ):
                raise Refusal(
                    "declaration.invalid", subject, "wrong shape, kind or duplicate id"
                )
            seen.add(subject)
            row["declared"] = select(entry["generation"], subject)
            if row["declared"] == EDGE:
                if not pointer_cache:
                    try:
                        pointer_cache.append(resolve_pointer(root, reviewed))
                    except Refusal as error:
                        pointer_cache.append(error)
                if isinstance(pointer_cache[0], Refusal):
                    raise pointer_cache[0]
                row["resolved"] = pointer_cache[0]["generation"]
                report["pointer"] = {
                    "generation": row["resolved"],
                    "transition_receipt": pointer_cache[0]["transition_receipt"],
                    "authorization": "not judged here",
                }
            else:
                row["resolved"] = row["declared"]
            if row["resolved"] not in reviewed:
                raise Refusal(
                    "generation.unknown", subject, f"{row['resolved']} is not reviewed"
                )
            record = records.get(row["resolved"])
            if record is None:
                raise Refusal(
                    "generation.integrity", subject, f"{row['resolved']} did not verify"
                )
            if not isinstance(entry["checks"], list) or not entry["checks"]:
                raise Refusal(
                    "declaration.invalid",
                    subject,
                    "a consumer needs at least one check",
                )
            for check in entry["checks"]:
                if not isinstance(check, dict):
                    raise Refusal(
                        "declaration.invalid", subject, "check must be an object"
                    )
                run_check(root, check, record, subject)
            row["ok"] = True
        except Refusal as error:
            note(error)
    return _finish(report, problems)


def _finish(report: dict[str, Any], problems: list[dict[str, str]]) -> dict[str, Any]:
    report["problems"] = problems
    report["ok"] = not problems
    return report


def main(argv: list[str]) -> int:
    """Run the check and print the report."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        return 2
    if not args.root.is_dir():
        print(f"error: {args.root} is not a directory", file=sys.stderr)
        return 2
    report = check_repository(args.root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
