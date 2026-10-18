"""Validate the append-only generation transition receipts (G3).

Usage: check_generation_transitions.py [--root DIR]

Every pointer move, retirement or consumer-registry change is one receipt file
``requirements/generations/transitions/NNNN-<kind>-<generation>.json``. Receipts are replayed in
order: the sequence is gapless, each receipt carries the sha256 of the previous receipt's bytes,
and the replayed active generation must equal ``requirements/ACTIVE-GENERATION.json``, whose
receipt must be the last one that moved the pointer. Rules:

* ``activate`` names a reviewed, not retired generation; ``from_generation`` is the current active
  one (null for the first).
* ``rollback`` is a pointer move to a generation that was active before and is not retired. A
  rollback is a transition receipt, never a state of a generation.
* ``retire`` is refused while the generation is active or declared by any consumer, and a retired
  generation can never be activated or rolled back to again.
* ``registry`` records a reviewed change of the consumer registry for the active generation; it
  moves no pointer.

The consumer registry (``requirements/generation-consumers.json``) is a **reviewed input**: every
receipt records its sha256, the replayed value must equal the digest in the reviewed index and the
raw digest of the file, and the registry may only change through a ``registry`` receipt. So
removing, emptying or replacing the registry cannot make a retention rule vanish.

The check is offline and pure. Approval references are checked for shape only; whether a named
pull request was really approved and merged is not verifiable here and is reported as such. It
exits 0 when the history is sound, 1 on any problem, 2 on a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_generation_pointer import (  # noqa: E402  # pyright: ignore[reportMissingImports]
    CONSUMERS,
    POINTER,
    RECEIPTS,
    SHA256_PATTERN,
    Refusal,
    load_json,
    load_reviewed_index,
    registry_digest,
)

FILENAME = re.compile(
    r"^(\d{4})-(activate|rollback|retire|registry)-([a-z0-9]+(?:-[a-z0-9]+)*)\.json$"
)
RECEIPT_KEYS = {
    "schema",
    "seq",
    "kind",
    "generation",
    "from_generation",
    "previous_receipt_sha256",
    "consumers_registry_sha256",
    "recorded",
    "retroactive",
    "reason",
    "approval",
}
APPROVAL_KEYS = {"repository", "pull_request", "evidence"}
AUTHORIZATION = "structural only; approval references are not verified offline"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _shape(name: str, body: dict[str, Any]) -> None:
    """Refuse a receipt whose keys, types or filename do not match the closed shape."""
    match = FILENAME.match(name)
    if match is None:
        raise Refusal("receipt.invalid", name, "file name must be NNNN-kind-generation.json")
    approval = body.get("approval")
    previous = body.get("previous_receipt_sha256")
    registry = body.get("consumers_registry_sha256")
    valid = (
        set(body) == RECEIPT_KEYS
        and body["schema"] == 1
        and _is_int(body["seq"])
        and int(match.group(1)) == body["seq"]
        and body["kind"] == match.group(2)
        and body["generation"] == match.group(3)
        and isinstance(body["recorded"], str)
        and isinstance(body["reason"], str)
        and body["reason"].strip() != ""
        and isinstance(body["retroactive"], bool)
        and (body["from_generation"] is None or isinstance(body["from_generation"], str))
        and (previous is None or (isinstance(previous, str) and SHA256_PATTERN.match(previous)))
        and isinstance(registry, str)
        and SHA256_PATTERN.match(registry) is not None
        and isinstance(approval, dict)
        and set(approval) == APPROVAL_KEYS
        and isinstance(approval["repository"], str)
        and _is_int(approval["pull_request"])
        and approval["pull_request"] >= 1
        and isinstance(approval["evidence"], str)
        and approval["evidence"].strip() != ""
    )
    if not valid:
        raise Refusal(
            "receipt.invalid", name, "keys, types, file name or approval shape are wrong"
        )


def declared_generations(root: Path) -> set[str]:
    """Return every concrete generation id that a consumer declares (registry already bound)."""
    declarations = load_json(root, CONSUMERS, "declaration.missing")
    entries = declarations.get("consumers")
    if not isinstance(entries, list) or not entries:
        raise Refusal("declaration.invalid", str(CONSUMERS), "the registry declares no consumers")
    found: set[str] = set()
    for entry in entries:
        value = entry.get("generation") if isinstance(entry, dict) else None
        if isinstance(value, str) and value != "edge":
            found.add(value)
    return found


def replay(root: Path) -> dict[str, Any]:
    """Replay the receipts and return the state; raise ``Refusal`` for the first violation."""
    folder = root / RECEIPTS
    index = load_reviewed_index(root)
    reviewed = index["generations"]
    actual_registry = registry_digest(root)
    if actual_registry != index["consumers_registry_sha256"]:
        raise Refusal(
            "registry.mismatch",
            str(CONSUMERS),
            "the consumer registry differs from the reviewed index digest",
        )
    declared = declared_generations(root)
    names = sorted(p.name for p in folder.glob("*.json")) if folder.is_dir() else []
    if not names:
        raise Refusal("receipt.missing", str(RECEIPTS), "there are no transition receipts")
    active: str | None = None
    ever_active: set[str] = set()
    retired: set[str] = set()
    previous_bytes: bytes | None = None
    last_move = ""
    tracked: str | None = None
    for index_number, name in enumerate(names, start=1):
        path = folder / name
        if path.is_symlink():
            raise Refusal("receipt.invalid", name, "receipts must be regular files")
        data = path.read_bytes()
        body = load_json(root, RECEIPTS / name, "receipt.invalid")
        _shape(name, body)
        if body["seq"] != index_number:
            raise Refusal(
                "receipt.sequence",
                name,
                f"expected sequence {index_number}, found {body['seq']}",
            )
        wanted = hashlib.sha256(previous_bytes).hexdigest() if previous_bytes is not None else None
        if body["previous_receipt_sha256"] != wanted:
            raise Refusal("receipt.chain", name, "previous receipt digest does not match")
        generation, kind, origin = body["generation"], body["kind"], body["from_generation"]
        digest = body["consumers_registry_sha256"]
        if generation not in reviewed:
            raise Refusal(
                "transition.unreviewed", name, f"{generation} is not a reviewed generation"
            )
        if kind == "registry":
            if generation != active or origin is not None:
                raise Refusal(
                    "registry.generation", name, "a registry receipt names the active generation"
                )
            if digest == tracked:
                raise Refusal("transition.noop", name, "the registry digest did not change")
            tracked = digest
        else:
            if tracked is not None and digest != tracked:
                raise Refusal(
                    "registry.chain", name, "receipt digest differs from the reviewed registry"
                )
            tracked = digest
        if kind in ("activate", "rollback"):
            if generation in retired:
                raise Refusal("transition.retired", name, f"{generation} is retired")
            if origin != active:
                raise Refusal(
                    "transition.from", name, "from_generation is not the current active one"
                )
            if generation == active:
                raise Refusal("transition.noop", name, "the generation is already active")
            if kind == "rollback" and generation not in ever_active:
                raise Refusal("rollback.never_active", name, f"{generation} was never active")
            active = generation
            ever_active.add(generation)
            last_move = f"{RECEIPTS.as_posix()}/{name}"
        elif kind == "retire":
            if origin is not None:
                raise Refusal("transition.from", name, "a retirement carries no from_generation")
            if generation == active:
                raise Refusal("retire.active", name, f"{generation} is the active generation")
            if generation in declared:
                raise Refusal(
                    "retire.declared", name, f"{generation} is declared by a consumer"
                )
            if generation in retired:
                raise Refusal("transition.retired", name, f"{generation} is already retired")
            retired.add(generation)
        previous_bytes = data
    if tracked != actual_registry:
        raise Refusal(
            "registry.mismatch",
            str(CONSUMERS),
            "the registry digest recorded by the receipts differs from the registry file",
        )
    return {
        "active": active,
        "retired": sorted(retired),
        "last_move": last_move,
        "receipts": len(names),
        "consumers_registry_sha256": actual_registry,
        "declared_retired": sorted(declared & retired),
    }


def check_repository(root: Path) -> dict[str, Any]:
    """Return the report; ``problems`` is empty when the history and the pointer agree."""
    report: dict[str, Any] = {"authorization": AUTHORIZATION, "problems": []}
    try:
        state = replay(root)
        report.update(state)
        if state["declared_retired"]:
            raise Refusal(
                "retire.declared",
                ",".join(state["declared_retired"]),
                "a consumer declares a retired generation",
            )
        pointer = load_json(root, POINTER, "pointer.missing")
        if pointer.get("generation") != state["active"]:
            raise Refusal(
                "pointer.mismatch",
                str(POINTER),
                "pointer differs from the replayed active generation",
            )
        if pointer.get("transition_receipt") != state["last_move"]:
            raise Refusal(
                "pointer.mismatch",
                str(POINTER),
                "pointer names a receipt that is not the last move",
            )
    except Refusal as error:
        report["problems"].append(
            {"code": error.code, "subject": error.subject, "detail": error.detail}
        )
    report["ok"] = not report["problems"]
    return report


def main(argv: list[str]) -> int:
    """Run the validation and print the report."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
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
