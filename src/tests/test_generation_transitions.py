"""G3: the append-only transition receipts and their validator.

Every case builds a throwaway copy of the repository's ``requirements`` tree, damages or extends
it, and runs the real command. Each test asserts the specific refusal code, never only a nonzero
exit, so the individual rules can fail independently. The real receipts are pinned by sha256
literals, which makes rewriting history a visible change.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_generation_transitions.py"
RECEIPTS = Path("requirements/generations/transitions")
POINTER = Path("requirements/ACTIVE-GENERATION.json")
REVIEWED = Path("requirements/generations/reviewed.json")
CONSUMERS = Path("requirements/generation-consumers.json")
APPROVAL = {
    "repository": "oramasys/oramasys",
    "pull_request": 99,
    "evidence": "test evidence",
}
PINNED_RECEIPTS = {
    "0001-activate-m1-gen1.json": "1f79f2208b976c521eceafe0cf07bdc70e29093d6c69e9e1f6335f3838de3758",
    "0002-activate-m1-gen2.json": "4b08172675503caa581b761357301d08ee544e82f7fc7c1768cb4e9d5b2b85ac",
}


def make_root(tmp_path: Path) -> Path:
    """Copy the requirements tree into a throwaway root."""
    root = tmp_path / "root"
    shutil.copytree(ROOT / "requirements", root / "requirements")
    return root


def run(root: Path) -> tuple[int, dict]:
    """Run the validator on ``root`` and return its exit code and parsed report."""
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, json.loads(done.stdout)


def codes(report: dict) -> list[str]:
    """Extract ordered stable refusal codes from a validator report."""
    return [problem["code"] for problem in report["problems"]]


def snapshot(root: Path) -> dict[str, str]:
    """Digest every file under ``root`` to prove the validator wrote nothing."""
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def receipts(root: Path) -> list[Path]:
    """Return receipt files in their lexical sequence order."""
    return sorted((root / RECEIPTS).glob("*.json"))


def registry_sha(root: Path) -> str:
    """Raw sha256 of the consumer registry file in ``root``."""
    return hashlib.sha256((root / CONSUMERS).read_bytes()).hexdigest()


def rebind(root: Path, *, receipt: bool = True, index: bool = True) -> None:
    """Record a *reviewed* registry change: new digest in the index and a registry receipt."""
    if index:
        data = json.loads((root / REVIEWED).read_text())
        data["consumers_registry_sha256"] = registry_sha(root)
        (root / REVIEWED).write_text(json.dumps(data, indent=2) + "\n")
    if receipt:
        active = json.loads((root / POINTER).read_text())["generation"]
        append(root, "registry", active, None)


def append(
    root: Path,
    kind: str,
    generation: str,
    origin: str | None,
    *,
    move: bool = True,
    **overrides: object,
) -> Path:
    """Append a correctly chained receipt; optionally move the pointer to it."""
    last = receipts(root)[-1]
    seq = len(receipts(root)) + 1
    body = {
        "schema": 1,
        "seq": seq,
        "kind": kind,
        "generation": generation,
        "from_generation": origin,
        "previous_receipt_sha256": hashlib.sha256(last.read_bytes()).hexdigest(),
        "consumers_registry_sha256": overrides.pop("consumers_registry_sha256", None)
        or registry_sha(root),
        "recorded": "2026-10-18",
        "retroactive": False,
        "reason": "test",
        "approval": APPROVAL,
    }
    body.update(overrides)
    path = root / RECEIPTS / f"{seq:04d}-{kind}-{generation}.json"
    path.write_text(json.dumps(body, indent=2) + "\n")
    if move and kind in ("activate", "rollback"):
        pointer = json.loads((root / POINTER).read_text())
        pointer["generation"] = generation
        pointer["transition_receipt"] = path.relative_to(root).as_posix()
        (root / POINTER).write_text(json.dumps(pointer, indent=2) + "\n")
    return path


def review(root: Path, generation: str) -> None:
    """Add a reviewed-index entry for a generation that has no folder (receipts need none)."""
    index = json.loads((root / REVIEWED).read_text())
    index["generations"][generation] = "0" * 64
    (root / REVIEWED).write_text(json.dumps(index, indent=2) + "\n")


def declare(root: Path, generation: str) -> None:
    """Make the first consumer declare a concrete generation, as a reviewed registry change."""
    data = json.loads((root / CONSUMERS).read_text())
    data["consumers"][0]["generation"] = generation
    (root / CONSUMERS).write_text(json.dumps(data, indent=2) + "\n")
    rebind(root)


def test_the_real_history_is_sound_and_says_what_it_cannot_prove(
    tmp_path: Path,
) -> None:
    """The retained history replays while disclosing its offline authorization limit."""
    code, report = run(ROOT)
    assert code == 0 and report["ok"], report
    assert (
        report["active"] == "m1-gen2"
        and report["receipts"] == 2
        and report["retired"] == []
    )
    assert "not verified offline" in report["authorization"]


def test_the_real_receipts_are_pinned_so_history_cannot_be_rewritten() -> None:
    """Pinned receipt hashes make retrospective edits detectable."""
    for name, digest in PINNED_RECEIPTS.items():
        assert (
            hashlib.sha256((ROOT / RECEIPTS / name).read_bytes()).hexdigest() == digest
        ), name


def test_a_missing_first_receipt_breaks_the_sequence(tmp_path: Path) -> None:
    """A receipt chain must start at its retained first transition."""
    root = make_root(tmp_path)
    receipts(root)[0].unlink()
    code, report = run(root)
    assert code == 1 and codes(report) == ["receipt.sequence"]


def test_editing_an_old_receipt_breaks_the_chain(tmp_path: Path) -> None:
    """Changing a retained receipt invalidates its successor hash link."""
    root = make_root(tmp_path)
    first = receipts(root)[0]
    body = json.loads(first.read_text())
    body["reason"] = "rewritten history"
    first.write_text(json.dumps(body, indent=2) + "\n")
    code, report = run(root)
    assert code == 1 and codes(report) == ["receipt.chain"]


def test_a_renamed_receipt_is_refused(tmp_path: Path) -> None:
    """Receipt filenames are part of the closed transition representation."""
    root = make_root(tmp_path)
    second = receipts(root)[1]
    second.rename(second.with_name("0003-activate-m1-gen2.json"))
    assert codes(run(root)[1]) == ["receipt.invalid"]


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"seq": "2"},
        {"reason": "  "},
        {"retroactive": "yes"},
        {"approval": {"repository": "x", "pull_request": 0, "evidence": "e"}},
        {"approval": {"repository": "x", "pull_request": 1}},
    ],
)
def test_a_receipt_with_the_wrong_shape_is_refused(
    tmp_path: Path, change: dict
) -> None:
    """Closed receipt keys and value types reject malformed transitions."""
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    body = json.loads(last.read_text())
    body.update(change)
    last.write_text(json.dumps(body, indent=2) + "\n")
    assert "receipt.invalid" in codes(run(root)[1])


def test_a_duplicate_key_in_a_receipt_is_refused(tmp_path: Path) -> None:
    """Duplicate JSON members cannot produce an ambiguous transition record."""
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    last.write_text(
        last.read_text().replace(
            '"kind": "activate",', '"kind": "activate", "kind": "rollback",', 1
        )
    )
    assert codes(run(root)[1]) == ["json.invalid"]


def test_a_symlinked_receipt_is_refused(tmp_path: Path) -> None:
    """Receipt paths must resolve to retained regular files, not symlinks."""
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    target = tmp_path / "real.json"
    shutil.move(last, target)
    last.symlink_to(target)
    assert "receipt.invalid" in codes(run(root)[1])


def test_no_receipts_is_refused(tmp_path: Path) -> None:
    """An empty transition directory cannot establish an active generation."""
    root = make_root(tmp_path)
    shutil.rmtree(root / RECEIPTS)
    assert codes(run(root)[1]) == ["receipt.missing"]


def test_activating_an_unreviewed_generation_is_refused(tmp_path: Path) -> None:
    """Only reviewed generations may become active through a transition."""
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen9", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.unreviewed"]


def test_activating_from_the_wrong_generation_is_refused(tmp_path: Path) -> None:
    """An activation must name the generation currently active before it."""
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen1", None)
    assert codes(run(root)[1]) == ["transition.from"]


def test_activating_the_already_active_generation_is_refused(tmp_path: Path) -> None:
    """No-op activation records are not valid lifecycle transitions."""
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen2", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.noop"]


def test_a_rollback_to_a_previously_active_generation_is_a_receipt_not_a_state(
    tmp_path: Path,
) -> None:
    """Rollback is represented as a transition receipt rather than a generation state."""
    root = make_root(tmp_path)
    append(root, "rollback", "m1-gen1", "m1-gen2")
    code, report = run(root)
    assert code == 0 and report["active"] == "m1-gen1" and report["receipts"] == 3, (
        report
    )


def test_a_rollback_without_moving_the_pointer_is_refused(tmp_path: Path) -> None:
    """A rollback receipt and the active pointer must move together."""
    root = make_root(tmp_path)
    append(root, "rollback", "m1-gen1", "m1-gen2", move=False)
    assert codes(run(root)[1]) == ["pointer.mismatch"]


def test_a_rollback_to_a_generation_that_was_never_active_is_refused(
    tmp_path: Path,
) -> None:
    """Rollback targets must have been active earlier in the replayed history."""
    root = make_root(tmp_path)
    review(root, "m1-gen3")
    append(root, "rollback", "m1-gen3", "m1-gen2")
    assert codes(run(root)[1]) == ["rollback.never_active"]


def test_the_pointer_must_name_the_last_move(tmp_path: Path) -> None:
    """The active pointer must cite the final retained transition receipt."""
    root = make_root(tmp_path)
    pointer = json.loads((root / POINTER).read_text())
    pointer["transition_receipt"] = (
        "requirements/generations/transitions/0001-activate-m1-gen1.json"
    )
    (root / POINTER).write_text(json.dumps(pointer, indent=2) + "\n")
    assert codes(run(root)[1]) == ["pointer.mismatch"]


def test_retiring_the_active_generation_is_refused(tmp_path: Path) -> None:
    """The currently active generation cannot be retired."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen2", None)
    assert codes(run(root)[1]) == ["retire.active"]


def test_retiring_a_declared_generation_is_refused(tmp_path: Path) -> None:
    """A consumer-declared generation remains protected from retirement."""
    root = make_root(tmp_path)
    declare(root, "m1-gen1")
    append(root, "retire", "m1-gen1", None)
    assert codes(run(root)[1]) == ["retire.declared"]


def test_a_retirement_carries_no_from_generation(tmp_path: Path) -> None:
    """Retirement is not a pointer move and therefore has no predecessor generation."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.from"]


def test_retiring_an_inactive_undeclared_generation_works_and_is_final(
    tmp_path: Path,
) -> None:
    """An unused inactive generation may retire and cannot later be restored."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    code, report = run(root)
    assert code == 0 and report["retired"] == ["m1-gen1"], report
    append(root, "rollback", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.retired"]


def test_a_retired_generation_cannot_be_activated(tmp_path: Path) -> None:
    """Retirement permanently excludes a generation from later activation."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    append(root, "activate", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.retired"]


def test_a_consumer_cannot_declare_a_retired_generation(tmp_path: Path) -> None:
    """Consumer declarations cannot revive a retired generation."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    declare(root, "m1-gen1")
    assert codes(run(root)[1]) == ["retire.declared"]


def test_validation_writes_nothing_and_is_repeatable(tmp_path: Path) -> None:
    """Validation is pure and returns identical reports for identical retained inputs."""
    root = make_root(tmp_path)
    for damage in (lambda: None, lambda: receipts(root)[0].unlink()):
        damage()
        before = snapshot(root)
        first, second = run(root), run(root)
        assert first == second and snapshot(root) == before


REVIEWED_INDEX_SHA256 = (
    "c096b9d41e7ea90ff8c3f927da4b6fb02ec79e2c228181e3315892357a28e92b"
)


def test_the_reviewed_index_is_pinned_and_binds_the_real_registry() -> None:
    """The index is a reviewed input: its bytes are pinned, and it names the real registry digest."""
    index_bytes = (ROOT / REVIEWED).read_bytes()
    assert hashlib.sha256(index_bytes).hexdigest() == REVIEWED_INDEX_SHA256
    assert json.loads(index_bytes)["consumers_registry_sha256"] == registry_sha(ROOT)


def registry_attack(root: Path, registry: dict | None) -> None:
    """Replace or delete the consumer registry, then append a chained retirement of m1-gen1."""
    before = registry_sha(root)
    if registry is None:
        (root / CONSUMERS).unlink()
        append(root, "retire", "m1-gen1", None, consumers_registry_sha256=before)
        return
    (root / CONSUMERS).write_text(json.dumps(registry, indent=2) + "\n")
    append(root, "retire", "m1-gen1", None)


@pytest.mark.parametrize(
    ("registry", "expected"),
    [
        ({"schema": 1, "consumers": []}, "registry.mismatch"),
        (
            {
                "schema": 1,
                "consumers": [
                    {"id": "x", "kind": "ci", "generation": "m1-gen2", "checks": []}
                ],
            },
            "registry.mismatch",
        ),
        (None, "declaration.missing"),
    ],
    ids=["emptied", "replaced_by_an_unrelated_list", "deleted"],
)
def test_removing_or_replacing_the_registry_cannot_unlock_a_retirement(
    tmp_path: Path, registry: dict | None, expected: str
) -> None:
    """The fail-open found in review: no registry means no declarations, so retire passed."""
    root = make_root(tmp_path)
    registry_attack(root, registry)
    code, report = run(root)
    assert code == 1 and expected in codes(report), report


def test_a_reviewed_registry_change_with_its_receipt_is_accepted(
    tmp_path: Path,
) -> None:
    """A registry change is valid only when its reviewed digest and receipt agree."""
    root = make_root(tmp_path)
    data = json.loads((root / CONSUMERS).read_text())
    data["consumers"][1]["generation"] = "m1-gen2"
    (root / CONSUMERS).write_text(json.dumps(data, indent=2) + "\n")
    rebind(root)
    code, report = run(root)
    assert code == 0 and report["receipts"] == 3, report


def test_a_registry_change_without_a_registry_receipt_is_refused(
    tmp_path: Path,
) -> None:
    """Changing the registry without its transition receipt is rejected."""
    root = make_root(tmp_path)
    data = json.loads((root / CONSUMERS).read_text())
    data["consumers"][1]["generation"] = "m1-gen2"
    (root / CONSUMERS).write_text(json.dumps(data, indent=2) + "\n")
    rebind(root, receipt=False)
    assert "registry.mismatch" in codes(run(root)[1])


def test_a_registry_receipt_without_the_reviewed_index_update_is_refused(
    tmp_path: Path,
) -> None:
    """A registry receipt cannot authorize bytes absent from the reviewed index."""
    root = make_root(tmp_path)
    data = json.loads((root / CONSUMERS).read_text())
    data["consumers"][1]["generation"] = "m1-gen2"
    (root / CONSUMERS).write_text(json.dumps(data, indent=2) + "\n")
    rebind(root, index=False)
    assert "registry.mismatch" in codes(run(root)[1])


def test_a_receipt_that_disagrees_with_the_tracked_registry_digest_is_refused(
    tmp_path: Path,
) -> None:
    """Each receipt must chain the registry digest currently tracked by the index."""
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None, consumers_registry_sha256="0" * 64)
    assert "registry.chain" in codes(run(root)[1])


def test_a_registry_receipt_must_name_the_active_generation_and_change_the_digest(
    tmp_path: Path,
) -> None:
    """Registry receipts bind the active generation and must advance the digest."""
    root = make_root(tmp_path)
    append(root, "registry", "m1-gen1", None)
    assert "registry.generation" in codes(run(root)[1])
    root2 = make_root(tmp_path / "second")
    append(root2, "registry", "m1-gen2", None)
    assert "transition.noop" in codes(run(root2)[1])
