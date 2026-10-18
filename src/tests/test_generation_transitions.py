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
    "0001-activate-m1-gen1.json": "5aadf4444c01169dc800dcb8890b4feaafd5d826a5f00225e8c0896a346e1e35",
    "0002-activate-m1-gen2.json": "7c82a734e716c495f8ea28b1ee3f22699aaa9bc187e14c311c738bec26b146b8",
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
    return [problem["code"] for problem in report["problems"]]


def snapshot(root: Path) -> dict[str, str]:
    """Digest every file under ``root`` to prove the validator wrote nothing."""
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def receipts(root: Path) -> list[Path]:
    return sorted((root / RECEIPTS).glob("*.json"))


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
    """Make the first consumer declare a concrete generation."""
    data = json.loads((root / CONSUMERS).read_text())
    data["consumers"][0]["generation"] = generation
    (root / CONSUMERS).write_text(json.dumps(data, indent=2) + "\n")


def test_the_real_history_is_sound_and_says_what_it_cannot_prove(
    tmp_path: Path,
) -> None:
    code, report = run(ROOT)
    assert code == 0 and report["ok"], report
    assert (
        report["active"] == "m1-gen2"
        and report["receipts"] == 2
        and report["retired"] == []
    )
    assert "not verified offline" in report["authorization"]


def test_the_real_receipts_are_pinned_so_history_cannot_be_rewritten() -> None:
    for name, digest in PINNED_RECEIPTS.items():
        assert (
            hashlib.sha256((ROOT / RECEIPTS / name).read_bytes()).hexdigest() == digest
        ), name


def test_a_missing_first_receipt_breaks_the_sequence(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    receipts(root)[0].unlink()
    code, report = run(root)
    assert code == 1 and codes(report) == ["receipt.sequence"]


def test_editing_an_old_receipt_breaks_the_chain(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    first = receipts(root)[0]
    body = json.loads(first.read_text())
    body["reason"] = "rewritten history"
    first.write_text(json.dumps(body, indent=2) + "\n")
    code, report = run(root)
    assert code == 1 and codes(report) == ["receipt.chain"]


def test_a_renamed_receipt_is_refused(tmp_path: Path) -> None:
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
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    body = json.loads(last.read_text())
    body.update(change)
    last.write_text(json.dumps(body, indent=2) + "\n")
    assert "receipt.invalid" in codes(run(root)[1])


def test_a_duplicate_key_in_a_receipt_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    last.write_text(
        last.read_text().replace(
            '"kind": "activate",', '"kind": "activate", "kind": "rollback",', 1
        )
    )
    assert codes(run(root)[1]) == ["json.invalid"]


def test_a_symlinked_receipt_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    last = receipts(root)[-1]
    target = tmp_path / "real.json"
    shutil.move(last, target)
    last.symlink_to(target)
    assert "receipt.invalid" in codes(run(root)[1])


def test_no_receipts_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    shutil.rmtree(root / RECEIPTS)
    assert codes(run(root)[1]) == ["receipt.missing"]


def test_activating_an_unreviewed_generation_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen9", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.unreviewed"]


def test_activating_from_the_wrong_generation_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen1", None)
    assert codes(run(root)[1]) == ["transition.from"]


def test_activating_the_already_active_generation_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "activate", "m1-gen2", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.noop"]


def test_a_rollback_to_a_previously_active_generation_is_a_receipt_not_a_state(
    tmp_path: Path,
) -> None:
    root = make_root(tmp_path)
    append(root, "rollback", "m1-gen1", "m1-gen2")
    code, report = run(root)
    assert code == 0 and report["active"] == "m1-gen1" and report["receipts"] == 3, (
        report
    )


def test_a_rollback_without_moving_the_pointer_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "rollback", "m1-gen1", "m1-gen2", move=False)
    assert codes(run(root)[1]) == ["pointer.mismatch"]


def test_a_rollback_to_a_generation_that_was_never_active_is_refused(
    tmp_path: Path,
) -> None:
    root = make_root(tmp_path)
    review(root, "m1-gen3")
    append(root, "rollback", "m1-gen3", "m1-gen2")
    assert codes(run(root)[1]) == ["rollback.never_active"]


def test_the_pointer_must_name_the_last_move(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    pointer = json.loads((root / POINTER).read_text())
    pointer["transition_receipt"] = (
        "requirements/generations/transitions/0001-activate-m1-gen1.json"
    )
    (root / POINTER).write_text(json.dumps(pointer, indent=2) + "\n")
    assert codes(run(root)[1]) == ["pointer.mismatch"]


def test_retiring_the_active_generation_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen2", None)
    assert codes(run(root)[1]) == ["retire.active"]


def test_retiring_a_declared_generation_is_refused(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    declare(root, "m1-gen1")
    append(root, "retire", "m1-gen1", None)
    assert codes(run(root)[1]) == ["retire.declared"]


def test_a_retirement_carries_no_from_generation(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.from"]


def test_retiring_an_inactive_undeclared_generation_works_and_is_final(
    tmp_path: Path,
) -> None:
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    code, report = run(root)
    assert code == 0 and report["retired"] == ["m1-gen1"], report
    append(root, "rollback", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.retired"]


def test_a_retired_generation_cannot_be_activated(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    append(root, "activate", "m1-gen1", "m1-gen2")
    assert codes(run(root)[1]) == ["transition.retired"]


def test_a_consumer_cannot_declare_a_retired_generation(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    append(root, "retire", "m1-gen1", None)
    declare(root, "m1-gen1")
    assert codes(run(root)[1]) == ["retire.declared"]


def test_validation_writes_nothing_and_is_repeatable(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    for damage in (lambda: None, lambda: receipts(root)[0].unlink()):
        damage()
        before = snapshot(root)
        first, second = run(root), run(root)
        assert first == second and snapshot(root) == before
