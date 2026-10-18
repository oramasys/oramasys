"""Acceptance and mutation test suite for G2 generation pointer consistency.

Implements acceptance cases G2-01 through G2-18 from ref/g2-spec.md against the
pure checker repo/scripts/check_generation_pointer.py.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_generation_pointer.py"


def make_root(tmp_path: Path) -> Path:
    """Create an isolated test directory populated with repository inputs."""
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "requirements", root / "requirements")
    shutil.copy2(ROOT / "pyproject.toml", root / "pyproject.toml")
    (root / ".github").mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / ".github" / "workflows", root / ".github" / "workflows")
    fixtures_dir = root / "src" / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        ROOT / "src" / "tests" / "fixtures" / "graph-ownership-registry.json",
        fixtures_dir / "graph-ownership-registry.json",
    )
    return root


def run_cli(root: Path) -> tuple[int, str, dict[str, Any]]:
    """Execute the check_generation_pointer script and return rc, stdout, and parsed JSON."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except ValueError:
        report = {}
    return proc.returncode, proc.stdout, report


def run(root: Path) -> tuple[int, dict[str, Any]]:
    """Execute the check_generation_pointer script and return rc and parsed JSON."""
    rc, _, report = run_cli(root)
    return rc, report


def codes(report: dict[str, Any]) -> set[str]:
    """Extract the set of refusal problem codes from a report."""
    return {
        p["code"]
        for p in report.get("problems", [])
        if isinstance(p, dict) and "code" in p
    }


def snapshot(root: Path) -> dict[str, str]:
    """Capture relative file paths and their sha256 digests under root."""
    state: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            state[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


def test_g2_01_explicit_edge_success_names_resolved_generation(tmp_path: Path) -> None:
    """G2-01: Explicit edge succeeds, resolves active generation, and verifies consumers."""
    root = make_root(tmp_path)
    rc, report = run(root)
    assert rc == 0
    assert report["ok"] is True
    assert report["problems"] == []
    assert report["pointer"] is not None
    assert report["pointer"]["generation"] == "m1-gen2"
    assert report["pointer"]["authorization"] == "not judged here"
    assert report["generations"]["m1-gen2"] == "intact"
    assert len(report["consumers"]) == 10
    for consumer in report["consumers"]:
        assert consumer["ok"] is True
        assert consumer["declared"] == "edge"
        assert consumer["resolved"] == "m1-gen2"


@pytest.mark.parametrize(
    "target",
    [
        "package-dependencies",
        "ci-production-install",
        "final-producers-install-plan",
        "missing_file",
    ],
)
def test_g2_02_remove_declaration_refused(tmp_path: Path, target: str) -> None:
    """G2-02: Removing declaration refuses closed and never silently resolves active pointer."""
    root = make_root(tmp_path)
    consumers_file = root / "requirements" / "generation-consumers.json"
    if target == "missing_file":
        consumers_file.unlink()
        expected_subject = "requirements/generation-consumers.json"
    else:
        doc = json.loads(consumers_file.read_text(encoding="utf-8"))
        for entry in doc["consumers"]:
            if entry.get("id") == target:
                del entry["generation"]
        consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        expected_subject = target

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "declaration.missing" in codes(report)
    assert any(
        p["code"] == "declaration.missing" and p["subject"] == expected_subject
        for p in report["problems"]
    )
    if target != "missing_file":
        row = next(c for c in report["consumers"] if c["id"] == target)
        assert row["ok"] is False
        assert row["resolved"] is None


@pytest.mark.parametrize(
    "invalid_selector",
    ["", None, 42, "INVALID_CHARS!", "a" * 65],
)
def test_g2_03_invalid_selector_refused(tmp_path: Path, invalid_selector: Any) -> None:
    """G2-03: Empty, null, non-string, or invalid selector fails before generation access."""
    root = make_root(tmp_path)
    consumers_file = root / "requirements" / "generation-consumers.json"
    doc = json.loads(consumers_file.read_text(encoding="utf-8"))
    target_id = doc["consumers"][0]["id"]
    doc["consumers"][0]["generation"] = invalid_selector
    consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "declaration.invalid" in codes(report)
    assert any(
        p["code"] == "declaration.invalid" and p["subject"] == target_id
        for p in report["problems"]
    )
    assert report["consumers"][0]["resolved"] is None


@pytest.mark.parametrize("mode", ["both_fields", "duplicate_keys"])
def test_g2_04_ambiguous_declaration_refused(tmp_path: Path, mode: str) -> None:
    """G2-04: Conflicting declarations or duplicate JSON keys are refused as ambiguous."""
    root = make_root(tmp_path)
    consumers_file = root / "requirements" / "generation-consumers.json"
    if mode == "both_fields":
        doc = json.loads(consumers_file.read_text(encoding="utf-8"))
        doc["consumers"][0]["edge"] = True
        consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        expected_subject = doc["consumers"][0]["id"]
    else:
        text = consumers_file.read_text(encoding="utf-8")
        text = text.replace('"schema": 1,', '"schema": 1,\n  "schema": 1,', 1)
        consumers_file.write_text(text, encoding="utf-8")
        expected_subject = "requirements/generation-consumers.json"

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "declaration.ambiguous" in codes(report)
    assert any(
        p["code"] == "declaration.ambiguous" and p["subject"] == expected_subject
        for p in report["problems"]
    )


def test_g2_05_concrete_generation_id_resolves_without_active(tmp_path: Path) -> None:
    """G2-05: Concrete generation id resolves without substituting active pointer."""
    root = make_root(tmp_path)
    pointer_file = root / "requirements" / "ACTIVE-GENERATION.json"
    active_ptr = {
        "schema": 1,
        "generation": "m1-gen1",
        "record_sha256": "a0457ab37d69144bb100adb5be2b9c4fbd21fec27bc5531d7339bc60d1251014",
        "transition_receipt": "requirements/generations/transitions/0001-activate-m1-gen1.json",
    }
    pointer_file.write_text(json.dumps(active_ptr, indent=2), encoding="utf-8")

    consumers_file = root / "requirements" / "generation-consumers.json"
    doc = json.loads(consumers_file.read_text(encoding="utf-8"))
    for entry in doc["consumers"]:
        entry["generation"] = "m1-gen2"
    consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    rc, report = run(root)
    assert rc == 0
    assert report["ok"] is True
    assert report["problems"] == []
    assert report["pointer"] is None
    for entry in report["consumers"]:
        assert entry["declared"] == "m1-gen2"
        assert entry["resolved"] == "m1-gen2"
        assert entry["ok"] is True


@pytest.mark.parametrize("mutation", ["unknown_id", "escaping_id", "traversal_file"])
def test_g2_06_unknown_or_escaping_generation_refused(
    tmp_path: Path, mutation: str
) -> None:
    """G2-06: Unknown or escaping generation identifiers are refused with no arbitrary reads."""
    root = make_root(tmp_path)
    consumers_file = root / "requirements" / "generation-consumers.json"
    doc = json.loads(consumers_file.read_text(encoding="utf-8"))
    if mutation == "unknown_id":
        doc["consumers"][0]["generation"] = "m1-gen99"
        expected_code = "generation.unknown"
    elif mutation == "escaping_id":
        doc["consumers"][0]["generation"] = "../../etc/passwd"
        expected_code = "declaration.invalid"
    else:
        doc["consumers"][0]["checks"][0]["file"] = "../outside.txt"
        expected_code = "path.unsafe"
    consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert expected_code in codes(report)
    assert any(p["code"] == expected_code for p in report["problems"])


@pytest.mark.parametrize(
    "corruption",
    ["missing", "corrupt_json", "wrong_schema", "unknown_gen"],
)
def test_g2_07_missing_or_corrupt_pointer_with_edge_refused(
    tmp_path: Path, corruption: str
) -> None:
    """G2-07: Missing or corrupt active pointer refuses closed without newest dir fallback."""
    root = make_root(tmp_path)
    pointer_file = root / "requirements" / "ACTIVE-GENERATION.json"
    if corruption == "missing":
        pointer_file.unlink()
        expected_code = "pointer.missing"
    elif corruption == "corrupt_json":
        pointer_file.write_text("{invalid json", encoding="utf-8")
        expected_code = "pointer.invalid"
    elif corruption == "wrong_schema":
        ptr = json.loads(pointer_file.read_text(encoding="utf-8"))
        ptr["schema"] = 999
        pointer_file.write_text(json.dumps(ptr, indent=2), encoding="utf-8")
        expected_code = "pointer.invalid"
    else:
        ptr = json.loads(pointer_file.read_text(encoding="utf-8"))
        ptr["generation"] = "unreviewed-gen"
        pointer_file.write_text(json.dumps(ptr, indent=2), encoding="utf-8")
        expected_code = "generation.unknown"

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert expected_code in codes(report)
    assert report["pointer"] is None
    for entry in report["consumers"]:
        assert entry["declared"] == "edge"
        assert entry["resolved"] is None
        assert entry["ok"] is False


def test_g2_08_concrete_selector_without_active_pointer(tmp_path: Path) -> None:
    """G2-08: Concrete selector resolves without pointer and makes no global active claim."""
    root = make_root(tmp_path)
    consumers_file = root / "requirements" / "generation-consumers.json"
    doc = json.loads(consumers_file.read_text(encoding="utf-8"))
    for entry in doc["consumers"]:
        entry["generation"] = "m1-gen2"
    consumers_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    (root / "requirements" / "ACTIVE-GENERATION.json").unlink()

    rc, report = run(root)
    assert rc == 0
    assert report["ok"] is True
    assert report["problems"] == []
    assert report["pointer"] is None
    for entry in report["consumers"]:
        assert entry["declared"] == "m1-gen2"
        assert entry["resolved"] == "m1-gen2"
        assert entry["ok"] is True


@pytest.mark.parametrize(
    "name,sha",
    [
        ("core", "6d75cfe08af95992dddffab13ae3019aa9c41350"),
        ("telos", "931b6347142e8e66b31136e3ac8159d86eb5b2f7"),
        ("agate", "172bfc3ebf00d507856e70d0f6a0e7dbd577ffbc"),
    ],
)
def test_g2_09_each_production_pin_drift_is_refused(
    tmp_path: Path, name: str, sha: str
) -> None:
    """G2-09: Drifting each production pin in pyproject.toml is refused individually."""
    root = make_root(tmp_path)
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert sha in text
    pyproject.write_text(text.replace(sha, "0" * 40, 1), encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "pin.drift" in codes(report)
    assert any(
        p["code"] == "pin.drift"
        and p["subject"] == "package-dependencies:pyproject.toml"
        for p in report["problems"]
    )
    row = next(c for c in report["consumers"] if c["id"] == "package-dependencies")
    assert row["ok"] is False


def test_g2_10_optional_phylax_pin_drift_is_refused(tmp_path: Path) -> None:
    """G2-10: Changing optional Phylax pin in pyproject.toml refuses without installing extra."""
    root = make_root(tmp_path)
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    phylax_sha = "0c3e860749b3ff8f62e102679f1f415f8acf0a61"
    assert phylax_sha in text
    pyproject.write_text(text.replace(phylax_sha, "1" * 40, 1), encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "pin.drift" in codes(report)
    assert any(
        p["code"] == "pin.drift"
        and p["subject"] == "package-dependencies:pyproject.toml"
        for p in report["problems"]
    )
    row = next(c for c in report["consumers"] if c["id"] == "package-dependencies")
    assert row["ok"] is False


@pytest.mark.parametrize("target", ["lane", "ci"])
def test_g2_11_lane_or_ci_pin_drift_refused(tmp_path: Path, target: str) -> None:
    """G2-11: Changing lane or CI pins refuses drift while package metadata stays valid."""
    root = make_root(tmp_path)
    if target == "lane":
        lane_file = root / "requirements" / "compatibility-core-production.txt"
        lane_file.write_text("2" * 40 + "\n", encoding="utf-8")
        expected_subject = (
            "production-core-lane:requirements/compatibility-core-production.txt"
        )
        affected_id = "production-core-lane"
    else:
        ci_file = root / ".github" / "workflows" / "ci.yml"
        text = ci_file.read_text(encoding="utf-8")
        core_sha = "6d75cfe08af95992dddffab13ae3019aa9c41350"
        ci_file.write_text(text.replace(core_sha, "2" * 40, 1), encoding="utf-8")
        expected_subject = "ci-production-install:.github/workflows/ci.yml"
        affected_id = "ci-production-install"

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "pin.drift" in codes(report)
    assert any(
        p["code"] == "pin.drift" and p["subject"] == expected_subject
        for p in report["problems"]
    )
    pkg_row = next(c for c in report["consumers"] if c["id"] == "package-dependencies")
    assert pkg_row["ok"] is True
    affected_row = next(c for c in report["consumers"] if c["id"] == affected_id)
    assert affected_row["ok"] is False


@pytest.mark.parametrize("field", ["consumer_sha", "registry_ref", "registry_digest"])
def test_g2_12_identity_mismatch_refused(tmp_path: Path, field: str) -> None:
    """G2-12: Substituting consumer SHA, registry ref, or registry digest refuses identity."""
    root = make_root(tmp_path)
    manifest_file = root / "requirements" / "compatibility-manifest.v3.json"
    if field == "consumer_sha":
        doc = json.loads(manifest_file.read_text(encoding="utf-8"))
        doc["consumer"]["sha"] = "3" * 40
        manifest_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        expected_subject = "qualification-manifest-identity:requirements/compatibility-manifest.v3.json"
    elif field == "registry_ref":
        doc = json.loads(manifest_file.read_text(encoding="utf-8"))
        doc["producer_registry"]["ref"] = "3" * 40
        manifest_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        expected_subject = "qualification-manifest-identity:requirements/compatibility-manifest.v3.json"
    else:
        reg_file = root / "src" / "tests" / "fixtures" / "graph-ownership-registry.json"
        reg_file.write_text(
            reg_file.read_text(encoding="utf-8") + "\n", encoding="utf-8"
        )
        expected_subject = "qualification-manifest-identity:src/tests/fixtures/graph-ownership-registry.json"

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "identity.mismatch" in codes(report)
    assert any(
        p["code"] == "identity.mismatch" and p["subject"] == expected_subject
        for p in report["problems"]
    )


@pytest.mark.parametrize(
    "target", ["copied_input", "generation_record", "inventory_file"]
)
def test_g2_13_generation_integrity_refused(tmp_path: Path, target: str) -> None:
    """G2-13: Mutating copied inputs, record, or inventory trips generation.integrity."""
    root = make_root(tmp_path)
    gen_dir = root / "requirements" / "generations" / "m1-gen2"
    if target == "copied_input":
        target_file = gen_dir / "inputs" / "compatibility-manifest.v3.json"
        target_file.write_text(
            target_file.read_text(encoding="utf-8") + " ", encoding="utf-8"
        )
    elif target == "generation_record":
        record_file = gen_dir / "generation.json"
        rec = json.loads(record_file.read_text(encoding="utf-8"))
        rec["kind"] = "tampered-generation"
        record_file.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    else:
        extra_file = gen_dir / "inputs" / "extra_file.json"
        extra_file.write_text("{}", encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "generation.integrity" in codes(report)
    assert report["generations"]["m1-gen2"] == "refused"
    assert any(
        p["code"] == "generation.integrity" and p["subject"] == "m1-gen2"
        for p in report["problems"]
    )


def test_g2_14_unreviewed_generation_folder_refused(tmp_path: Path) -> None:
    """G2-14: Adding an unreviewed generation folder is refused without allowlist expansion."""
    root = make_root(tmp_path)
    unreviewed = root / "requirements" / "generations" / "m1-gen3"
    unreviewed.mkdir(parents=True, exist_ok=True)
    before_reviewed = (
        root / "requirements" / "generations" / "reviewed.json"
    ).read_bytes()

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "generation.unreviewed" in codes(report)
    assert any(
        p["code"] == "generation.unreviewed" and p["subject"] == "m1-gen3"
        for p in report["problems"]
    )
    after_reviewed = (
        root / "requirements" / "generations" / "reviewed.json"
    ).read_bytes()
    assert before_reviewed == after_reviewed


def test_g2_15_tampered_historical_generation_refused(tmp_path: Path) -> None:
    """G2-15: Mutating historical generation pins fails integrity and is never auto-repaired."""
    root = make_root(tmp_path)
    gen1_record = root / "requirements" / "generations" / "m1-gen1" / "generation.json"
    doc = json.loads(gen1_record.read_text(encoding="utf-8"))
    doc["pins"]["neutral-mechanics"]["production_pin"] = (
        "6d75cfe08af95992dddffab13ae3019aa9c41350"
    )
    gen1_record.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    rc, report = run(root)
    assert rc == 1
    assert report["ok"] is False
    assert "generation.integrity" in codes(report)
    assert report["generations"]["m1-gen1"] == "refused"
    assert any(
        p["code"] == "generation.integrity" and p["subject"] == "m1-gen1"
        for p in report["problems"]
    )


@pytest.mark.parametrize(
    "scenario",
    ["success", "refusal_declaration", "refusal_pointer", "refusal_pin"],
)
def test_g2_16_purity_identical_stdout_and_unchanged_snapshot(
    tmp_path: Path, scenario: str
) -> None:
    """G2-16: Running twice on success and refusal families yields identical stdout and state."""
    root = make_root(tmp_path)
    if scenario == "refusal_declaration":
        cf = root / "requirements" / "generation-consumers.json"
        doc = json.loads(cf.read_text(encoding="utf-8"))
        del doc["consumers"][0]["generation"]
        cf.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    elif scenario == "refusal_pointer":
        (root / "requirements" / "ACTIVE-GENERATION.json").unlink()
    elif scenario == "refusal_pin":
        pf = root / "pyproject.toml"
        text = pf.read_text(encoding="utf-8")
        pf.write_text(
            text.replace("6d75cfe08af95992dddffab13ae3019aa9c41350", "4" * 40, 1),
            encoding="utf-8",
        )

    snap_before = snapshot(root)
    rc1, out1, rep1 = run_cli(root)
    snap_mid = snapshot(root)
    rc2, out2, rep2 = run_cli(root)
    snap_after = snapshot(root)

    assert snap_before == snap_mid == snap_after
    assert rc1 == rc2
    assert out1 == out2
    assert rep1 == rep2
    if scenario == "success":
        assert rc1 == 0
    else:
        assert rc1 == 1


@pytest.mark.parametrize("mode", ["missing_receipt", "structurally_present"])
def test_g2_17_transition_receipt_binding_and_authorization(
    tmp_path: Path, mode: str
) -> None:
    """G2-17: Distinguish structurally present receipt from authorization and refuse missing."""
    root = make_root(tmp_path)
    if mode == "missing_receipt":
        receipt = (
            root
            / "requirements"
            / "generations"
            / "transitions"
            / "0002-activate-m1-gen2.json"
        )
        receipt.unlink()
        rc, report = run(root)
        assert rc == 1
        assert report["ok"] is False
        assert "pointer.receipt_missing" in codes(report)
        assert any(p["code"] == "pointer.receipt_missing" for p in report["problems"])
    else:
        rc, report = run(root)
        assert rc == 0
        assert report["ok"] is True
        assert report["pointer"] is not None
        assert report["pointer"]["authorization"] == "not judged here"


def test_g2_18_no_unsupported_lifecycle_claims(tmp_path: Path) -> None:
    """G2-18: Checker report makes no top-level lifecycle claims (state, approved, retired)."""
    root = make_root(tmp_path)
    rc, report = run(root)
    assert rc == 0
    forbidden_keys = {"state", "lifecycle", "approved", "retired"}
    assert not (forbidden_keys & set(report.keys()))
    assert set(report.keys()) == {
        "generations",
        "consumers",
        "pointer",
        "problems",
        "ok",
    }


# --- Added by the maker after mutation-testing the checker: two rules the draft left unproven ---


def re_review(root: Path, generation: str) -> None:
    """Make a damaged record look reviewed, so only the record's own internal checks can refuse."""
    digest = hashlib.sha256(
        (
            root / "requirements/generations" / generation / "generation.json"
        ).read_bytes()
    ).hexdigest()
    index_path = root / "requirements/generations/reviewed.json"
    index = json.loads(index_path.read_text())
    index["generations"][generation] = digest
    index_path.write_text(json.dumps(index, indent=2) + "\n")
    pointer_path = root / "requirements/ACTIVE-GENERATION.json"
    pointer = json.loads(pointer_path.read_text())
    if pointer["generation"] == generation:
        pointer["record_sha256"] = digest
        pointer_path.write_text(json.dumps(pointer, indent=2) + "\n")


@pytest.mark.parametrize(
    "damage", ["bad_inventory_digest", "unsorted_inventory", "wrong_id"]
)
def test_g2_13b_a_reviewed_record_with_a_broken_inventory_is_still_refused(
    tmp_path: Path, damage: str
) -> None:
    """The inventory checks must hold even when the record bytes were (wrongly) reviewed."""
    root = make_root(tmp_path)
    record_path = root / "requirements/generations/m1-gen2/generation.json"
    record = json.loads(record_path.read_text())
    if damage == "bad_inventory_digest":
        record["inventory_digest"] = "0" * 64
    elif damage == "unsorted_inventory":
        record["inventory"].reverse()
    else:
        record["id"] = "m1-gen1"
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    re_review(root, "m1-gen2")
    rc, report = run(root)
    assert rc == 1 and "generation.integrity" in codes(report), report["problems"]
    expected = {
        "bad_inventory_digest": "inventory digest differs",
        "unsorted_inventory": "unsorted or duplicated",
        "wrong_id": "record id or inventory is wrong",
    }[damage]
    assert any(expected in p["detail"] for p in report["problems"]), report["problems"]


def test_g2_09b_removing_a_pin_occurrence_is_a_count_refusal(tmp_path: Path) -> None:
    """A pin that disappears from a file is refused even though nothing left disagrees."""
    root = make_root(tmp_path)
    ci = root / ".github/workflows/ci.yml"
    text = ci.read_text()
    marker = "verify_production_install.py"
    assert marker in text
    ci.write_text(text.replace(marker, "verify_removed.py", 1))
    rc, report = run(root)
    assert rc == 1 and "pin.count" in codes(report), report["problems"]
    assert any(
        p["subject"].startswith("ci-production-install") for p in report["problems"]
    )
