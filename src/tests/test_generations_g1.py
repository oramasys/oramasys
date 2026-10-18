"""G1: immutable generation records for M1 generation 1 and 2, as data only.

Each folder under ``requirements/generations/`` is a canonical inventory (path, sha256, size,
role) plus copies of the bound inputs, the registry snapshot and the published evidence digests.
Accepted generations are never edited: a later change is a new generation and a reviewed addition
to ``EXPECT`` below. The verifier lives here, in the tests, and nothing at runtime, in CI or in
the install path reads these folders or an ``ACTIVE-GENERATION`` pointer (G2, a later stage).

Pinned literals are independent of the files they check: the inventory digests, the approved
manifest and coverage digests, and the commits come from the approvals and receipts, not from the
generation records.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from orama.compat.manifest import canonical_digest

ROOT = Path(__file__).resolve().parents[2]
GENERATIONS = ROOT / "requirements" / "generations"
HISTORY = ROOT / "requirements" / "history" / "m1-gen1"
FIXTURES = ROOT / "src" / "tests" / "fixtures"
SHA256 = "sha256"
COVERAGE_DIGEST = "6af7fa7a02fa6fca3b34ec0eff06a7e281c9b3f92d8de3bbdd4d325f8656b326"
ALLOWLIST_DIGEST = "6ecbbfe8e65f1e9cc2ee5ddb4077c8e7b57a664cf558403b69d5708da57b2ae0"

EXPECT = {
    "m1-gen1": {
        "record_sha256": "a0457ab37d69144bb100adb5be2b9c4fbd21fec27bc5531d7339bc60d1251014",
        "inventory_digest": "142fd8ac5b58e2482516271b8177daaae97934e8f3aaace3440c59ba08b38f77",
        "manifest_digest": "4892b6ba9894eee0e85deae3dcbb020a82f3afb55fadc7424f2a3cfa2dd6bae2",
        "harness_commit": "3332b615668d4040ff9d0e8cc0d888870e6160fa",
        "consumer_commit": "f8898b35d5249e483b2f4a68c097957e675a0ef4",
        "registry_ref": "65ec365293c6a892cd4f978e656cfb61c0d04b9a",
        "registry_sha256": "91d3c74b5cd9aea1d176dd87115f09151fc1e3a6155292aa58a32d8f7bb40787",
        "comment_id": 6217460696,
        "run_id": "38916773943",
        "core": "609ff0ed99cf8eca6c9ef608e764b7a25b6b9973",
    },
    "m1-gen2": {
        "record_sha256": "661371f533c9a9f3ec1d9de070580ffaef95076db79597d90de22a81290efb17",
        "inventory_digest": "47c7790b0d95eef57f5cb6ad7f86dcae77fb4ae7aa0b0667b2deb86d4479845c",
        "manifest_digest": "309d44440d4db0938ed55891ffa5a26768b420033982e6eaf71c1382b1d9a32f",
        "harness_commit": "902d2a8edc3fb1b9f7a91fe93a8aca6f4f000100",
        "consumer_commit": "133553a6d05b8704e6e4010f581d57623829f4b2",
        "registry_ref": "a5bdcd2b76a865e61f0ff2e752550ee73d18f82e",
        "registry_sha256": "1f1531d94f73309f2c3271af41313fd15bf5438ba0a91355ea81111fb66fcb34",
        "comment_id": 6241262040,
        "run_id": "39070456148",
        "core": "6d75cfe08af95992dddffab13ae3019aa9c41350",
    },
}
# Retained historical sources that generation 1's copies must equal, byte for byte.
GEN1_SOURCES = {
    "inputs/compatibility-manifest.v3.json": HISTORY / "compatibility-manifest.v3.json",
    "inputs/compatibility-manifest.json": HISTORY / "compatibility-manifest.json",
    "inputs/qualification-coverage-packet.v1.json": HISTORY
    / "qualification-coverage-packet.v1.json",
    "inputs/final-producers-install-plan.v1.json": HISTORY
    / "final-producers-install-plan.v1.json",
    "inputs/ownership-registry.json": FIXTURES
    / "graph-ownership-registry-m1-gen1.json",
}


def _sha(data: bytes) -> str:
    """Return the lowercase SHA-256 digest for fixture or record bytes."""
    return hashlib.sha256(data).hexdigest()


def _inventory_digest(inventory: list) -> str:
    """Canonical digest of an inventory: the manifest encoding rules (sorted keys, no spaces)."""
    return _sha(
        json.dumps(
            inventory,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    )


def load_record(folder: Path) -> dict:
    """Read a generation record, refusing duplicate keys."""

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict:
        """Reject duplicate JSON keys while reconstructing the object."""
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)

    return json.loads(
        (folder / "generation.json").read_text(encoding="utf-8"),
        object_pairs_hook=no_duplicates,
    )


def verify_generation(folder: Path) -> list[str]:
    """Return the problems found in one generation folder; empty means it is intact."""
    expected = EXPECT.get(folder.name)
    if expected is None:
        return ["generation has no pinned expectations"]
    try:
        record_bytes = (folder / "generation.json").read_bytes()
        record = load_record(folder)
    except (OSError, ValueError) as error:
        return [f"generation.json unreadable: {error}"]
    problems: list[str] = []
    if _sha(record_bytes) != expected["record_sha256"]:
        problems.append("generation.json differs from its reviewed bytes")
    inventory = record.get("inventory")
    if not isinstance(inventory, list) or not inventory:
        return ["inventory missing"]
    paths = [entry.get("path") for entry in inventory]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        problems.append("inventory paths must be unique and sorted")
    for entry in inventory:
        relative = Path(str(entry.get("path")))
        if relative.is_absolute() or ".." in relative.parts:
            problems.append(f"unsafe path {relative}")
            continue
        target = folder / relative
        if target.is_symlink() or not target.is_file():
            problems.append(f"{relative}: missing or not a regular file")
        elif _sha(target.read_bytes()) != entry.get(SHA256):
            problems.append(f"{relative}: sha256 differs")
        elif target.stat().st_size != entry.get("bytes"):
            problems.append(f"{relative}: size differs")
    present = {
        p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()
    }
    extra = present - set(paths) - {"generation.json"}
    problems.extend(f"{name}: not in the inventory" for name in sorted(extra))
    if record.get("inventory_digest") != _inventory_digest(inventory):
        problems.append("inventory_digest does not match the inventory")
    return problems


# The problem each tampering must produce. Pinning the whole record would refuse every record
# edit by itself, so each mutation must also trip the specific check that guards it.
REFUSAL = {
    "flip_byte": "sha256 differs",
    "extra_file": "not in the inventory",
    "missing_file": "missing or not a regular file",
    "bad_digest": "inventory_digest does not match",
    "unsorted": "unique and sorted",
    "symlink": "missing or not a regular file",
    "traversal": "unsafe path",
    "artifact_identity": "reviewed bytes",
    "record_identity": "reviewed bytes",
    "record_reserialization": "reviewed bytes",
}


@pytest.fixture(params=sorted(EXPECT))
def generation(request: pytest.FixtureRequest) -> str:
    """Parametrize integrity tests over every pinned immutable generation."""
    return request.param


def test_the_pinned_generations_are_present() -> None:
    """Every reviewed generation has a corresponding immutable folder."""
    assert set(EXPECT) <= {p.name for p in GENERATIONS.iterdir() if p.is_dir()}


def test_every_present_generation_is_intact_and_pinned() -> None:
    """A new generation is a reviewed addition to EXPECT, never an unpinned folder."""
    for folder in sorted(p for p in GENERATIONS.iterdir() if p.is_dir()):
        if folder.name == "transitions":
            continue  # G3 receipts: validated by test_generation_transitions, not generations
        assert folder.name in EXPECT, f"{folder.name} has no pinned expectations"
        assert verify_generation(folder) == [], folder.name


def test_inventory_digest_is_the_pinned_literal(generation: str) -> None:
    """A generation inventory retains its approved canonical digest."""
    record = load_record(GENERATIONS / generation)
    assert record["inventory_digest"] == EXPECT[generation]["inventory_digest"]


def test_identities_match_the_approvals_and_receipts(generation: str) -> None:
    """Generation identities agree with their captured approval and evidence facts."""
    expected = EXPECT[generation]
    record = load_record(GENERATIONS / generation)
    identities = record["identities"]
    assert identities["harness_commit"] == expected["harness_commit"]
    assert identities["consumer_commit"] == expected["consumer_commit"]
    assert identities["manifest_digest"] == expected["manifest_digest"]
    assert identities["coverage_digest"] == COVERAGE_DIGEST
    assert identities["allowlist_digest"] == ALLOWLIST_DIGEST
    assert identities["registry"] == {
        "repository": "orama-system",
        "ref": expected["registry_ref"],
        SHA256: expected["registry_sha256"],
    }
    assert identities["approval"]["comment_id"] == expected["comment_id"]
    assert record["evidence"]["run_id"] == expected["run_id"]
    assert record["pins"]["neutral-mechanics"]["production_pin"] == expected["core"]


def test_copies_agree_with_their_own_record(generation: str) -> None:
    """The manifest and coverage copies hash to the identities the record claims."""
    folder = GENERATIONS / generation
    record = load_record(folder)
    manifest = json.loads(
        (folder / "inputs/compatibility-manifest.v3.json").read_text()
    )
    coverage = json.loads(
        (folder / "inputs/qualification-coverage-packet.v1.json").read_text()
    )
    assert canonical_digest(manifest) == EXPECT[generation]["manifest_digest"]
    assert canonical_digest(coverage) == COVERAGE_DIGEST
    assert manifest["consumer"]["sha"] == record["identities"]["consumer_commit"]
    assert manifest["producer_registry"]["ref"] == EXPECT[generation]["registry_ref"]
    for role, pins in record["pins"].items():
        assert manifest["producers"][role].items() >= pins.items()


def test_evidence_digests_cover_nineteen_files_in_both_cells(generation: str) -> None:
    """Both interpreter cells seal the same nineteen evidence inputs."""
    evidence = json.loads(
        (GENERATIONS / generation / "evidence/sealed-digests.json").read_text()
    )
    sealed = evidence["sealed_files"]
    assert len(sealed) == 19
    for name, cells in sealed.items():
        assert set(cells) == {"3.11", "3.12"}, name
        assert all(
            len(v) == 64 and set(v) <= set("0123456789abcdef") for v in cells.values()
        )


def test_generation_one_copies_equal_the_retained_historical_sources() -> None:
    """The sources are kept where they were; the copies must equal them byte for byte."""
    folder = GENERATIONS / "m1-gen1"
    for relative, source in GEN1_SOURCES.items():
        assert (folder / relative).read_bytes() == source.read_bytes(), relative


@pytest.mark.parametrize(
    "mutation",
    [
        "flip_byte",
        "extra_file",
        "missing_file",
        "bad_digest",
        "unsorted",
        "symlink",
        "traversal",
        "artifact_identity",
        "record_identity",
        "record_reserialization",
    ],
)
def test_the_verifier_refuses_tampered_generations(
    tmp_path: Path, generation: str, mutation: str
) -> None:
    """Each check can fail: a damaged copy of a good generation must be refused."""
    folder = tmp_path / generation
    shutil.copytree(GENERATIONS / generation, folder)
    assert verify_generation(folder) == []
    target = folder / "inputs/compatibility-manifest.v3.json"
    record = load_record(folder)
    if mutation == "flip_byte":
        data = bytearray(target.read_bytes())
        data[10] ^= 1
        target.write_bytes(bytes(data))
    elif mutation == "extra_file":
        (folder / "inputs/extra.json").write_text("{}")
    elif mutation == "missing_file":
        target.unlink()
    elif mutation == "bad_digest":
        record["inventory_digest"] = "0" * 64
        (folder / "generation.json").write_text(json.dumps(record))
    elif mutation == "unsorted":
        record["inventory"].reverse()
        (folder / "generation.json").write_text(json.dumps(record))
    elif mutation == "symlink":
        target.unlink()
        target.symlink_to(
            GENERATIONS / generation / "inputs/compatibility-manifest.v3.json"
        )
    elif mutation == "traversal":
        record["inventory"][0]["path"] = "../escape.json"
        (folder / "generation.json").write_text(json.dumps(record))
    else:
        if mutation == "artifact_identity":
            record["evidence"]["artifacts"][0]["artifact_id"] = "0"
        elif mutation == "record_identity":
            record["id"] = "different-generation"
        (folder / "generation.json").write_text(json.dumps(record))
    problems = verify_generation(folder)
    assert any(REFUSAL[mutation] in problem for problem in problems), problems


def test_every_mutation_names_the_check_that_must_refuse_it() -> None:
    """Whole-record pinning must not mask the individual checks: each mutation has its own."""
    assert set(REFUSAL) == {
        "flip_byte",
        "extra_file",
        "missing_file",
        "bad_digest",
        "unsorted",
        "symlink",
        "traversal",
        "artifact_identity",
        "record_identity",
        "record_reserialization",
    }


# G2 deliberately admits exactly these two read-only checkers. Everything else stays barred from
# reading a generation or the pointer: no install, runtime, package-file or other workflow path.
CHECKERS = {
    "scripts/check_generation_pointer.py",
    "scripts/check_generation_transitions.py",
}


def test_only_the_two_read_only_checkers_consume_generations_or_the_pointer() -> None:
    """G1's data-only rule, evolved deliberately by G2: only the declared checkers read them."""
    needles = ("requirements/generations", "ACTIVE-GENERATION", "generation-consumers")
    scanned = [
        *(ROOT / ".github").rglob("*"),
        *(ROOT / "scripts").rglob("*"),
        *(ROOT / "src" / "orama").rglob("*.py"),
        ROOT / "pyproject.toml",
        *ROOT.glob("requirements/*.txt"),
        *ROOT.glob("requirements/*.in"),
        *(
            ROOT / name
            for name in ("Makefile", "tox.ini", "noxfile.py", "setup.cfg", "setup.py")
        ),
    ]
    for path in scanned:
        relative = path.relative_to(ROOT).as_posix()
        # Bytecode is a derived copy of the permitted checkers (importing them writes it), so it
        # is skipped; otherwise the result would depend on whether a checker ran first.
        if "__pycache__" in path.parts:
            continue
        if path.is_file() and relative not in CHECKERS:
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not any(n in text for n in needles), f"{relative} reads a generation"


def test_ci_runs_the_checkers_and_nothing_installs_from_a_generation() -> None:
    """The CI entrypoint names the two scripts; no workflow installs or activates from a pointer."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python scripts/check_generation_pointer.py" in ci
    assert "python scripts/check_generation_transitions.py" in ci
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        assert "pip install" not in "".join(
            line for line in text.splitlines() if "generation" in line
        ), workflow.name
