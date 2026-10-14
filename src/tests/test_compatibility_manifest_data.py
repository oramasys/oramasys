"""The committed schema-3 manifest data validates, hashes stably, and its digest script gates."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from orama.compat.manifest import ManifestError, canonical_digest, validate_manifest
from tests.test_compatibility_manifest import lane_shas
from tests.test_compatibility_pins import producer_refs
from tests.test_ownership_registry import CORE_PINS

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "requirements" / "compatibility-manifest.v3.json"
SCRIPT = ROOT / "scripts" / "compat_manifest_digest.py"
SHA_FIELDS = ("candidate", "production_pin")


def load() -> dict:
    """Read the committed schema-3 manifest."""
    return json.loads(DATA.read_text(encoding="utf-8"))


def check(manifest: dict, **kw) -> None:
    """Validate against the real registry pins and workflow producer ref."""
    ref = next(iter({r for v in producer_refs().values() for r in v}))
    validate_manifest(manifest, core_pins=CORE_PINS, lane_files=lane_shas(),
                      producer_ref=ref, **kw)


def run_script(*args: str) -> subprocess.CompletedProcess:
    """Run the digest script in a subprocess and capture its output."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    if "--producer-ref" not in args and args and not args[0].startswith("-"):
        args = (*args, "--producer-ref", next(iter({r for v in producer_refs().values() for r in v})))
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                          text=True, check=False, cwd=ROOT, env=env)


def test_data_file_validates_as_schema3() -> None:
    manifest = load()
    check(manifest, expected_schema=3)
    assert len(manifest["cells"]) == 8


def test_data_carries_the_verified_identities() -> None:
    manifest = load()
    assert manifest["consumer"]["sha"] == "99283f789f078689404653d5105b597e614160b0"
    grant = manifest["producers"]["grant-authority"]
    assert grant["declared_dependency"] is False
    assert "production_pin" not in grant


def test_digest_is_stable_across_key_order() -> None:
    manifest = load()
    reordered = json.loads(json.dumps(manifest, sort_keys=True))
    shuffled = dict(reversed(list(reordered.items())))
    assert canonical_digest(shuffled) == canonical_digest(manifest)


@pytest.mark.parametrize("role", ["neutral-mechanics", "endpoint-policy", "hardware-eligibility",
                                  "grant-authority"])
def test_changing_a_candidate_sha_changes_the_digest(role: str) -> None:
    manifest = load()
    changed = copy.deepcopy(manifest)
    changed["producers"][role]["candidate"] = "0" * 40
    assert canonical_digest(changed) != canonical_digest(manifest)


def test_changing_consumer_or_pin_changes_the_digest() -> None:
    manifest = load()
    consumer = copy.deepcopy(manifest)
    consumer["consumer"]["sha"] = "0" * 40
    pin = copy.deepcopy(manifest)
    pin["producers"]["endpoint-policy"]["production_pin"] = "0" * 40
    digests = {canonical_digest(m) for m in (manifest, consumer, pin)}
    assert len(digests) == 3


def test_expected_digest_mismatch_is_refused_with_stable_code() -> None:
    with pytest.raises(ManifestError) as info:
        check(load(), expected_digest="0" * 64)
    assert info.value.code == "manifest-digest-mismatch"


def test_expected_digest_match_is_accepted() -> None:
    manifest = load()
    check(manifest, expected_digest=canonical_digest(manifest))


def test_schema2_relabelled_copy_is_refused() -> None:
    manifest = load()
    manifest["schema"] = 2
    with pytest.raises(ManifestError):
        check(manifest)


def test_script_prints_the_canonical_digest() -> None:
    result = run_script(str(DATA), "--allow-unbound")
    assert result.returncode == 0
    assert result.stdout.strip() == canonical_digest(load())
    assert "UNBOUND: digest not compared with a frozen value" in result.stderr


def test_script_without_expected_digest_exits_3_unless_allowed() -> None:
    result = run_script(str(DATA))
    assert result.returncode == 3
    assert result.stdout.strip() == canonical_digest(load())
    assert "UNBOUND: digest not compared with a frozen value" in result.stderr


def test_script_bound_digest_exits_0_without_unbound_notice() -> None:
    result = run_script(str(DATA), "--expected-digest", canonical_digest(load()))
    assert result.returncode == 0
    assert "UNBOUND" not in result.stderr


def test_script_consumer_sha_is_bound() -> None:
    good = run_script(str(DATA), "--allow-unbound", "--consumer-sha", load()["consumer"]["sha"])
    assert good.returncode == 0
    bad = run_script(str(DATA), "--allow-unbound", "--consumer-sha", "0" * 40)
    assert bad.returncode == 1
    assert "manifest-consumer-mismatch" in bad.stderr


@pytest.mark.parametrize("raw", [
    '{"a": NaN}', '{"a": Infinity}', '{"a": 1, "a": 2}',
])
def test_script_refuses_ambiguous_json(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "m.json"
    path.write_text(raw, encoding="utf-8")
    result = run_script(str(path), "--allow-unbound")
    assert result.returncode == 1
    assert "manifest-invalid" in result.stderr


def test_script_lone_surrogate_in_unvalidated_section_is_stable_error(tmp_path: Path) -> None:
    text = DATA.read_text(encoding="utf-8").replace('"seam-positive-modules-collected"',
                                                     '"\\ud800"')
    path = tmp_path / "m.json"
    path.write_text(text, encoding="utf-8")
    result = run_script(str(path), "--allow-unbound")
    assert result.returncode == 1
    assert "manifest-invalid" in result.stderr
    assert "Traceback" not in result.stderr


def test_data_pins_differ_from_candidates_and_core_pin_is_registry_bound() -> None:
    producers = load()["producers"]
    for role, entry in producers.items():
        if role != "grant-authority":
            assert entry["production_pin"] != entry["candidate"]
    assert producers["neutral-mechanics"]["production_pin"] == CORE_PINS["production"]


def test_script_exit_codes_for_digest_mismatch(tmp_path: Path) -> None:
    result = run_script(str(DATA), "--expected-digest", "0" * 64)
    assert result.returncode == 1
    assert "manifest-digest-mismatch" in result.stderr


def test_script_exit_code_for_unknown_schema(tmp_path: Path) -> None:
    bad = load()
    bad["schema"] = 9
    path = tmp_path / "m.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    result = run_script(str(path), "--allow-unbound")
    assert result.returncode == 1
    assert "manifest-schema-unknown" in result.stderr


def test_script_checks_schema_before_reading_v3_fields(tmp_path: Path) -> None:
    path = tmp_path / "unknown-schema.json"
    path.write_text('{"schema": 9}', encoding="utf-8")
    result = run_script(str(path), "--allow-unbound")
    assert result.returncode == 1
    assert "manifest-schema-unknown" in result.stderr
    assert "unreadable manifest" not in result.stderr


@pytest.mark.parametrize("option", ["--expected-digest", "--producer-ref", "--consumer-sha"])
def test_script_rejects_option_as_missing_value(tmp_path: Path, option: str) -> None:
    result = run_script(str(DATA), option, "--allow-unbound")
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_script_exit_code_for_invalid_manifest(tmp_path: Path) -> None:
    bad = load()
    bad["cells"] = bad["cells"][:-1]
    path = tmp_path / "m.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    result = run_script(str(path), "--allow-unbound")
    assert result.returncode == 1
    assert "manifest-invalid" in result.stderr


def test_script_requires_an_external_producer_ref() -> None:
    """Without --producer-ref the registry ref would be compared with itself."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, str(SCRIPT), str(DATA), "--allow-unbound"],
                            capture_output=True, text=True, check=False, cwd=ROOT, env=env)
    assert result.returncode == 1
    assert "--producer-ref is required" in result.stderr


def test_script_refuses_a_producer_ref_that_differs_from_the_registry() -> None:
    result = run_script(str(DATA), "--allow-unbound", "--producer-ref", "0" * 40)
    assert result.returncode == 1


def test_script_usage_error_is_exit_2() -> None:
    assert run_script().returncode == 2
    assert run_script("/nonexistent/manifest.json").returncode == 2
