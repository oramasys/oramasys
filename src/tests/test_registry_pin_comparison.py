"""The declared registry_profiles are compared with the pins the reviewed registries declare."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "requirements" / "compatibility-manifest.v3.json"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "compare_registry_pins", ROOT / "scripts" / "compare_registry_pins.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["compare_registry_pins"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()


def _declared() -> dict[str, str]:
    return json.loads(MANIFEST.read_text())["registry_profiles"]


def _registries(**override: str | None) -> dict[str, object]:
    fixtures = ROOT / "src" / "tests" / "fixtures"
    loaded = {name: json.loads((fixtures / file).read_text())
              for name, file in tool.PROFILE_FIXTURES.items()}
    for name, pin in override.items():
        loaded[name] = {"qualification_profile": {} if pin is None else {"core_pin": pin}}
    return loaded


def test_declared_pins_agree_with_every_fixture_snapshot() -> None:
    """The committed manifest and the digest-pinned fixture snapshots name the same pins."""
    verdict = tool.compare(_declared(), _registries(), frozenset())
    assert verdict["problems"] == []
    assert {r["anchor"] for r in verdict["results"].values()} == {"fixture-snapshot"}


def test_an_external_production_registry_is_labelled_external_and_only_for_production() -> None:
    """A fixture comparison is never presented as an external anchor."""
    verdict = tool.compare(_declared(), _registries(), frozenset({"production"}))
    anchors = {name: r["anchor"] for name, r in verdict["results"].items()}
    assert anchors == {"production": "external-registry", "policy-r3": "fixture-snapshot",
                       "core-r3": "fixture-snapshot"}


def test_a_changed_declared_pin_is_a_mismatch() -> None:
    """A manifest that vouches for a different pin than the registry is refused."""
    declared = _declared()
    declared["core-r3"] = "0" * 40
    verdict = tool.compare(declared, _registries(), frozenset())
    assert verdict["problems"] == ["core-r3: declared pin differs from the registry pin"]


def test_a_missing_registry_pin_is_a_problem_not_a_pass() -> None:
    """An absent pin cannot be read as agreement."""
    verdict = tool.compare(_declared(), _registries(**{"policy-r3": None}), frozenset())
    assert verdict["problems"] == ["policy-r3: registry pin missing"]
    assert tool.registry_core_pin("not a mapping") is None


PINNED_BYTES = ROOT / "src" / "tests" / "fixtures" / "graph-ownership-registry.json"


def _run(args: list[str], capsys) -> tuple[int, dict | None, str]:  # type: ignore[no-untyped-def]
    code = tool.main(["x", *args])
    captured = capsys.readouterr()
    try:
        return code, json.loads(captured.out), captured.err
    except ValueError:
        return code, None, captured.err


def test_the_pinned_digest_equals_the_digest_of_the_reviewed_production_snapshot() -> None:
    """The tool's constant is the reviewed bytes' digest, not a value taken from an input."""
    import hashlib

    assert hashlib.sha256(PINNED_BYTES.read_bytes()).hexdigest() == (
        tool.PINNED_PRODUCTION_REGISTRY_SHA256)


def test_the_reviewed_bytes_are_accepted_as_the_external_anchor(capsys) -> None:  # type: ignore[no-untyped-def]
    """Exact reviewed bytes are external; the verdict records repository, ref, path and digest."""
    code, out, _ = _run([str(MANIFEST), "--production-registry", str(PINNED_BYTES)], capsys)
    assert code == 0 and out is not None
    assert out["results"]["production"]["anchor"] == "external-registry"
    assert out["external_anchor"]["ref"] == "65ec365293c6a892cd4f978e656cfb61c0d04b9a"
    assert out["external_anchor"]["sha256"] == tool.PINNED_PRODUCTION_REGISTRY_SHA256


def test_changed_bytes_repeating_the_same_pin_are_refused(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """An invented 'external' file with the right core_pin but other content is not an anchor."""
    forged = json.loads(PINNED_BYTES.read_text())
    forged["note"] = "invented"
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(forged))
    code, out, _ = _run([str(MANIFEST), "--production-registry", str(path)], capsys)
    assert code == 1 and out is not None
    assert "differ from the pinned reviewed bytes" in out["problems"][0]


def test_a_flag_with_no_value_or_repeated_is_a_usage_error_never_a_silent_downgrade(
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    """A trailing --production-registry must not fall back to the fixture anchor."""
    assert _run([str(MANIFEST), "--production-registry"], capsys)[0] == 2
    assert _run([str(MANIFEST), "--production-registry", "--fixtures-dir", "x"], capsys)[0] == 2
    assert _run([str(MANIFEST), "--production-registry", str(PINNED_BYTES),
                 "--production-registry", str(PINNED_BYTES)], capsys)[0] == 2


def test_duplicate_keys_and_non_finite_numbers_are_refused_in_every_input(
    tmp_path: Path, capsys,  # type: ignore[no-untyped-def]
) -> None:
    """Unanchored inputs are parsed strictly so an ambiguous document cannot pass."""
    duplicate = tmp_path / "dup.json"
    duplicate.write_text('{"registry_profiles": {}, "registry_profiles": {}}')
    assert _run([str(duplicate)], capsys)[0] == 2
    nan = tmp_path / "nan.json"
    nan.write_text('{"registry_profiles": {}, "x": NaN}')
    assert _run([str(nan)], capsys)[0] == 2
    assert _run([str(tmp_path / "absent.json")], capsys)[0] == 2


def test_the_default_run_is_fixture_anchored_and_says_it_is_not_a_structural_audit(
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    """Without an external file nothing is labelled external."""
    code, out, _ = _run([str(MANIFEST)], capsys)
    assert code == 0 and out is not None
    assert {r["anchor"] for r in out["results"].values()} == {"fixture-snapshot"}
    assert "not a structural registry audit" in out["scope"]
