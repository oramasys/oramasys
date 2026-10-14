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


def test_cli_exit_codes(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """0 on agreement, 1 on a wrong external production registry, 2 on an unreadable input."""
    assert tool.main(["x", str(MANIFEST)]) == 0
    wrong = tmp_path / "registry.json"
    wrong.write_text(json.dumps({"qualification_profile": {"core_pin": "1" * 40}}))
    assert tool.main(["x", str(MANIFEST), "--production-registry", str(wrong)]) == 1
    out = json.loads(capsys.readouterr().out.split("\n}\n")[-2] + "\n}")
    assert out["results"]["production"]["anchor"] == "external-registry"
    assert tool.main(["x", str(tmp_path / "absent.json")]) == 2
