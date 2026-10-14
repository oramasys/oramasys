"""Exact final-set installation contract."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def helper():
    return load_script("final_set_install_plan")


@pytest.fixture
def plan():
    return json.loads((ROOT / "requirements/final-producers-install-plan.v1.json").read_text())


def manifest():
    return json.loads((ROOT / "requirements/compatibility-manifest.v3.json").read_text())


def test_exact_plan_and_emit(helper, plan, capsys):
    assert helper.validate_plan(plan, manifest()) == plan
    requirements = helper.emit_requirements(plan, manifest())
    assert len(requirements) == 4
    assert requirements[0] == "perpetua-core @ git+https://github.com/oramasys/perpetua-core.git@6d75cfe08af95992dddffab13ae3019aa9c41350"
    assert helper.main(["emit", str(ROOT / "requirements/final-producers-install-plan.v1.json"), str(ROOT / "requirements/compatibility-manifest.v3.json")]) == 0
    assert json.loads(capsys.readouterr().out) == requirements


@pytest.mark.parametrize("field,value", [
    ("distribution", "other"), ("module", "orama"), ("url", "https://evil.invalid/core.git"),
    ("commit", "6D75CFE08AF95992DDDFFAB13AE3019AA9C41350"),
    ("commit", "6d75cfe"), ("commit", "a" * 40), ("install_mode", "archive"),
])
def test_wrong_producer_tuple(helper, plan, field, value):
    plan["producers"]["neutral-mechanics"][field] = value
    with pytest.raises(ValueError):
        helper.validate_plan(plan, manifest())


@pytest.mark.parametrize("mutation", ["role", "extra", "consumer", "schema", "duplicate-sha", "cell"])
def test_closed_contract(helper, plan, mutation):
    source = manifest()
    if mutation == "role":
        plan["producers"]["unknown"] = plan["producers"].pop("grant-authority")
    elif mutation == "extra":
        plan["producers"]["grant-authority"]["extra"] = True
    elif mutation == "consumer":
        plan["consumer"]["commit"] = "b" * 40
    elif mutation == "schema":
        plan["schema"] = True
    elif mutation == "duplicate-sha":
        plan["producers"]["grant-authority"]["commit"] = plan["producers"]["neutral-mechanics"]["commit"]
    else:
        source["cells"][-1]["candidate_set"]["grant-authority"] = "a" * 40
    with pytest.raises(ValueError):
        helper.validate_plan(plan, source)


def test_duplicate_json_keys_rejected(helper, tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":1,"schema":1}')
    with pytest.raises(ValueError):
        helper.load_json(path)


def test_wrong_manifest_consumer(helper, plan):
    source = copy.deepcopy(manifest())
    source["consumer"]["repository"] = "unknown/consumer"
    with pytest.raises(ValueError):
        helper.validate_plan(plan, source)
