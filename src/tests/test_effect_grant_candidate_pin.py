"""The effect-grant test group delivers exactly the pinned candidate, as a test-only optional group."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_FILE = ROOT / "requirements" / "compatibility-phylax-effect-grant.txt"
WORKFLOW = ROOT / ".github" / "workflows" / "effect-grant-composition.yml"
GROUP = "effect-grant-test"
URL = "https://github.com/oramasys/phylax"


def _project() -> dict:
    """Return the parsed ``[project]`` table of the repository's ``pyproject.toml``."""
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _candidate() -> str:
    """Return the candidate commit recorded in the compatibility file, which must be a full SHA."""
    pin = CANDIDATE_FILE.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{40}", pin)
    return pin


def test_the_group_pins_exactly_the_candidate_file_commit() -> None:
    """The one declared reference equals the compatibility file's SHA, never a branch or range."""
    group = _project()["optional-dependencies"][GROUP]
    assert group == [f"oramasys-phylax @ git+{URL}@{_candidate()}"]


def test_the_group_is_test_only_and_never_a_base_or_serving_dependency() -> None:
    """A default, dev or grant-serving install never receives the candidate."""
    project = _project()
    extras = project["optional-dependencies"]
    assert not any("phylax" in dep.lower() for dep in project["dependencies"])
    assert not any("phylax" in dep.lower() for dep in extras["dev"])
    assert not any(GROUP in dep for dep in extras["grant-serving"])


def test_perpetua_core_is_one_base_dependency_not_repeated_in_the_group() -> None:
    """The effect tests' perpetua-core import is satisfied by the base install only."""
    project = _project()
    base = [dep for dep in project["dependencies"] if dep.startswith("perpetua-core")]
    assert len(base) == 1
    assert not any("perpetua" in dep.lower() for dep in project["optional-dependencies"][GROUP])


def test_the_candidate_job_installs_through_the_group_not_an_ad_hoc_reference() -> None:
    """CI exercises the declared group and still verifies the installed provenance against the file."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert f"'.[dev,{GROUP}]'" in text
    assert "oramasys-phylax @" not in text
    assert "verify_phylax_pin.py" in text and "compatibility-phylax-effect-grant.txt" in text
