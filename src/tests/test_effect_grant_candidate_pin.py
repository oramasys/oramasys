"""The effect-grant test lane delivers exactly the pinned candidate, outside every package extra."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_FILE = ROOT / "requirements" / "compatibility-phylax-effect-grant.txt"
LANE_FILE = ROOT / "requirements" / "effect-grant-test.txt"
WORKFLOW = ROOT / ".github" / "workflows" / "effect-grant-composition.yml"
URL = "https://github.com/oramasys/phylax.git"


def _project() -> dict:
    """Return the parsed ``[project]`` table of the repository's ``pyproject.toml``."""
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _candidate() -> str:
    """Return the candidate commit recorded in the compatibility file, which must be a full SHA."""
    pin = CANDIDATE_FILE.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{40}", pin)
    return pin


def test_the_lane_file_pins_exactly_the_candidate_file_commit() -> None:
    """The one declared reference equals the compatibility file's SHA, never a branch or range."""
    lines = [line for line in LANE_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines == [f"oramasys-phylax @ git+{URL}@{_candidate()}"]


def test_pyproject_keeps_exactly_one_phylax_reference_the_grant_serving_extra() -> None:
    """The candidate never enters pyproject; the pin registry still sees the one serving pin."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert len(re.findall(r"oramasys-phylax", text)) == 1
    project = _project()
    assert not any("phylax" in dep.lower() for dep in project["dependencies"])
    extras = project["optional-dependencies"]
    assert not any("phylax" in dep.lower() for dep in extras["dev"])
    assert [name for name, deps in extras.items() if any("phylax" in d for d in deps)] == [
        "grant-serving"
    ]
    assert _candidate() not in text


def test_perpetua_core_is_one_base_dependency_not_repeated_in_the_lane() -> None:
    """The effect tests' perpetua-core import is satisfied by the base install only."""
    base = [dep for dep in _project()["dependencies"] if dep.startswith("perpetua-core")]
    assert len(base) == 1
    assert "perpetua" not in LANE_FILE.read_text(encoding="utf-8")


def test_the_candidate_job_installs_through_the_lane_file_not_an_ad_hoc_reference() -> None:
    """CI exercises the declared lane and still verifies the installed provenance against the file."""
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "-r requirements/effect-grant-test.txt" in text
    assert "oramasys-phylax @" not in text
    assert "verify_phylax_pin.py" in text and "compatibility-phylax-effect-grant.txt" in text
