"""The operator script is read-only, fails closed and never sets the serving switch."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "operator_serving_checks.sh"
NAMES = ["SERVING_UID", "SEED_FILE", "ISSUER_DB", "PUBLIC_STATE", "INSTALL_PLAN", "CONSUMER_WHEEL", "CONSUMER_PROVENANCE", "PHYLAX_PIN_FILE", "ORAMASYS_CHECKOUT", "PYTHON"]


def run(env_extra):
    """Run the script with a clean environment plus the given variables."""
    env = {"PATH": os.environ["PATH"], **env_extra}
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False)


def test_syntax_is_valid() -> None:
    """The script parses."""
    assert subprocess.run(["bash", "-n", str(SCRIPT)], check=False).returncode == 0


def test_missing_inputs_fail_closed() -> None:
    """No input is guessed: every missing variable is named and the result is not-qualified."""
    done = run({})
    assert done.returncode == 2 and "NOT-QUALIFIED" in done.stdout
    assert all(name in done.stderr for name in NAMES)


def test_refuses_when_the_switch_is_set() -> None:
    """A set switch aborts qualification."""
    done = run({**dict.fromkeys(NAMES, "x"), "ORAMA_GRANT_SERVING": "1"})
    assert done.returncode == 2 and "must stay unset" in done.stdout


def test_script_never_sets_the_switch() -> None:
    """The text contains no assignment or export of the switch."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "export ORAMA_GRANT_SERVING" not in text and "ORAMA_GRANT_SERVING=" not in text


def test_failing_checks_yield_not_qualified(tmp_path) -> None:
    """Pointing at a checkout with failing checks prints evidence and exits non-zero."""
    (tmp_path / "scripts").mkdir()
    for name in ("qualify_serving_identity", "verify_installed_identity", "verify_phylax_pin"):
        (tmp_path / "scripts" / f"{name}.py").write_text("import sys; sys.exit(1)\n", encoding="utf-8")
    env = dict.fromkeys(NAMES, "x") | {"ORAMASYS_CHECKOUT": str(tmp_path), "PYTHON": "python3"}
    done = run(env)
    assert done.returncode == 1 and done.stdout.count("sha256=") == 3 and "NOT-QUALIFIED" in done.stdout


def test_relative_inputs_are_resolved_and_paths_are_recorded(tmp_path) -> None:
    """Relative inputs survive the scratch cd, and the evidence lists the resolved paths."""
    (tmp_path / "scripts").mkdir()
    for name in ("qualify_serving_identity", "verify_installed_identity", "verify_phylax_pin"):
        (tmp_path / "scripts" / f"{name}.py").write_text("import sys; sys.exit(0)\n", encoding="utf-8")
    (tmp_path / "plan.json").write_text("{}", encoding="utf-8")
    env = dict.fromkeys(NAMES, "x") | {"ORAMASYS_CHECKOUT": ".", "INSTALL_PLAN": "plan.json", "PYTHON": "python3"}
    done = subprocess.run(["bash", str(SCRIPT)], env={"PATH": os.environ["PATH"], **env}, cwd=tmp_path,
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout
    assert f"INSTALL_PLAN={tmp_path.resolve()}/plan.json" in done.stdout
    assert f"ORAMASYS_CHECKOUT={tmp_path.resolve()}" in done.stdout


def test_runbook_preserves_the_script_exit_status() -> None:
    """The documented pipeline enables pipefail so tee cannot mask a failure."""
    runbook = (SCRIPT.parents[1] / "docs" / "serving-activation-runbook.md").read_text(encoding="utf-8")
    assert "set -o pipefail" in runbook


def test_relative_interpreter_path_is_resolved_but_bare_names_stay_on_path(tmp_path) -> None:
    """PYTHON=./bin/py runs from the invoking directory; PYTHON=python3 is looked up on PATH."""
    (tmp_path / "scripts").mkdir()
    for name in ("qualify_serving_identity", "verify_installed_identity", "verify_phylax_pin"):
        (tmp_path / "scripts" / f"{name}.py").write_text("import sys; sys.exit(0)\n", encoding="utf-8")
    (tmp_path / "bin").mkdir()
    py = tmp_path / "bin" / "py"
    py.write_text('#!/bin/sh\nexec python3 "$@"\n', encoding="utf-8")
    py.chmod(0o755)
    for interpreter, expect in (("bin/py", f"PYTHON={tmp_path.resolve()}/bin/py"), ("python3", "PYTHON=python3")):
        env = dict.fromkeys(NAMES, "x") | {"ORAMASYS_CHECKOUT": ".", "PYTHON": interpreter}
        done = subprocess.run(["bash", str(SCRIPT)], env={"PATH": os.environ["PATH"], **env}, cwd=tmp_path,
                              capture_output=True, text=True, check=False)
        assert done.returncode == 0, done.stdout
        assert expect in done.stdout
