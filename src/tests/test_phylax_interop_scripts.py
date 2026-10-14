"""The pin verifier and the sanitized receipt builder used by the Ubuntu interop job."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
PIN = (ROOT / "requirements" / "compatibility-phylax-verify-only.txt").read_text().strip()
URL = "https://github.com/oramasys/phylax.git"


def load(name: str) -> ModuleType:
    """Load one script from scripts/ by file name."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pin_verifier = load("verify_phylax_pin")
receipt_builder = load("phylax_interop_receipt")


def direct_url(url: str = URL, commit: str = PIN, vcs: str = "git") -> str:
    """Return a pip ``direct_url.json`` document."""
    return json.dumps({"url": url, "vcs_info": {"vcs": vcs, "commit_id": commit}})


def test_the_pin_file_holds_one_full_sha() -> None:
    """The only place the Phylax pin lives is one immutable commit."""
    assert len(PIN) == 40 and PIN == PIN.lower() and all(c in "0123456789abcdef" for c in PIN)


def test_a_matching_direct_url_is_bound() -> None:
    """Repository and exact commit equal the pin; a trailing .git or slash is tolerated."""
    assert pin_verifier.check_direct_url(direct_url(), expected_url=URL, expected_commit=PIN) == []
    assert pin_verifier.check_direct_url(
        direct_url(url="https://github.com/oramasys/phylax/"), expected_url=URL, expected_commit=PIN
    ) == []


@pytest.mark.parametrize("document, code", [
    (direct_url(commit="0" * 40), "commit.mismatch"),
    (direct_url(url="https://github.com/someone/phylax.git"), "url.mismatch"),
    (direct_url(vcs="hg"), "source.not_git"),
    ("not json", "direct_url.malformed"),
    ("[]", "direct_url.malformed"),
    (None, "direct_url.missing"),
    ("", "direct_url.missing"),
])
def test_any_other_source_is_refused(document: str | None, code: str) -> None:
    """A different commit, repository, VCS or an unreadable record never counts as bound."""
    assert code in pin_verifier.check_direct_url(document, expected_url=URL, expected_commit=PIN)


def test_an_invalid_pin_is_refused() -> None:
    """A branch name or short SHA is not an immutable pin."""
    for bad in ("main", PIN[:7], PIN.upper()):
        assert pin_verifier.check_direct_url(direct_url(), expected_url=URL, expected_commit=bad) == [
            "pin.invalid"
        ]


def test_only_an_installed_location_satisfies_the_import_proof() -> None:
    """A workspace path cannot stand in for the installed package."""
    assert pin_verifier.check_location("/usr/lib/python3.12/site-packages/phylax/__init__.py") == []
    assert pin_verifier.check_location("/runner/work/oramasys/src/phylax/__init__.py") == [
        "location.not_installed"
    ]
    assert pin_verifier.check_location(None) == ["location.unknown"]


CLASS = "src.tests.interop.test_verify_only_serving"


def _junit(names: list[str], *, classname: str = CLASS, extra: str = "") -> str:
    """Build a JUnit document with one passing testcase per name."""
    cases = "".join(f'<testcase classname="{classname}" name="{n}"/>' for n in names)
    return f"<testsuites><testsuite>{cases}{extra}</testsuite></testsuites>"


NAMES = list(receipt_builder.SCENARIOS)
JUNIT = _junit(NAMES)


def build(junit: str = JUNIT, commit: str = PIN) -> dict:
    """Build a receipt with a fixed clock."""
    return receipt_builder.build_receipt(
        junit, expected_pin=PIN, observed_url=URL, observed_commit=commit,
        now=datetime(2026, 10, 15, 1, 2, 3, tzinfo=UTC),
    )


def test_the_receipt_is_minimal_and_uses_only_fixed_public_labels() -> None:
    """Only the fixed fields appear, and scenario labels come from the allowlist."""
    receipt = build()
    assert set(receipt) == {
        "outcome", "expected_pin", "observed_url", "observed_commit", "pin_matches",
        "counts", "scenarios", "generated_at",
    }
    assert receipt["outcome"] == "pass" and receipt["pin_matches"] is True
    assert {s["scenario"] for s in receipt["scenarios"]} == set(receipt_builder.SCENARIOS.values())
    assert receipt["counts"] == {
        "expected": 5, "recognized": 5, "unrecognized": 0, "failed": 0, "skipped": 0,
    }


def test_untrusted_junit_text_never_reaches_the_receipt() -> None:
    """Path-like class names, parameter values and captured output are not copied."""
    hostile = _junit(
        [*NAMES, "tenant=alpha", "test_case[secret-token]"],
        extra=(
            '<testcase classname="/private/work/secret-token" name="tenant=alpha">'
            "<system-out>PHYLAX_STATE_DIR=/home/runner/x TOKEN=abc</system-out></testcase>"
        ),
    )
    receipt = build(hostile)
    text = json.dumps(receipt)
    for fragment in (
        "tenant", "alpha", "secret", "token", "/private", "/home", "PHYLAX_STATE_DIR", "abc",
        "test_case",
    ):
        assert fragment not in text.replace("expected_pin", "").replace("observed", "")
    assert receipt["counts"]["unrecognized"] == 3
    assert receipt["outcome"] == "fail"  # unknown identities fail the receipt without being quoted


def test_a_look_alike_class_name_is_not_trusted() -> None:
    """A foreign module that reuses a known test name is unrecognized."""
    receipt = build(_junit(NAMES, classname="some.other.module"))
    assert receipt["counts"]["recognized"] == 0 and receipt["outcome"] == "fail"


def test_a_failure_a_skip_a_missing_or_a_repeated_scenario_is_not_a_pass() -> None:
    """Every expected scenario must run exactly once, pass, and nothing may be skipped."""
    first = NAMES[0]
    failed = JUNIT.replace(f'name="{first}"/>', f'name="{first}"><failure/></testcase>')
    assert build(failed)["outcome"] == "fail"
    skipped = JUNIT.replace(f'name="{first}"/>', f'name="{first}"><skipped/></testcase>')
    assert build(skipped)["outcome"] == "fail"
    assert build(_junit(NAMES[:-1]))["outcome"] == "fail"
    assert build(_junit([*NAMES, first]))["outcome"] == "fail"
    assert build("<testsuites><testsuite/></testsuites>")["outcome"] == "fail"


def test_a_commit_that_is_not_the_pin_is_recorded_and_fails_the_binding() -> None:
    """The receipt records both values and states they differ."""
    other = "1" * 40
    receipt = build(commit=other)
    assert receipt["pin_matches"] is False
    assert receipt["observed_commit"] == other and receipt["expected_pin"] == PIN


def test_a_malformed_pin_or_report_raises() -> None:
    """The builder refuses rather than guess."""
    with pytest.raises(ValueError):
        receipt_builder.build_receipt(
            JUNIT, expected_pin="main", observed_url=URL, observed_commit=PIN
        )


def test_an_observed_url_that_is_not_a_plain_repository_url_is_refused() -> None:
    """Paths, credentials, queries and spaces cannot ride in through the URL field."""
    for bad in ("/home/runner/work", "https://user:pw@github.com/x/y", "https://h/x?token=1",
                "https://github.com/a b", "file:///etc/passwd", ""):
        with pytest.raises(ValueError):
            receipt_builder.build_receipt(
                JUNIT, expected_pin=PIN, observed_url=bad, observed_commit=PIN
            )


def test_every_allowlisted_name_is_a_real_interop_test() -> None:
    """The allowlist cannot drift from the tests it labels."""
    import ast

    tree = ast.parse((ROOT / "src/tests/interop/test_verify_only_serving.py").read_text())
    defined = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
    }
    assert defined == set(receipt_builder.SCENARIOS)


WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = __import__("re").compile(r"[0-9a-f]{40}")


def _without_action_lines(text: str) -> str:
    """Drop ``uses:`` lines, whose full SHAs are action pins checked elsewhere."""
    return "\n".join(line for line in text.splitlines() if "uses:" not in line)


def test_the_interop_workflow_holds_no_second_phylax_pin() -> None:
    """The Phylax commit exists only in the requirements file; the workflow reads it."""
    text = (WORKFLOWS / "grant-composition-interop.yml").read_text(encoding="utf-8")
    assert "requirements/compatibility-phylax-verify-only.txt" in text
    assert FULL_SHA.findall(_without_action_lines(text)) == []


@pytest.mark.parametrize("name", ["grant-composition-interop.yml", "manifest-schema3.yml"])
def test_the_new_workflows_are_ubuntu_least_privilege_and_secret_free(name: str) -> None:
    """GitHub-hosted Ubuntu, py3.11/3.12, read-only token, no secrets, no privileged trigger."""
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    assert "runs-on: ubuntu-latest" in text
    assert 'python-version: ["3.11", "3.12"]' in text
    assert "contents: read" in text
    assert "persist-credentials: false" in text
    for forbidden in ("secrets.", "pull_request_target", "workflow_run", "self-hosted"):
        assert forbidden not in text


def test_the_manifest_workflow_ref_is_a_constant_equal_to_the_ci_registry_ref() -> None:
    """The producer ref is a workflow constant that cannot drift from the ci.yml checkout."""
    from tests.test_compatibility_pins import producer_refs

    text = (WORKFLOWS / "manifest-schema3.yml").read_text(encoding="utf-8")
    constants = __import__("re").findall(r"PRODUCER_REGISTRY_REF:\s*([0-9a-f]{40})", text)
    assert len(constants) == 1
    assert set(producer_refs()["ci.yml"]) == {constants[0]}
    assert '--producer-ref "$PRODUCER_REGISTRY_REF"' in text
    assert "docs-candidate" not in text, "no decorative checkout: nothing reads it"


def test_the_grant_serving_extra_delivers_exactly_the_pinned_phylax_and_only_as_an_extra() -> None:
    """Delivery is opt-in and bound to the one pin; a default install stays Phylax-free."""
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extra = project["optional-dependencies"]["grant-serving"]
    assert extra == [f"oramasys-phylax @ git+{URL}@{PIN}"]
    assert not any("phylax" in dep.lower() for dep in project["dependencies"])
    assert not any("phylax" in dep.lower() for dep in project["optional-dependencies"]["dev"])


def test_the_interop_job_installs_through_the_extra_not_a_second_command() -> None:
    """CI must exercise the delivery surface itself."""
    text = (WORKFLOWS / "grant-composition-interop.yml").read_text(encoding="utf-8")
    assert "'.[dev,grant-serving]'" in text
    assert "oramasys-phylax @" not in text


def test_workflows_preserve_validator_failures_and_pass_receipt_values_via_env() -> None:
    """CI must not mask manifest failures or splice observed values into shell source."""
    manifest = (WORKFLOWS / "manifest-schema3.yml").read_text(encoding="utf-8")
    assert "set -o pipefail" in manifest

    interop = (WORKFLOWS / "grant-composition-interop.yml").read_text(encoding="utf-8")
    assert "OBSERVED_URL: ${{ steps.pin.outputs.url }}" in interop
    assert "OBSERVED_COMMIT: ${{ steps.pin.outputs.commit }}" in interop
    assert '"$OBSERVED_URL" "$OBSERVED_COMMIT"' in interop
    assert '"${{ steps.pin.outputs.url }}"' not in interop
    assert '"${{ steps.pin.outputs.commit }}"' not in interop


def test_a_suffix_spoofed_class_name_is_not_trusted() -> None:
    """Only the canonical module path labels a testcase, never a matching final component."""
    for spoof in (
        "untrusted.test_verify_only_serving",
        "tests.interop.test_verify_only_serving",
        "src.tests.interop.test_verify_only_serving.extra",
        "src.tests.interop.test_verify_only_serving ",
        "test_verify_only_serving",
    ):
        receipt = build(_junit(NAMES, classname=spoof))
        assert receipt["counts"]["recognized"] == 0, spoof
        assert receipt["outcome"] == "fail"
    assert build(_junit(NAMES, classname=receipt_builder.CANONICAL_CLASSNAME))["outcome"] == "pass"


def test_the_pin_report_returns_the_observed_values_not_the_expected_arguments() -> None:
    """The line the workflow forwards to the receipt carries what direct_url.json recorded."""
    observed_url = "https://github.com/oramasys/phylax"  # no .git: accepted, but different text
    document = json.dumps({"url": observed_url, "vcs_info": {"vcs": "git", "commit_id": PIN}})
    code, line = pin_verifier.report(
        document, expected_url=URL, expected_commit=PIN,
        module_file="/opt/lib/python3.12/site-packages/phylax/__init__.py",
    )
    assert code == 0
    assert line == f"OK {observed_url} {PIN}"
    assert URL not in line  # the expected argument must not be echoed back as an observation


def test_the_pin_report_refuses_and_never_reports_observed_values_on_a_mismatch() -> None:
    """A mismatch exits non-zero with problem codes only."""
    document = json.dumps({"url": URL, "vcs_info": {"vcs": "git", "commit_id": "2" * 40}})
    code, line = pin_verifier.report(
        document, expected_url=URL, expected_commit=PIN,
        module_file="/opt/lib/python3.12/site-packages/phylax/__init__.py",
    )
    assert code == 1 and line == "commit.mismatch"
    assert "2" * 40 not in line


def test_the_new_jobs_have_specific_names_so_a_required_check_context_is_unambiguous() -> None:
    """A required context is the job name plus matrix; generic names would collide later."""
    import re

    expected = {
        "grant-composition-interop.yml": "grant-composition-interop",
        "manifest-schema3.yml": "manifest-schema3",
    }
    for workflow, job in expected.items():
        text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
        jobs = re.search(r"^jobs:\n((?:  [A-Za-z0-9_-]+:\n)(?:.*\n)*)", text, re.M)
        assert jobs is not None
        names = re.findall(r"^  ([A-Za-z0-9_-]+):\n", jobs.group(1), re.M)
        assert names[0] == job, f"{workflow}: first job is {names[0]!r}, expected {job!r}"
