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


JUNIT = """<testsuites><testsuite>
<testcase classname="src.tests.interop.test_verify_only_serving" name="test_ready"/>
<testcase classname="src.tests.interop.test_verify_only_serving" name="test_revoked[a/b]">
<system-out>PHYLAX_STATE_DIR=/home/runner/secret TOKEN=abc</system-out></testcase>
</testsuite></testsuites>"""


def build(junit: str = JUNIT, commit: str = PIN) -> dict:
    """Build a receipt with a fixed clock."""
    return receipt_builder.build_receipt(
        junit, expected_pin=PIN, observed_url=URL, observed_commit=commit,
        now=datetime(2026, 10, 15, 1, 2, 3, tzinfo=UTC),
    )


def test_the_receipt_is_minimal_and_carries_no_run_output() -> None:
    """Only the fixed fields appear; captured output, paths and values never do."""
    receipt = build()
    assert set(receipt) == {
        "outcome", "expected_pin", "observed_url", "observed_commit", "pin_matches",
        "counts", "tests", "generated_at",
    }
    text = json.dumps(receipt)
    for forbidden in ("PHYLAX_STATE_DIR", "TOKEN", "/home/runner", "secret", "abc"):
        assert forbidden not in text
    assert receipt["outcome"] == "pass" and receipt["pin_matches"] is True
    assert receipt["counts"] == {"total": 2, "failed": 0, "skipped": 0}
    assert all("/" not in t["id"] for t in receipt["tests"])


def test_a_failure_a_skip_or_an_empty_run_is_not_a_pass() -> None:
    """Skips consume the allowance and an empty run proves nothing."""
    failed = JUNIT.replace('name="test_ready"/>', 'name="test_ready"><failure/></testcase>')
    assert build(failed)["outcome"] == "fail"
    skipped = JUNIT.replace('name="test_ready"/>', 'name="test_ready"><skipped/></testcase>')
    assert build(skipped)["outcome"] == "fail"
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


def test_the_manifest_workflow_derives_the_producer_ref_from_its_own_checkout() -> None:
    """The ref passed to the digest script is the checked-out registry HEAD, not the manifest."""
    text = (WORKFLOWS / "manifest-schema3.yml").read_text(encoding="utf-8")
    assert 'REF="$(git -C docs-candidate rev-parse HEAD)"' in text
    assert '--producer-ref "$REF"' in text
