"""Qualification approvals are exact, allowlisted GitHub-account evidence."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("qualification_approval", ROOT / "scripts/qualification_approval.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["qualification_approval"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()
ALLOWLIST = ROOT / "requirements/qualification-approvers.v1.json"
REPOSITORY = "oramasys/oramasys"
PULL_REQUEST = 45
COMMENT_ID = 6179741042
PULL_COMMENT_REFERENCE = (
    "https://github.com/oramasys/oramasys/pull/45#issuecomment-6179741042"
)
CONSUMER = "a" * 40
HARNESS = "b" * 40


def _body() -> str:
    return tool.approval_body(
        REPOSITORY, PULL_REQUEST, CONSUMER, HARNESS, {"schema": 3}, {"packet_version": 1}, ALLOWLIST
    )


def _comment(**changes: object) -> dict[str, object]:
    comment: dict[str, object] = {"id": COMMENT_ID, "html_url": PULL_COMMENT_REFERENCE,
                                  "user": {"login": "diazMelgarejo"}, "body": _body(),
                                  "created_at": "2026-10-15T00:00:00Z", "updated_at": "2026-10-15T00:00:00Z"}
    comment.update(changes)
    return comment


def test_exact_unedited_allowlisted_comment_is_accepted() -> None:
    tool.verify_comment(_comment(), _comment()["html_url"], _body(), tool.approvers(ALLOWLIST))


def test_issue_comment_reference_is_accepted() -> None:
    issue_reference = (
        "https://github.com/oramasys/oramasys/issues/45#issuecomment-6179741042"
    )
    assert tool.parse_reference(issue_reference) == (REPOSITORY, PULL_REQUEST, COMMENT_ID)


@pytest.mark.parametrize("changes", [
    {"body": "different"}, {"id": 18}, {"html_url": "https://github.com/other/repo/issues/45#issuecomment-17"},
    {"user": {"login": "other"}}, {"updated_at": "2026-10-15T00:00:01Z"},
])
def test_comment_tampering_is_refused(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        tool.verify_comment(_comment(**changes), PULL_COMMENT_REFERENCE,
                            _body(), tool.approvers(ALLOWLIST))


@pytest.mark.parametrize("reference", [
    "operator-decision:synthetic", "https://github.com/a/b/pulls/45#issuecomment-17",
    "https://github.com/a/b/issues/0#issuecomment-17",
])
def test_non_comment_references_are_refused(reference: str) -> None:
    with pytest.raises(ValueError):
        tool.parse_reference(reference)


def test_allowlist_digest_binds_the_exact_allowlist_bytes_semantics(tmp_path: Path) -> None:
    changed = tmp_path / "allowlist.json"
    changed.write_text(json.dumps({"schema": 1, "accounts": ["someone-else"]}))
    assert _body() != tool.approval_body(REPOSITORY, 45, CONSUMER, HARNESS, {"schema": 3}, {"packet_version": 1}, changed)


def test_harness_commit_binds_the_approval_body() -> None:
    assert _body() != tool.approval_body(
        REPOSITORY, PULL_REQUEST, CONSUMER, "c" * 40,
        {"schema": 3}, {"packet_version": 1}, ALLOWLIST,
    )


def test_fresh_marker_requires_current_matching_account(tmp_path: Path) -> None:
    config = tmp_path / "isolated"
    config.mkdir()
    marker = tool.marker_path(config)
    marker.write_text(json.dumps({"schema": 1, "account": "diazMelgarejo", "issued_at": __import__("time").time()}))
    tool.require_fresh_marker(config, "diazMelgarejo")
    with pytest.raises(ValueError):
        tool.require_fresh_marker(config, "someone-else")


def test_zero_identifiers_are_refused() -> None:
    with pytest.raises(ValueError):
        tool.parse_reference("https://github.com/a/b/issues/0#issuecomment-0")


def test_failed_post_consumes_the_marker_and_says_to_reauthenticate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The fresh-auth marker is a one-time capability: it is spent before use."""
    import subprocess
    import time

    config = tmp_path / "isolated"
    config.mkdir()
    tool.marker_path(config).write_text(
        json.dumps({"schema": 1, "account": "diazMelgarejo", "issued_at": time.time()})
    )
    manifest, coverage = tmp_path / "m.json", tmp_path / "c.json"
    manifest.write_text("{}")
    coverage.write_text("{}")
    monkeypatch.setattr(tool, "authenticated_login", lambda _dir: "diazMelgarejo")
    monkeypatch.setattr(tool, "isolated_environment", lambda _dir: {})

    def failing_post(*_args: object, **_kwargs: object) -> None:
        raise subprocess.CalledProcessError(1, "gh")

    monkeypatch.setattr(tool.subprocess, "run", failing_post)
    monkeypatch.setattr(sys, "argv", [
        "qualification_approval.py", "approve", str(manifest), str(coverage),
        "--consumer", CONSUMER, "--harness", HARNESS, "--repository", REPOSITORY, "--pull-request", "45",
        "--record", str(tmp_path / "record.json"), "--config-dir", str(config),
    ])
    assert tool.main() == 1
    assert not tool.marker_path(config).exists()
    assert "re-authenticate" in capsys.readouterr().err
