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
REPOSITORY = "diazMelgarejo/orama-system"
CONSUMER = "a" * 40


def _body() -> str:
    return tool.approval_body(REPOSITORY, 45, CONSUMER, {"schema": 3}, {"packet_version": 1}, ALLOWLIST)


def _comment(**changes: object) -> dict[str, object]:
    comment: dict[str, object] = {"id": 17, "html_url": f"https://github.com/{REPOSITORY}/issues/45#issuecomment-17",
                                  "user": {"login": "diazMelgarejo"}, "body": _body(),
                                  "created_at": "2026-10-15T00:00:00Z", "updated_at": "2026-10-15T00:00:00Z"}
    comment.update(changes)
    return comment


def test_exact_unedited_allowlisted_comment_is_accepted() -> None:
    tool.verify_comment(_comment(), _comment()["html_url"], _body(), tool.approvers(ALLOWLIST))


@pytest.mark.parametrize("changes", [
    {"body": "different"}, {"id": 18}, {"html_url": "https://github.com/other/repo/issues/45#issuecomment-17"},
    {"user": {"login": "other"}}, {"updated_at": "2026-10-15T00:00:01Z"},
])
def test_comment_tampering_is_refused(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        tool.verify_comment(_comment(**changes), "https://github.com/diazMelgarejo/orama-system/issues/45#issuecomment-17",
                            _body(), tool.approvers(ALLOWLIST))


@pytest.mark.parametrize("reference", [
    "operator-decision:synthetic", "https://github.com/a/b/pull/45#issuecomment-17",
    "https://github.com/a/b/issues/0#issuecomment-17",
])
def test_non_comment_references_are_refused(reference: str) -> None:
    with pytest.raises(ValueError):
        tool.parse_reference(reference)


def test_allowlist_digest_binds_the_exact_allowlist_bytes_semantics(tmp_path: Path) -> None:
    changed = tmp_path / "allowlist.json"
    changed.write_text(json.dumps({"schema": 1, "accounts": ["someone-else"]}))
    assert _body() != tool.approval_body(REPOSITORY, 45, CONSUMER, {"schema": 3}, {"packet_version": 1}, changed)


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
