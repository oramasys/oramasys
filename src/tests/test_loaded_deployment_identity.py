"""Tests for the opt-in, return-time profile projection."""

import dataclasses
import json
from pathlib import Path
from typing import Any, IO

import pytest

from orama.deploy.identity import load_with_identity


def test_capture_uses_one_read_and_freezes_safe_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A captured projection remains historical after inputs and result mutate."""
    path = tmp_path / "secret-path.yml"
    path.write_text("version: 1\nnodes:\n  - id: secret-node\n    os: linux\n    role: primary-server\n    endpoint: secret-host:1234\n    state_root: /secret-path\n")
    monkeypatch.setattr("orama.deploy.profile.running_os", lambda: "linux")
    original = Path.open
    reads = []

    def counted(self: Path, *args: Any, **kwargs: Any) -> IO[Any]:
        """Count reads and mutate the caller's environment during the read."""
        if self == path:
            reads.append(self)
            env["ORAMA_NODE_ROLE"] = "off"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted)
    env = {"ORAMA_SERVING_PROFILE": str(path), "ORAMA_NODE_ID": "secret-node", "ORAMA_NODE_ROLE": "client"}
    result = load_with_identity(env)
    env["ORAMA_NODE_ROLE"] = "off"
    result.effective.role = "off"
    assert len(reads) == 1
    assert result.projection.role == "client"
    assert result.projection.role_override == "downgraded"
    assert set(dataclasses.asdict(result.projection)) == {
        "schema", "outcome", "source", "role", "serving_applicability",
        "public_state", "role_override", "refusal",
    }
    assert "secret" not in json.dumps(dataclasses.asdict(result.projection))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.projection.role = "off"


def test_missing_profile_and_invalid_profile_are_distinct(tmp_path: Path) -> None:
    """Fallback and refusal have different safe public outcomes."""
    path = tmp_path / "missing"
    fallback = load_with_identity({"ORAMA_SERVING_PROFILE": str(path)})
    assert fallback.projection.outcome == "fallback"
    assert fallback.projection.source == "no-profile"
    assert fallback.projection.role == "client"
    path.write_text("password: secret-value\npassword: secret-value\n")
    refused = load_with_identity({"ORAMA_SERVING_PROFILE": str(path)})
    assert refused.effective is None
    assert refused.projection.outcome == "refused"
    assert refused.projection.refusal == "load-refused"
    assert "secret" not in repr(refused)


@pytest.mark.parametrize("override, expected_role, expected_result", [
    ("", "client", "absent"),
    ("client", "client", "same"),
    ("off", "off", "downgraded"),
    ("primary-server", "client", "ignored"),
])
def test_fallback_override_classification(tmp_path: Path, override: str, expected_role: str, expected_result: str) -> None:
    """Fallback role overrides report their actual effect."""
    result = load_with_identity({"ORAMA_SERVING_PROFILE": str(tmp_path / "missing"), "ORAMA_NODE_ROLE": override})
    assert result.projection.role == expected_role
    assert result.projection.role_override == expected_result


def test_refusal_does_not_claim_override_was_evaluated(tmp_path: Path) -> None:
    """A parse refusal cannot report an override effect it never evaluated."""
    path = tmp_path / "bad"
    path.write_text("not: [valid")
    result = load_with_identity({"ORAMA_SERVING_PROFILE": str(path), "ORAMA_NODE_ROLE": "client"})
    assert result.projection.role_override == "unknown"
    assert result.projection.refusal == "load-refused"


def test_valid_profile_with_invalid_override_has_generic_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid override does not falsely classify a valid profile as invalid."""
    path = tmp_path / "valid.yml"
    path.write_text("version: 1\nnodes:\n  - id: node\n    os: linux\n")
    monkeypatch.setattr("orama.deploy.profile.running_os", lambda: "linux")
    result = load_with_identity({"ORAMA_SERVING_PROFILE": str(path), "ORAMA_NODE_ID": "node", "ORAMA_NODE_ROLE": "private-invalid-value"})
    assert result.projection.refusal == "load-refused"
    assert result.effective is None
    assert "private-invalid-value" not in repr(result)
