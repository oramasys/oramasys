import dataclasses
import json
from pathlib import Path

import pytest

from orama.deploy.identity import load_with_identity


def test_capture_uses_one_read_and_freezes_safe_projection(tmp_path, monkeypatch):
    path = tmp_path / "secret-path.yml"
    path.write_text("version: 1\nnodes:\n  - id: secret-node\n    os: linux\n    role: primary-server\n    endpoint: secret-host:1234\n    state_root: /secret-path\n")
    monkeypatch.setattr("orama.deploy.profile.running_os", lambda: "linux")
    original = Path.open
    reads = []

    def counted(self, *args, **kwargs):
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


def test_missing_profile_and_invalid_profile_are_distinct(tmp_path):
    path = tmp_path / "missing"
    fallback = load_with_identity({"ORAMA_SERVING_PROFILE": str(path)})
    assert fallback.projection.outcome == "fallback"
    assert fallback.projection.source == "no-profile"
    assert fallback.projection.role == "client"
    path.write_text("password: secret-value\npassword: secret-value\n")
    refused = load_with_identity({"ORAMA_SERVING_PROFILE": str(path)})
    assert refused.effective is None
    assert refused.projection.outcome == "refused"
    assert refused.projection.refusal == "profile-invalid"
    assert "secret" not in repr(refused)


@pytest.mark.parametrize("override, expected_role, expected_result", [
    ("", "client", "absent"),
    ("client", "client", "same"),
    ("off", "off", "downgraded"),
    ("primary-server", "client", "ignored"),
])
def test_fallback_override_classification(tmp_path, override, expected_role, expected_result):
    result = load_with_identity({"ORAMA_SERVING_PROFILE": str(tmp_path / "missing"), "ORAMA_NODE_ROLE": override})
    assert result.projection.role == expected_role
    assert result.projection.role_override == expected_result


def test_refusal_does_not_claim_override_was_evaluated(tmp_path):
    path = tmp_path / "bad"
    path.write_text("not: [valid")
    result = load_with_identity({"ORAMA_SERVING_PROFILE": str(path), "ORAMA_NODE_ROLE": "client"})
    assert result.projection.role_override == "unknown"
    assert result.projection.refusal == "profile-invalid"
