"""Observable workspace contracts shared by the v1/v2 proof of concept."""
import hashlib
import importlib
import json
import socket

import pytest
from fastapi.testclient import TestClient

FIXTURE = {
    "task": "Create an evidence table from this selected local passage.",
    "sources": [{"id": "s1", "title": "Synthetic local fixture",
                 "passage": "The fixture contains three records.", "kind": "primary"}],
    "records": [{"claim": "The fixture contains three records.", "source_id": "s1",
                 "quote": "The fixture contains three records."}],
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.setenv("ORAMA_LISTEN_HOST", "localhost")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    from orama.api.server import create_app; app = create_app()
    return TestClient(app, base_url="http://localhost")


def test_offline_run_delivers_bound_csv_and_canonical_receipt(client, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline task attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    response = client.post("/api/workspace/run", json=FIXTURE)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "verified"
    assert result["privacy"] == "local"
    assert result["execution"] == "offline-deterministic"
    assert result["artifact_name"] == "evidence.csv"
    assert result["receipt"]["actual_disclosure"] == "none"
    assert hashlib.sha256(result["csv"].encode()).hexdigest() == result["artifact_sha256"]
    assert hashlib.sha256(result["receipt_json"].encode()).hexdigest() == result["receipt_sha256"]
    assert json.loads(result["receipt_json"]) == result["receipt"]
    assert result["receipt"]["row_count"] == 1
    assert all(check["passed"] for check in result["receipt"]["checks"])
    assert "no-store" in response.headers["cache-control"]
    assert "claim,source_id,source_title,quote" in result["csv"]


@pytest.mark.parametrize("privacy", ["local", "sources", "redacted", "open"])
def test_sharing_opt_in_does_not_create_egress(client, privacy):
    result = client.post("/api/workspace/run", json={**FIXTURE, "privacy": privacy}).json()
    assert result["privacy"] == privacy
    assert result["receipt"]["actual_disclosure"] == "none"


@pytest.mark.parametrize("change", [
    {"privacy": "unknown"},
    {"sources": []},
    {"records": []},
    {"task": "   "},
    {"records": [{"claim": "Invented conclusion", "source_id": "s1",
                  "quote": "The fixture contains three records."}]},
    {"records": [{"claim": "Missing quote", "source_id": "s1", "quote": "Missing quote"}]},
    {"records": [{"claim": "The fixture contains three records.", "source_id": "missing",
                  "quote": "The fixture contains three records."}]},
    {"sources": FIXTURE["sources"] * 2},
    {"output_path": "../escape.csv"},
    {"privacy": None},
])
def test_invalid_or_unsupported_inputs_do_not_publish(client, change):
    response = client.post("/api/workspace/run", json={**FIXTURE, **change})
    assert response.status_code == 422
    assert "csv" not in response.json()


@pytest.mark.parametrize("value", ["=SUM(A1)", " +cmd", "\t@formula", "-2+3"])
def test_spreadsheet_formula_cells_are_refused(client, value):
    payload = {**FIXTURE, "sources": [{"id": "s1", "title": value,
               "passage": value, "kind": "unverified"}],
               "records": [{"claim": value, "source_id": "s1", "quote": value}]}
    assert client.post("/api/workspace/run", json=payload).status_code == 422


def test_capability_inventory_is_explicit_about_current_limits(client):
    result = client.get("/api/workspace/capabilities")
    assert result.status_code == 200
    assert result.json()["default_privacy"] == "local"
    assert result.json()["models"] == []
    assert result.json()["network_enabled"] is False


def test_control_plane_auth_remains_required(client, monkeypatch):
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "0")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "fixture-operator-capability-12345")
    response = client.post("/api/workspace/run", json=FIXTURE)
    assert response.status_code == 401
    response = client.post("/api/workspace/run", json=FIXTURE,
                           headers={"Authorization": "Bearer fixture-operator-capability-12345"})
    assert response.status_code == 200, response.text


def test_verifier_rejects_tampering_independently(client):
    result = client.post("/api/workspace/run", json=FIXTURE).json()
    verifier = importlib.import_module("orama.workspace.verify")
    assert verifier.verify_artifact(result["csv"], result["receipt"])["passed"]
    assert not verifier.verify_artifact(result["csv"].replace("three", "four"),
                                        result["receipt"])["passed"]
    receipt = json.loads(result["receipt_json"])
    receipt["sources"][0]["passage"] = "Unrelated source"
    assert not verifier.verify_artifact(result["csv"], receipt)["passed"]


def test_observation_excludes_task_source_and_private_text(client):
    result = client.post("/api/workspace/run", json=FIXTURE).json()
    observation = json.dumps(result["observation"])
    for private in [FIXTURE["task"], FIXTURE["sources"][0]["passage"],
                    FIXTURE["sources"][0]["title"]]:
        assert private not in observation
    assert result["observation"]["type"] == "message"


def test_oversized_request_is_refused_before_validation(client):
    response = client.post("/api/workspace/run", content=b" " * 270000,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413
