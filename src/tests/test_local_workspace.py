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
    """TestClient for a locally-insecure (loopback-only) oramasys app instance."""
    monkeypatch.setenv("ORAMA_INSECURE_DEV", "1")
    monkeypatch.setenv("ORAMA_LISTEN_HOST", "localhost")
    monkeypatch.delenv("ORAMA_BIND_LAN", raising=False)
    from orama.api.server import create_app
    app = create_app()
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


def test_bare_carriage_return_round_trips_through_the_csv_verifier(client):
    text = "first\rsecond"
    payload = {**FIXTURE, "sources": [{"id": "s1", "title": "CR fixture",
               "passage": text, "kind": "primary"}],
               "records": [{"claim": text, "source_id": "s1", "quote": text}]}
    response = client.post("/api/workspace/run", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["receipt"]["row_count"] == 1


def test_verifier_binds_the_receipt_to_the_hashed_input(client):
    two_sources = {**FIXTURE, "sources": [
        {"id": "s1", "title": "One", "passage": "The fixture contains three records.",
         "kind": "unverified"},
        {"id": "s2", "title": "Two", "passage": "Another passage.", "kind": "primary"}]}
    result = client.post("/api/workspace/run", json=two_sources).json()
    verifier = importlib.import_module("orama.workspace.verify")
    csv_text = result["csv"]
    assert verifier.verify_artifact(csv_text, result["receipt"])["passed"]
    for tamper in (
        lambda r: r.update(task="A different task"),
        lambda r: r.update(privacy="open"),
        lambda r: r.pop("input_sha256"),
        lambda r: r.update(source_order=list(reversed(r["source_order"]))),
    ):
        receipt = json.loads(result["receipt_json"])
        tamper(receipt)
        verdict = verifier.verify_artifact(csv_text, receipt)
        assert not verdict["passed"]


def test_capabilities_expose_the_numeric_limits(client):
    limits = client.get("/api/workspace/capabilities").json()["limits"]
    assert limits == {"max_body_bytes": 262144, "max_sources": 32, "max_records": 100,
                      "max_text_chars": 12000, "max_short_text_chars": 500}


def test_a_legacy_v1_receipt_still_verifies_with_an_explicit_note(client):
    """Receipts downloaded before source_order existed are legacy evidence, not damaged."""
    result = client.post("/api/workspace/run", json=FIXTURE).json()
    verifier = importlib.import_module("orama.workspace.verify")
    legacy = json.loads(result["receipt_json"])
    legacy["schema_version"] = "workspace-artifact-v1"
    legacy.pop("source_order")
    verdict = verifier.verify_artifact(result["csv"], legacy)
    assert verdict["passed"]
    assert any("legacy v1" in note for note in verdict["notes"])
    assert not any(check["name"] == "input_sha256" for check in verdict["checks"])
    current = verifier.verify_artifact(result["csv"], json.loads(result["receipt_json"]))
    assert current["passed"] and current["notes"] == []


def test_an_unknown_receipt_version_fails_closed(client):
    result = client.post("/api/workspace/run", json=FIXTURE).json()
    verifier = importlib.import_module("orama.workspace.verify")
    receipt = json.loads(result["receipt_json"])
    receipt["schema_version"] = "workspace-artifact-v9"
    assert not verifier.verify_artifact(result["csv"], receipt)["passed"]
