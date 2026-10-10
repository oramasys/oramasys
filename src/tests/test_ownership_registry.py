"""Ownership registry conformance: one owner per fact, checked against live code.

The registry is authored in orama-system docs/v2 (planning authority). This repo keeps a
byte-identical snapshot and pins its digest, so a registry change is a reviewed change in
both repositories. Candidate profiles qualify policy changes against production
Core and R3 Core separately; they do not promote the baseline. Decisions:
D-LG-1, D-LG-5 and D-LG-6.
"""
from __future__ import annotations

import dataclasses
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, get_args

import pytest

from orama.compat import policy as policy_module
from orama.compat.policy import GraphPolicy
from perpetua_core.graph import spec as core_spec

FIXTURES = Path(__file__).parent / "fixtures"
HAS_R3 = hasattr(core_spec, "ReducerSpec")
PROFILE = os.environ.get("ORAMA_REGISTRY_PROFILE", "production")
SNAPSHOTS = {
    "production": FIXTURES / "graph-ownership-registry.json",
    "policy-r3": FIXTURES / "graph-ownership-registry-policy-r3.json",
    "core-r3": FIXTURES / "graph-ownership-registry-core-r3.json",
}
CORE_PINS = {
    "production": "4d217f6b9e94e36554a9427198b8c2c4b7febc47",
    "policy-r3": "04759a50c748444ff97136ea95c1e1289eac3a1a",
    "core-r3": "34e4a8d22212d38d6ab100c1ad7fb2b19f56cb68",
}
CORE_SCHEMAS = {
    "production": "2",
    "policy-r3": "1",
    "core-r3": "2",
}


def snapshot_for_profile(profile: str) -> Path:
    """Select only a named reviewed profile; no heuristic fallback is permitted."""
    try:
        return SNAPSHOTS[profile]
    except KeyError as exc:
        raise ValueError(f"unknown registry profile: {profile}") from exc


SNAPSHOT = snapshot_for_profile(PROFILE)
PINNED_DIGESTS = {
    "baseline": "fbde64f2c3b2bec62f703137f5fddb480d502440b9e1b229c15292816b52f7e2",
    "policy-r3": "4972754f7ceb0ad3e908f6583533fec3c59a807732ac86c3ee967df33e29e36f",
    "core-r3": "e270493a7c924871e50fcf384c792a6922a375976127e26214f69b7c89ba9437",
}
PRE_R3_ARCHIVE_DIGEST = "c1bf6b519f703184745e61142f259ae8eb73d163210bb1395437f8a82c2b402f"


def index_records(registry: dict[str, Any]) -> dict[str, Any]:
    """Refuse duplicate records before indexing can silently discard evidence."""
    records = registry["records"]
    assert len({record["record"] for record in records}) == len(records), "duplicate record"
    return {record["record"]: record for record in records}


REGISTRY: dict[str, Any] = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
RECORDS = index_records(REGISTRY)


def code_fields(record: str) -> set[str]:
    """Return the field names the installed code declares for a registered record."""
    if RECORDS[record]["owner"] == "oramasys":
        return set(getattr(policy_module, record).model_fields)
    return {field.name for field in dataclasses.fields(getattr(core_spec, record))}


def names(record: str, status: str) -> set[str]:
    """Registry field names for one record and status."""
    return {f["name"] for f in RECORDS[record]["fields"] if f["status"] == status}


def test_snapshot_digest_is_pinned() -> None:
    """A registry edit must be a reviewed edit in both repositories."""
    for profile, digest in PINNED_DIGESTS.items():
        suffix = "" if profile == "baseline" else f"-{profile}"
        snapshot = FIXTURES / f"graph-ownership-registry{suffix}.json"
        assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == digest


def test_pre_r3_archive_preserves_the_original_baseline_bytes() -> None:
    """The archived baseline is evidence, not JSON eligible for reformatting."""
    archive = FIXTURES / "graph-ownership-registry-pre-r3.json"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == PRE_R3_ARCHIVE_DIGEST


def test_unknown_profile_is_refused() -> None:
    """A typo must never select a candidate or silently fall back to production."""
    with pytest.raises(ValueError, match="unknown registry profile: typo"):
        snapshot_for_profile("typo")


def test_orama_checkout_is_byte_identical() -> None:
    """Compare canonical bytes; CI supplies its immutable Orama checkout."""
    root = os.environ.get("ORAMA_DOCS_V2_REGISTRY")
    if not root:
        pytest.skip("ORAMA_DOCS_V2_REGISTRY not set")
    canonical = Path(root)
    if PROFILE == "production":
        assert canonical.read_bytes() == SNAPSHOT.read_bytes()
    else:
        assert canonical.with_name(f"ownership-registry-{PROFILE}.json").read_bytes() == SNAPSHOT.read_bytes()
    assert canonical.with_name("ownership-registry-pre-r3.json").read_bytes() == (
        FIXTURES / "graph-ownership-registry-pre-r3.json"
    ).read_bytes()


def test_each_field_has_exactly_one_entry() -> None:
    """No field is registered twice within a record."""
    for record in RECORDS.values():
        listed = [f["name"] for f in record["fields"]]
        assert len(listed) == len(set(listed)), record["record"]


@pytest.mark.parametrize("record", sorted(RECORDS))
def test_implemented_fields_match_code(record: str) -> None:
    """Code and registry agree: nothing unregistered, nothing registered but absent."""
    assert code_fields(record) == names(record, "implemented")


def test_owners_are_the_declared_ones() -> None:
    """Structure belongs to Core and restriction to Oramasys."""
    owners = {name: rec["owner"] for name, rec in RECORDS.items()}
    expected = {"GraphSpec": "perpetua-core", "NodeSpec": "perpetua-core",
                "EdgeSpec": "perpetua-core", "GraphPolicy": "oramasys",
                "ForbiddenReducer": "oramasys", "ReducerRestrictions": "oramasys",
                "JoinRestrictions": "oramasys"}
    if HAS_R3:
        expected.update(ReducerSpec="perpetua-core", JoinSpec="perpetua-core")
    assert owners == expected
    assert set(owners.values()) <= set(REGISTRY["owners"])


def test_policy_never_computes() -> None:
    """A policy field may restrict or identify; it may never change a computed result."""
    categories = {f["category"] for f in RECORDS["GraphPolicy"]["fields"]}
    assert categories <= {"identity", "binding", "restricts"}


def test_computes_fields_live_only_in_the_core_spec() -> None:
    """Fields that change produced state belong to the structural GraphSpec."""
    for record in RECORDS.values():
        computing = [f for f in record["fields"] if f["category"] == "computes"]
        if record["record"] != "GraphSpec" or record["owner"] != "perpetua-core":
            assert not computing, record["record"]


def test_duplicate_record_mutation_is_rejected_before_indexing() -> None:
    """A conflicting duplicate cannot disappear behind the last record's value."""
    mutated = deepcopy(REGISTRY)
    mutated["records"].insert(0, deepcopy(mutated["records"][0]))
    mutated["records"][0]["owner"] = "oramasys"
    with pytest.raises(AssertionError, match="duplicate record"):
        index_records(mutated)


@pytest.mark.parametrize("record", ["NodeSpec", "EdgeSpec"])
def test_wrong_record_computes_mutation_is_rejected(record: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Core ownership alone must not permit computes fields on another record."""
    mutated = deepcopy(RECORDS)
    mutated[record]["fields"][0]["category"] = "computes"
    monkeypatch.setitem(globals(), "RECORDS", mutated)
    with pytest.raises(AssertionError, match=record):
        test_computes_fields_live_only_in_the_core_spec()


def test_profile_is_explicit_and_matches_its_immutable_core_pin() -> None:
    """Production and historical candidate lanes cannot be confused."""
    qualification = REGISTRY["qualification_profile"]
    expected_status = "production" if PROFILE == "production" else "candidate"
    assert qualification["status"] == expected_status
    assert qualification["core_pin"] == CORE_PINS[PROFILE]
    assert qualification["core_schema"] == CORE_SCHEMAS[PROFILE]
    assert HAS_R3 is (CORE_SCHEMAS[PROFILE] == "2")


@pytest.mark.parametrize("record", sorted(RECORDS))
def test_planned_fields_are_not_in_code_yet(record: str) -> None:
    """Shipping a planned field requires a registry change in the same reviewed step."""
    assert not (names(record, "planned") & code_fields(record))


def test_literals_match_code() -> None:
    """Registered producer and consumer unions agree with their reviewed values."""
    expected = {("perpetua-core", "EdgeKind"), ("oramasys", "ReducerKind"),
                ("oramasys", "JoinKind")}
    if HAS_R3:
        expected |= {("perpetua-core", "ReducerKind"), ("perpetua-core", "JoinKind")}
    identities = [(literal["owner"], literal["name"]) for literal in REGISTRY["literals"]]
    assert len(identities) == len(set(identities)), "duplicate literal"
    assert set(identities) == expected, "literal inventory"
    for literal in REGISTRY["literals"]:
        module = core_spec if literal["owner"] == "perpetua-core" else policy_module
        live = set(get_args(getattr(module, literal["name"])))
        implemented = {v["value"] for v in literal["values"] if v["status"] == "implemented"}
        planned = {v["value"] for v in literal["values"] if v["status"] == "planned"}
        assert live == implemented
        assert not (live & planned)
    if HAS_R3:
        for name in ("ReducerKind", "JoinKind"):
            assert set(get_args(getattr(core_spec, name))) == set(get_args(getattr(policy_module, name)))


def test_missing_literal_inventory_mutation_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing declarations cannot turn conformance into a vacuous success."""
    mutated = deepcopy(REGISTRY)
    mutated["literals"] = mutated["literals"][:1]
    monkeypatch.setitem(globals(), "REGISTRY", mutated)
    with pytest.raises(AssertionError, match="literal inventory"):
        test_literals_match_code()


@pytest.mark.parametrize("name", ["ReducerKind", "JoinKind"])
def test_literal_drift_mutation_is_rejected(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A consumer-only literal change must fail even if field names still match."""
    from typing import Literal
    monkeypatch.setattr(policy_module, name, Literal["unregistered"])
    with pytest.raises(AssertionError):
        test_literals_match_code()


def test_policy_rejects_reducer_declarations() -> None:
    """Policy may only restrict: a reducer declaration is an unknown field and fails closed."""
    graph_id = "0" * 64
    for key in ("reducers", "joins"):
        with pytest.raises(ValueError):
            GraphPolicy.model_validate({"graph_id": graph_id, key: {}})
