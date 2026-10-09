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
PROFILE = "core-r3" if HAS_R3 else "policy-r3"
SNAPSHOT = FIXTURES / f"graph-ownership-registry-{PROFILE}.json"
PINNED_DIGESTS = {
    "baseline": "c1bf6b519f703184745e61142f259ae8eb73d163210bb1395437f8a82c2b402f",
    "policy-r3": "7aeed7456db148383698f6df97a38632dbf72f23d411f9c773ed6cb10ab777fb",
    "core-r3": "498e9383667252b841845d4dc061853adfe3e3864d976a3e2f7c8a59eea3adab",
}


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


def test_orama_checkout_is_byte_identical() -> None:
    """Compare canonical bytes; CI supplies its immutable Orama checkout."""
    root = os.environ.get("ORAMA_DOCS_V2_REGISTRY")
    if not root:
        pytest.skip("ORAMA_DOCS_V2_REGISTRY not set")
    baseline = Path(root)
    assert baseline.read_bytes() == (FIXTURES / "graph-ownership-registry.json").read_bytes()
    canonical = baseline.with_name(f"ownership-registry-{PROFILE}.json")
    assert canonical.read_bytes() == SNAPSHOT.read_bytes()


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


def test_profile_is_explicitly_candidate_and_matches_installed_core() -> None:
    """Candidate conformance cannot be confused with promotion of the baseline."""
    qualification = REGISTRY["qualification_profile"]
    assert qualification["status"] == "candidate"
    assert qualification["core_schema"] == ("2" if HAS_R3 else "1")
    assert qualification["production_core_pin"] == "04759a50c748444ff97136ea95c1e1289eac3a1a"


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
