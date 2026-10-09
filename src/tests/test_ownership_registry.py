"""Ownership registry conformance: one owner per fact, checked against live code.

The registry is authored in orama-system docs/v2 (planning authority). This repo keeps a
byte-identical snapshot and pins its digest, so a registry change is a reviewed change in
both repositories. Decision records: D-LG-1 and D-LG-5.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
from typing import Any, get_args

import pytest

from orama.compat.policy import GraphPolicy
from perpetua_core.graph import spec as core_spec

SNAPSHOT = Path(__file__).parent / "fixtures" / "graph-ownership-registry.json"
PINNED_SHA256 = "c1bf6b519f703184745e61142f259ae8eb73d163210bb1395437f8a82c2b402f"
REGISTRY: dict[str, Any] = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
assert len({r["record"] for r in REGISTRY["records"]}) == len(REGISTRY["records"]), "duplicate record"
RECORDS = {record["record"]: record for record in REGISTRY["records"]}


def code_fields(record: str) -> set[str]:
    """Return the field names the installed code declares for a registered record."""
    if record == "GraphPolicy":
        return set(GraphPolicy.model_fields)
    return {field.name for field in dataclasses.fields(getattr(core_spec, record))}


def names(record: str, status: str) -> set[str]:
    """Registry field names for one record and status."""
    return {f["name"] for f in RECORDS[record]["fields"] if f["status"] == status}


def test_snapshot_digest_is_pinned() -> None:
    """A registry edit must be a reviewed edit in both repositories."""
    assert hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest() == PINNED_SHA256


def test_orama_checkout_is_byte_identical() -> None:
    """Optional local check against an orama-system checkout named by the environment."""
    root = os.environ.get("ORAMA_DOCS_V2_REGISTRY")
    if not root:
        pytest.skip("ORAMA_DOCS_V2_REGISTRY not set")
    assert Path(root).read_bytes() == SNAPSHOT.read_bytes()


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
    assert owners == {"GraphSpec": "perpetua-core", "NodeSpec": "perpetua-core",
                      "EdgeSpec": "perpetua-core", "GraphPolicy": "oramasys"}
    assert set(owners.values()) <= set(REGISTRY["owners"])


def test_policy_never_computes() -> None:
    """A policy field may restrict or identify; it may never change a computed result."""
    categories = {f["category"] for f in RECORDS["GraphPolicy"]["fields"]}
    assert categories <= {"identity", "binding", "restricts"}


def test_computes_fields_live_only_in_the_core_spec() -> None:
    """Fields that change produced state belong to the structural GraphSpec."""
    for record in RECORDS.values():
        computing = [f for f in record["fields"] if f["category"] == "computes"]
        if record["record"] != "GraphSpec":
            assert not computing, record["record"]


@pytest.mark.parametrize("record", sorted(RECORDS))
def test_planned_fields_are_not_in_code_yet(record: str) -> None:
    """Shipping a planned field requires a registry change in the same reviewed step."""
    assert not (names(record, "planned") & code_fields(record))


def test_literals_match_code() -> None:
    """Edge kinds: implemented values equal the live Literal; planned ones are absent."""
    for literal in REGISTRY["literals"]:
        live = set(get_args(getattr(core_spec, literal["name"])))
        implemented = {v["value"] for v in literal["values"] if v["status"] == "implemented"}
        planned = {v["value"] for v in literal["values"] if v["status"] == "planned"}
        assert live == implemented
        assert not (live & planned)


def test_policy_rejects_reducer_declarations() -> None:
    """Policy may only restrict: a reducer declaration is an unknown field and fails closed."""
    graph_id = "0" * 64
    for key in ("reducers", "joins"):
        with pytest.raises(ValueError):
            GraphPolicy.model_validate({"graph_id": graph_id, key: {}})
