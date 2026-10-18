"""E1 "C2" permit-replay: binding digest determinism and field validation."""
from __future__ import annotations

import re

import pytest

from orama.graph.binding_digest import BindingDigestFields, compute_binding_digest

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

STRING_FIELDS = (
    "grant_id",
    "grant_payload_digest",
    "operation_id",
    "request_digest",
    "artifact_digest",
    "reservation_id",
    "ledger_store_id",
)

EPOCH_FIELDS = ("configuration_policy_epoch", "authority_epoch")


def _base_kwargs() -> dict[str, object]:
    """Return a valid baseline set of the nine binding digest field values."""
    return {
        "grant_id": "grant-1",
        "grant_payload_digest": "a" * 64,
        "operation_id": "op-1",
        "request_digest": "b" * 64,
        "artifact_digest": "c" * 64,
        "reservation_id": "reservation-1",
        "ledger_store_id": "store-1",
        "configuration_policy_epoch": 1,
        "authority_epoch": 1,
    }


def test_digest_is_deterministic() -> None:
    """Same 9 field values produce the same digest."""
    fields_a = BindingDigestFields(**_base_kwargs())
    fields_b = BindingDigestFields(**_base_kwargs())
    assert compute_binding_digest(fields_a) == compute_binding_digest(fields_b)


@pytest.mark.parametrize(
    "field_name,new_value",
    [
        ("grant_id", "grant-2"),
        ("request_digest", "d" * 64),
        ("authority_epoch", 2),
    ],
)
def test_changing_one_field_changes_digest(field_name: str, new_value: object) -> None:
    """Changing any single one of the 9 fields changes the digest."""
    baseline = BindingDigestFields(**_base_kwargs())
    kwargs = _base_kwargs()
    kwargs[field_name] = new_value
    changed = BindingDigestFields(**kwargs)
    assert compute_binding_digest(baseline) != compute_binding_digest(changed)


def test_construction_keyword_order_does_not_affect_digest() -> None:
    """Keyword argument order at construction does not affect the digest."""
    in_order = BindingDigestFields(
        grant_id="grant-1",
        grant_payload_digest="a" * 64,
        operation_id="op-1",
        request_digest="b" * 64,
        artifact_digest="c" * 64,
        reservation_id="reservation-1",
        ledger_store_id="store-1",
        configuration_policy_epoch=1,
        authority_epoch=1,
    )
    reordered = BindingDigestFields(
        authority_epoch=1,
        configuration_policy_epoch=1,
        ledger_store_id="store-1",
        reservation_id="reservation-1",
        artifact_digest="c" * 64,
        request_digest="b" * 64,
        operation_id="op-1",
        grant_payload_digest="a" * 64,
        grant_id="grant-1",
    )
    assert compute_binding_digest(in_order) == compute_binding_digest(reordered)


@pytest.mark.parametrize("field_name", STRING_FIELDS)
def test_rejects_empty_string_field(field_name: str) -> None:
    """__post_init__ rejects an empty (or whitespace-only) string for each string field."""
    kwargs = _base_kwargs()
    kwargs[field_name] = ""
    with pytest.raises(ValueError):
        BindingDigestFields(**kwargs)

    kwargs[field_name] = "   "
    with pytest.raises(ValueError):
        BindingDigestFields(**kwargs)


@pytest.mark.parametrize("field_name", EPOCH_FIELDS)
@pytest.mark.parametrize("bad_value", [0, -1, True, False])
def test_rejects_invalid_epoch_values(field_name: str, bad_value: object) -> None:
    """__post_init__ rejects non-positive ints and bool-as-int for the epoch fields."""
    kwargs = _base_kwargs()
    kwargs[field_name] = bad_value
    with pytest.raises(ValueError):
        BindingDigestFields(**kwargs)


def test_digest_is_64_lowercase_hex_characters() -> None:
    """The digest is always exactly 64 lowercase hex characters."""
    digest = compute_binding_digest(BindingDigestFields(**_base_kwargs()))
    assert len(digest) == 64
    assert _HEX64.match(digest)
    assert int(digest, 16) >= 0
