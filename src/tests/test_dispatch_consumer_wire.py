"""E1 "C2" consumer wire: strict validators and byte-exact vector reproduction."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from orama.graph.binding_digest import BindingDigestFields, compute_binding_digest
from orama.graph.dispatch_consumer_wire import (
    EVENT_WIRE_FIELDS,
    FINALIZATION_WIRE_FIELDS,
    GENESIS_EVENT_DIGEST,
    PERMIT_WIRE_FIELDS,
    WireError,
    canonical_bytes,
    event_digest,
    event_preimage,
    finalization_body,
    finalization_digest,
    parse_timestamp,
    permit_body,
    permit_payload_digest,
    validate_event_wire,
    validate_finalization_wire,
    validate_permit_wire,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "dispatch-permit-v1.json").read_text(encoding="utf-8")
)
PERMIT: dict[str, Any] = json.loads(VECTORS["permit"]["wire"])
FINALIZATION: dict[str, Any] = json.loads(VECTORS["finalization"]["wire"])
EVENTS: list[dict[str, Any]] = VECTORS["events"]
SIG63 = "A" * 84  # decodes to 63 bytes


def test_field_set_sizes_match_the_freeze() -> None:
    """21 permit fields, 15 finalization fields, 7 event fields."""
    assert (len(PERMIT_WIRE_FIELDS), len(FINALIZATION_WIRE_FIELDS), len(EVENT_WIRE_FIELDS)) == (
        21, 15, 7,
    )


def test_permit_vector_is_reproduced_byte_for_byte() -> None:
    """Body bytes, body object and payload digest of the vector permit are exact."""
    validate_permit_wire(PERMIT)
    body = permit_body(PERMIT)

    assert body == VECTORS["permit"]["body"]
    assert canonical_bytes(body).decode("utf-8") == VECTORS["permit"]["body_bytes"]
    assert canonical_bytes(PERMIT).decode("utf-8") == VECTORS["permit"]["wire"]
    assert permit_payload_digest(body) == VECTORS["permit"]["payload_digest"]
    assert PERMIT["payload_digest"] == VECTORS["permit"]["payload_digest"]


def test_finalization_vector_is_reproduced_byte_for_byte() -> None:
    """Body bytes, body object and finalization digest of the vector are exact."""
    validate_finalization_wire(FINALIZATION)
    body = finalization_body(FINALIZATION)

    assert body == VECTORS["finalization"]["body"]
    assert canonical_bytes(body).decode("utf-8") == VECTORS["finalization"]["body_bytes"]
    assert canonical_bytes(FINALIZATION).decode("utf-8") == VECTORS["finalization"]["wire"]
    assert finalization_digest(body) == VECTORS["finalization"]["finalization_digest"]


def test_permit_digest_is_the_finalization_permit_digest() -> None:
    """The finalization binds the permit's payload digest."""
    assert FINALIZATION["permit_digest"] == permit_payload_digest(permit_body(PERMIT))


def test_event_vectors_are_reproduced_and_chain_from_genesis() -> None:
    """Every vector event digest is recomputed and the chain starts at genesis."""
    previous = VECTORS["genesis_event_digest"]
    assert previous == GENESIS_EVENT_DIGEST == "0" * 64
    for event in EVENTS:
        validate_event_wire(event)
        digest = event_digest(event["version"], event["kind"], event["body"], previous)
        assert digest == event["event_digest"]
        assert event["previous_event_digest"] == previous
        previous = digest


def test_event_preimage_example_is_reproduced_exactly() -> None:
    """The documented preimage example equals the canonical wrapper bytes."""
    second = EVENTS[1]
    preimage = event_preimage(
        second["version"], second["kind"], second["body"], second["previous_event_digest"]
    )

    assert preimage.decode("utf-8") == VECTORS["event_preimage_example"]


def test_finalization_id_alone_is_not_the_event_preimage() -> None:
    """The bare finalization_id never hashes to the event digest."""
    import hashlib

    second = EVENTS[1]
    bare = hashlib.sha256(second["body"]["finalization_id"].encode()).hexdigest()

    assert bare != second["event_digest"]


def test_binding_digest_vector_uses_the_existing_helper() -> None:
    """compute_binding_digest reproduces the vector's binding digest from the request."""
    request = VECTORS["permit_request"]
    fields = BindingDigestFields(
        **{
            key: request[key]
            for key in (
                "grant_id", "grant_payload_digest", "operation_id", "request_digest",
                "artifact_digest", "reservation_id", "ledger_store_id",
                "configuration_policy_epoch", "authority_epoch",
            )
        }
    )

    assert compute_binding_digest(fields) == VECTORS["binding_digest"]


def test_canonical_bytes_rejects_nan_and_keeps_unicode() -> None:
    """allow_nan is off and ensure_ascii is off."""
    assert canonical_bytes({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
    with pytest.raises(ValueError):
        canonical_bytes({"a": float("nan")})


def _mutated(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Copy ``base`` with ``changes`` applied (a value of ... deletes the key)."""
    copy = deepcopy(base)
    for key, value in changes.items():
        if value is ...:
            del copy[key]
        else:
            copy[key] = value
    return copy


BAD_COMMON = [
    ("extra_key", {"zzz": "x"}),
    ("null_text", {"grant_id": None}),
    ("blank_text", {"grant_id": "  "}),
    ("long_text", {"grant_id": "é" * 513}),
    ("bool_epoch", {"authority_epoch": True}),
    ("zero_epoch", {"authority_epoch": 0}),
    ("float_epoch", {"authority_epoch": 5.0}),
    ("huge_epoch", {"authority_epoch": 2**53}),
    ("negative_ack", {"consumer_acked_through": -1}),
    ("string_ack", {"consumer_acked_through": "1"}),
    ("schema_2", {"schema_version": 2}),
    ("ts_three_digits", {"requested_at": "2026-10-19T04:00:00.000Z"}),
    ("ts_offset", {"requested_at": "2026-10-19T04:00:00.000000+00:00"}),
    ("ts_bad_date", {"requested_at": "2026-13-19T04:00:00.000000Z"}),
    ("sig_padded", {"issuer_signature": PERMIT["issuer_signature"] + "=="}),
    ("sig_short", {"issuer_signature": SIG63}),
    ("sig_not_str", {"issuer_signature": 7}),
]


@pytest.mark.parametrize(("name", "changes"), BAD_COMMON, ids=[n for n, _ in BAD_COMMON])
def test_permit_wire_rejects_malformed(name: str, changes: dict[str, Any]) -> None:
    """Each malformation of the 21-field permit wire is refused."""
    with pytest.raises(WireError):
        validate_permit_wire(_mutated(PERMIT, **changes))


@pytest.mark.parametrize("digest_field", ["grant_payload_digest", "payload_digest"])
@pytest.mark.parametrize("bad", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, 5])
def test_permit_wire_rejects_bad_digests(digest_field: str, bad: Any) -> None:
    """Digests are exactly 64 lowercase hex characters."""
    with pytest.raises(WireError):
        validate_permit_wire(_mutated(PERMIT, **{digest_field: bad}))


def test_permit_wire_rejects_missing_field_and_non_mapping() -> None:
    """A missing key and a non-object are both refused."""
    with pytest.raises(WireError):
        validate_permit_wire(_mutated(PERMIT, permit_id=...))
    with pytest.raises(WireError):
        validate_permit_wire([PERMIT])  # type: ignore[arg-type]


def test_finalization_wire_rejects_malformed() -> None:
    """Finalization wire: extra, missing, null, bool-as-int, bad digest, bad signature."""
    for changes in (
        {"zzz": 1},
        {"finalization_id": ...},
        {"finalization_id": None},
        {"revocation_version": True},
        {"revocation_version": 0.5},
        {"revocation_event_digest": "F" * 64},
        {"permit_digest": "a" * 10},
        {"issuer_signature": SIG63},
        {"expires_at": "2026-10-19 04:01:31.000000Z"},
        {"schema_version": 0},
    ):
        with pytest.raises(WireError):
            validate_finalization_wire(_mutated(FINALIZATION, **changes))


def test_finalization_wire_accepts_zero_acked_through() -> None:
    """consumer_acked_through may be 0 but revocation_version of a finalization may too."""
    validate_finalization_wire(_mutated(FINALIZATION, consumer_acked_through=0))


def test_event_wire_rejects_malformed() -> None:
    """Event wire: extra, missing, bad kind, bad version, bad body, bad digests."""
    base = EVENTS[1]
    for changes in (
        {"zzz": 1},
        {"body": ...},
        {"kind": "other"},
        {"version": 0},
        {"version": True},
        {"body": []},
        {"body": {"finalization_id": "a", "x": "y"}},
        {"body": {"finalization_id": None}},
        {"event_digest": "x" * 64},
        {"previous_event_digest": "A" * 64},
        {"signature": SIG63},
        {"issuer_key_id": ""},
    ):
        with pytest.raises(WireError):
            validate_event_wire(_mutated(base, **changes))


def test_event_wire_rejects_an_oversize_object() -> None:
    """An event whose canonical bytes exceed 65536 is refused."""
    grants = [f"{i:04d}" + "x" * 1020 for i in range(70)]  # a valid cascade body, too large
    big = _mutated(
        EVENTS[1], kind="cascade",
        body={"approval_id": "a-1", "grant_ids": grants, "issuer_authority_version": 1},
    )

    with pytest.raises(WireError, match="65536"):
        validate_event_wire(big)


def test_parse_timestamp_is_strict_and_utc() -> None:
    """Only six-digit UTC text parses."""
    parsed = parse_timestamp("2026-10-19T04:01:31.000000Z")
    assert parsed.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    with pytest.raises(WireError):
        parse_timestamp("2026-10-19T04:01:31Z")


FULLWIDTH_TIME = "２０２６-10-19T04:00:00.000000Z"


def test_fullwidth_digit_timestamps_are_refused_everywhere() -> None:
    """Only ASCII digits form a timestamp (event wire has no timestamp field)."""
    with pytest.raises(WireError):
        parse_timestamp(FULLWIDTH_TIME)
    with pytest.raises(WireError):
        validate_permit_wire(_mutated(PERMIT, issued_at=FULLWIDTH_TIME))
    with pytest.raises(WireError):
        validate_finalization_wire(_mutated(FINALIZATION, expires_at=FULLWIDTH_TIME))


@pytest.mark.parametrize("kind", [["finalization"], {"k": 1}, 7, None, b"finalization"])
def test_event_kind_that_is_not_a_string_raises_wire_error(kind: Any) -> None:
    """An unhashable or non-text kind is a WireError, never a raw TypeError."""
    with pytest.raises(WireError):
        validate_event_wire(_mutated(EVENTS[1], kind=kind))


def test_canonical_bytes_turns_nan_into_a_wire_error() -> None:
    """NaN in an event body is a WireError through the validator and canonical_bytes."""
    with pytest.raises(WireError):
        canonical_bytes({"a": float("nan")})
    with pytest.raises(WireError):
        validate_event_wire(_mutated(EVENTS[1], kind="revocation", body={"x": float("nan")}))
