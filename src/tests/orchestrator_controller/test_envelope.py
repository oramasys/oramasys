"""C2a: the claim request envelope (doc 68 section 4.2, IC-7/IC-8 partial, IC-28, IC-29)."""
from __future__ import annotations

import pytest

from orama.orchestrator_controller.envelope import ClaimRequest
from orama.orchestrator_controller.refusals import ClaimRefused

from .support import DROP, raw, request

REQUIRED = (
    "schema_version",
    "operation",
    "task_id",
    "principal",
    "idempotency_key",
    "expected_task_version",
    "source_ref",
    "expected_base_sha",
)


def _refused(body: dict) -> ClaimRefused:
    """Parse ``body`` expecting a refusal and return it."""
    with pytest.raises(ClaimRefused) as caught:
        ClaimRequest.from_mapping(body)
    return caught.value


def test_valid_claim_parses_with_exact_fields() -> None:
    """A complete section 4.2 claim parses into the frozen request."""
    parsed = request()
    assert parsed.operation == "claim"
    assert parsed.task_id == "task-1"
    assert parsed.expected_task_version == 1
    assert parsed.lease_id is None and parsed.lineage is None


@pytest.mark.parametrize("name", REQUIRED)
def test_required_field_has_no_default(name: str) -> None:
    """IC-7 (claim panel): a missing required field is invalid, never defaulted."""
    refusal = _refused(raw(**{name: DROP}))
    assert (refusal.code, refusal.status) == ("envelope.invalid", 400)


@pytest.mark.parametrize("extra", ["availability", "header", "heartbeat", "lease_expires_at"])
def test_unknown_fields_are_forbidden(extra: str) -> None:
    """IC-8 (claim panel): unknown fields are refused rather than ignored."""
    assert _refused(raw(**{extra: "x"})).code == "envelope.invalid"


def test_header_not_accepted_until_core_validator_exists() -> None:
    """IC-29 is out of slice: a common header cannot reach claim semantics at all."""
    assert _refused(raw(header={"envelope_kind": "claim"})).status == 400


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2"),
        ("schema_version", 1),
        ("operation", "recover-expired"),
        ("operation", "handoff"),
        ("expected_task_version", 0),
        ("expected_task_version", True),
        ("expected_task_version", "1"),
        ("task_id", ""),
        ("task_id", "/tmp/task"),
        ("task_id", "a b"),
        ("task_id", "host:8080"),
        ("principal", "~agent"),
        ("idempotency_key", "x" * 129),
        ("source_ref", "/abs/ref"),
        ("source_ref", "~/ref"),
        ("source_ref", "refs\\heads"),
        ("source_ref", "refs/../main"),
        ("source_ref", ""),
        ("expected_base_sha", "abc123"),
        ("expected_base_sha", "A" * 40),
        ("expected_base_sha", "a" * 41),
        ("capability_proof", 7),
    ],
)
def test_malformed_values_are_invalid(field: str, value: object) -> None:
    """Every field is validated before any lookup."""
    assert _refused(raw(**{field: value})).code == "envelope.invalid"


def test_source_ref_accepts_a_reviewed_ref_with_slashes() -> None:
    """An ordinary reviewed ref is an allowed opaque source line."""
    assert request(source_ref="refs/heads/main").source_ref == "refs/heads/main"


def test_operation_specific_fields() -> None:
    """Lease fields belong to lease-bound operations; completion and failure fields to their own."""
    assert _refused(raw("claim", lease_id="lease-1", lease_token="t" * 43)).code == "envelope.invalid"
    assert _refused(raw("renew")).code == "envelope.invalid"
    assert _refused(raw("complete", lease_id="lease-1", lease_token="t" * 43, result_digest=DROP)).status == 400
    assert _refused(raw("claim", result_digest="e" * 64)).status == 400
    assert _refused(raw("fail", lease_id="lease-1", lease_token="t" * 43, failure_class="oops")).status == 400
    assert _refused(raw("release", lease_id="lease-1", lease_token="t" * 43, failure_class="timeout")).status == 400


def test_lineage_is_allowlisted() -> None:
    """Lineage carries only the doc 69 keys with opaque values."""
    ok = request(lineage={"on_behalf_of": "agent-z", "takeover": True})
    assert ok.lineage_dict() == {"on_behalf_of": "agent-z", "takeover": True}
    assert _refused(raw(lineage={"workspace": "x"})).status == 400
    assert _refused(raw(lineage={"prior_agent": "/opt/agent"})).status == 400
    assert _refused(raw(lineage="agent-z")).status == 400


def test_projection_mismatch_is_its_own_400() -> None:
    """IC-28: projected task and principal values must equal the canonical ones exactly."""
    assert request(correlation_task_id="task-1", actor_principal_id="agent-a").task_id == "task-1"
    for field, value in (("correlation_task_id", "task-2"), ("actor_principal_id", "agent-b")):
        refusal = _refused(raw(**{field: value}))
        assert (refusal.code, refusal.status) == ("envelope.projection_mismatch", 400)


def test_digest_is_canonical_and_excludes_proof() -> None:
    """IC-12/13: the digest covers request content, not the rotating capability proof."""
    first = request()
    assert first.request_digest() == request(capability_proof="another-proof").request_digest()
    assert first.request_digest() != request(expected_task_version=2).request_digest()
    assert first.request_digest() == ClaimRequest.from_mapping(dict(reversed(list(raw().items())))).request_digest()


def test_digest_covers_the_lease_token() -> None:
    """A retry that presents a different token is different content."""
    one = request("renew", lease_id="lease-1", lease_token="a" * 43)
    two = request("renew", lease_id="lease-1", lease_token="b" * 43)
    assert one.request_digest() != two.request_digest()


def test_repr_never_shows_secret_material() -> None:
    """Proof and lease token stay out of reprs and therefore out of logs."""
    text = repr(request("renew", lease_id="lease-1", lease_token="token-secret-xyz"))
    assert "proof-secret-material" not in text and "token-secret-xyz" not in text


def test_non_mapping_is_invalid() -> None:
    """A non-mapping body is an invalid envelope."""
    assert _refused(["claim"]).code == "envelope.invalid"  # type: ignore[arg-type]
