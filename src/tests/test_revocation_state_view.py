"""Consumer view of the issuer's signed public revocation state (decision D3).

The state vector is a golden file produced by Phylax's ``build_state``; the lookup vector is the
shared truth table that both the consumer's ``refusal_reason`` and the state view must reproduce.
The Ed25519ph adapter here is test-only: oramasys source holds no cryptography.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

nacl_bindings = pytest.importorskip("nacl.bindings")
nacl_exceptions = pytest.importorskip("nacl.exceptions")

from orama.graph import dispatch_revocations, revocation_state_view
from orama.graph.revocation_state_view import (
    CompositeRevocationLookup,
    RevocationStateFacts,
    SignedStateRevocationView,
    StateRefused,
    reason_from_facts,
    verify_state,
)

VECTOR_DIR = Path(__file__).parent / "vectors"
LOOKUP = json.loads((VECTOR_DIR / "revocation-lookup-v1.json").read_text(encoding="utf-8"))
GOLDEN = json.loads((VECTOR_DIR / "revocation-state-v1.json").read_text(encoding="utf-8"))
# Pinned digests of the vendored Phylax files; a silent edit breaks lockstep and fails here.
LOOKUP_SHA256 = "a0c180695a1d56dd6fe4546ef4d8be5f999d843f6044deb32bca4cef178f9f5b"
GOLDEN_SHA256 = "d9dbec453c67d1f9990b56bfc92b3606483a965b1e5b74c3283b647aa6436237"
STATE_DOMAIN = b"phylax-revocation-state-v1\x00"
SEED = b"1" * 32
PUBLIC_KEY = bytes.fromhex(GOLDEN["public_key"])
NOW = datetime(2026, 11, 2, 4, 0, 0, tzinfo=UTC)
ISSUER = "issuer-1"


def canonical(obj: Any) -> bytes:
    """Return Phylax's canonical JSON bytes."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def b64url_encode(raw: bytes) -> str:
    """Encode unpadded base64url."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(seed: bytes, body: dict) -> str:
    """Sign a state body with Ed25519ph under the state domain."""
    _public, secret = nacl_bindings.crypto_sign_seed_keypair(seed)
    state = nacl_bindings.crypto_sign_ed25519ph_state()
    nacl_bindings.crypto_sign_ed25519ph_update(state, STATE_DOMAIN)
    nacl_bindings.crypto_sign_ed25519ph_update(state, canonical(body))
    return b64url_encode(nacl_bindings.crypto_sign_ed25519ph_final_create(state, secret))


class Verifier:
    """Test-only StateSignatureVerifier over one public key."""

    def __init__(self, public_key: bytes = PUBLIC_KEY, key_id: str = "key-1") -> None:
        """Pin the trusted key."""
        self.public_key, self.key_id = public_key, key_id

    def verify_state(self, key_id: str, body: dict, signature: str) -> bool:
        """Verify under the state domain; unknown key ids fail."""
        if key_id != self.key_id:
            return False
        try:
            state = nacl_bindings.crypto_sign_ed25519ph_state()
            nacl_bindings.crypto_sign_ed25519ph_update(state, STATE_DOMAIN)
            nacl_bindings.crypto_sign_ed25519ph_update(state, canonical(body))
            return bool(nacl_bindings.crypto_sign_ed25519ph_final_verify(
                state, b64url_decode(signature), self.public_key))
        except (nacl_exceptions.BadSignatureError, ValueError):
            return False


class Source:
    """State source returning fixed bytes, None, or raising."""

    def __init__(self, data: bytes | None = None, error: Exception | None = None) -> None:
        """Choose what ``read`` yields."""
        self.data, self.error = data, error

    def read(self) -> bytes | None:
        """Return the bytes, None, or raise."""
        if self.error is not None:
            raise self.error
        return self.data


def stamp(moment: datetime) -> str:
    """Encode the fixed six-digit UTC wire timestamp."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def state_bytes(case: dict | None = None, **overrides: Any) -> bytes:
    """Build and sign a state from a vector case with the test seed."""
    revoked = (case or {}).get("revoked", [])
    cascades = (case or {}).get("cascades", [])
    body = {
        "schema_version": 1, "issuer_id": ISSUER, "head_version": len(revoked) + len(cascades) or 1,
        "head_event_digest": "d" * 64, "generated_at": stamp(NOW),
        "issuer_revoked": any(k == "issuer" and s == ISSUER for k, s in revoked),
        "revoked_grants": sorted({s for k, s in revoked if k == "grant"}),
        "revoked_approvals": sorted({s for k, s in revoked if k == "approval"}),
        "cascades": [
            {"version": i + 1, "approval_id": ap, "issuer_authority_version": 1, "grant_ids": sorted(gs)}
            for i, (ap, gs) in enumerate(cascades)
        ],
        **overrides,
    }
    return canonical({"body": body, "signature": sign(SEED, body), "issuer_key_id": "key-1"})


def view(raw: bytes | None, **kwargs: Any) -> SignedStateRevocationView:
    """Build a view over fixed bytes at NOW."""
    return SignedStateRevocationView(
        Source(raw), Verifier(crypto_public(SEED)), issuer_id=ISSUER, clock=lambda: NOW, **kwargs)


def crypto_public(seed: bytes) -> bytes:
    """Return the public key for a seed."""
    return nacl_bindings.crypto_sign_seed_keypair(seed)[0]


def test_vendored_vectors_are_pinned() -> None:
    """The vendored Phylax files are byte-identical to the reviewed ones."""
    for name, expected in (("revocation-lookup-v1.json", LOOKUP_SHA256), ("revocation-state-v1.json", GOLDEN_SHA256)):
        assert hashlib.sha256((VECTOR_DIR / name).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("case", LOOKUP["cases"], ids=lambda c: c["name"])
def test_consumer_refusal_reason_and_state_view_agree_with_the_shared_table(case) -> None:
    """Both consumer paths reproduce every row of the shared truth table."""
    db = sqlite3.connect(":memory:")
    for statement in dispatch_revocations.REVOCATION_SCHEMA:
        db.execute(statement)
    version = 0
    for kind, subject in case["revoked"]:
        version += 1
        dispatch_revocations.record(db, ISSUER, {
            "version": version, "kind": "revocation",
            "body": {"subject_kind": kind, "subject_id": subject}})
    for index, (approval, grants) in enumerate(case["cascades"], start=1):
        version += 1
        dispatch_revocations.record(db, ISSUER, {
            "version": version, "kind": "cascade",
            "body": {"approval_id": approval, "grant_ids": sorted(grants), "issuer_authority_version": index}})
    assert dispatch_revocations.refusal_reason(db, ISSUER, case["grant"], case["approval_ref"]) == case["expect"]
    assert view(state_bytes(case)).reason(case["grant"], case["approval_ref"]) == case["expect"]


def test_golden_state_from_phylax_verifies_and_reads_correctly() -> None:
    """A state produced by Phylax's real builder verifies under the consumer's port."""
    raw = GOLDEN["state"].encode("utf-8")
    now = datetime.strptime(GOLDEN["generated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    facts = verify_state(raw, verifier=Verifier(), issuer_id=GOLDEN["issuer_id"], now=now)
    assert facts.head_version == 3 and facts.head_event_digest == GOLDEN["events"][-1]["event_digest"]
    assert reason_from_facts(facts, "g-revoked", "") == "grant_revoked"
    assert reason_from_facts(facts, "g-ok", "ap-revoked") == "approval_revoked"
    assert reason_from_facts(facts, "g-cascaded-2", "x") == "cascade_listed"
    assert reason_from_facts(facts, "g-ok", "x") is None


def test_golden_state_fails_when_any_byte_or_the_clock_is_wrong() -> None:
    """Tampering, a stale clock or a different trusted key all refuse."""
    raw = GOLDEN["state"].encode("utf-8")
    now = datetime.strptime(GOLDEN["generated_at"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    kwargs = {"verifier": Verifier(), "issuer_id": GOLDEN["issuer_id"], "now": now}
    with pytest.raises(StateRefused) as stale:
        verify_state(raw, **{**kwargs, "now": now + timedelta(seconds=61)})
    assert stale.value.code == "state.stale"
    with pytest.raises(StateRefused) as other_key:
        verify_state(raw, **{**kwargs, "verifier": Verifier(crypto_public(b"9" * 32))})
    assert other_key.value.code == "state.signature"
    document = json.loads(raw)
    document["body"]["revoked_grants"] = []
    with pytest.raises(StateRefused) as tampered:
        verify_state(canonical(document), **kwargs)
    assert tampered.value.code == "state.signature"


@pytest.mark.parametrize("raw,code", [
    (None, "state.unavailable"),
    (b"not json", "state.malformed"),
    (b"{}", "state.malformed"),
    (state_bytes() + b" ", "state.malformed"),
    (state_bytes(issuer_id="issuer-2"), "state.issuer_mismatch"),
    (state_bytes(generated_at=stamp(NOW - timedelta(seconds=61))), "state.stale"),
    (state_bytes(generated_at=stamp(NOW + timedelta(seconds=10))), "state.stale"),
    (state_bytes(revoked_grants=["b", "a"]), "state.malformed"),
    (state_bytes(head_version=0, head_event_digest="d" * 64), "state.malformed"),
    (state_bytes(issuer_revoked="no"), "state.malformed"),
    (state_bytes(extra=1), "state.malformed"),
])
def test_every_unusable_state_is_treated_as_revoked(raw, code) -> None:
    """Absent, malformed, foreign, stale or invalid states revoke everything, never nothing."""
    lookup = view(raw)
    assert lookup.revoked(grant_id="g1", issuer_id=ISSUER) is True
    assert lookup.refusal == code


def test_unsigned_and_wrong_issuer_queries_are_revoked() -> None:
    """A bad signature, or a query for another issuer, revokes."""
    document = json.loads(state_bytes())
    document["signature"] = sign(b"9" * 32, document["body"])
    lookup = view(canonical(document))
    assert lookup.revoked(grant_id="g1", issuer_id=ISSUER) and lookup.refusal == "state.signature"
    good = view(state_bytes())
    assert good.revoked(grant_id="g1", issuer_id=ISSUER) is False
    assert good.revoked(grant_id="g1", issuer_id="issuer-2") is True and good.refusal == "state.issuer_mismatch"


def test_source_faults_fail_closed() -> None:
    """A source that raises never reads as 'nothing revoked'."""
    lookup = SignedStateRevocationView(
        Source(error=OSError("boom")), Verifier(), issuer_id=ISSUER, clock=lambda: NOW)
    assert lookup.revoked(grant_id="g1", issuer_id=ISSUER) is True and lookup.refusal == "state.unavailable"


def test_state_behind_or_forking_the_acknowledged_head_is_refused() -> None:
    """A rolled-back state, or a different digest at the acknowledged version, is refused."""
    raw = state_bytes({"revoked": [["grant", "g9"]], "cascades": []})
    behind = view(raw, acknowledged_head=lambda: (5, "d" * 64))
    assert behind.revoked(grant_id="g1", issuer_id=ISSUER) and behind.refusal == "state.behind_acknowledged"
    fork = view(raw, acknowledged_head=lambda: (1, "e" * 64))
    assert fork.revoked(grant_id="g1", issuer_id=ISSUER) and fork.refusal == "state.head_conflict"
    same = view(raw, acknowledged_head=lambda: (1, "d" * 64))
    assert same.revoked(grant_id="g1", issuer_id=ISSUER) is False


def test_undeclared_approval_is_conservative_through_the_port() -> None:
    """Without an approval resolver an approval revocation refuses every grant; with one it is exact."""
    raw = state_bytes({"revoked": [["approval", "ap9"]], "cascades": []})
    assert view(raw).revoked(grant_id="g1", issuer_id=ISSUER) is True
    exact = view(raw, approval_ref_for=lambda grant: "ap1")
    assert exact.revoked(grant_id="g1", issuer_id=ISSUER) is False
    assert view(raw, approval_ref_for=lambda grant: "ap9").revoked(grant_id="g1", issuer_id=ISSUER) is True


def test_composite_is_revoked_if_any_member_is_or_fails() -> None:
    """Union semantics: any revoking or raising member revokes."""
    class Fixed:
        def __init__(self, answer):
            self.answer = answer

        def revoked(self, *, grant_id, issuer_id):
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer

    assert CompositeRevocationLookup(Fixed(False), Fixed(False)).revoked(grant_id="g", issuer_id=ISSUER) is False
    assert CompositeRevocationLookup(Fixed(False), Fixed(True)).revoked(grant_id="g", issuer_id=ISSUER) is True
    assert CompositeRevocationLookup(Fixed(False), Fixed(RuntimeError())).revoked(grant_id="g", issuer_id=ISSUER) is True
    with pytest.raises(ValueError):
        CompositeRevocationLookup()


def test_refusal_codes_are_closed_and_the_module_holds_no_cryptography() -> None:
    """Unknown codes are rejected and the source imports no crypto library."""
    with pytest.raises(ValueError):
        StateRefused("state.invented")
    tree = ast.parse(inspect.getsource(revocation_state_view))
    imported = {
        (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) else alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [node])
    }
    assert not imported & {"nacl", "cryptography", "hashlib", "hmac"}
    assert isinstance(RevocationStateFacts(0, "0" * 64, False, frozenset(), frozenset(), frozenset()), RevocationStateFacts)
    with pytest.raises(ValueError):
        SignedStateRevocationView(Source(), Verifier(), issuer_id=" ", clock=lambda: NOW)
