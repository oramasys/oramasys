"""Real Ed25519ph verification of Phylax-signed issuer events (test-only adapter).

Oramasys source holds no cryptography, so the production ``SignatureVerifier`` adapter lives
outside ``src/orama``. This test-only adapter pins the scheme the issuer actually uses
(``docs/e1-c2-permit-contract-freeze.md`` FREEZE-CHOICE 5): Ed25519ph over the domain
``phylax-issuer-event-v1\\x00`` followed by the 64 ASCII hex characters of the event digest.
The signed events come from the vendored Phylax vector; flipped bytes must fail.
"""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

import pytest

nacl_bindings = pytest.importorskip("nacl.bindings")
nacl_exceptions = pytest.importorskip("nacl.exceptions")

from orama.graph.dispatch_anchor import AnchorRefused  # noqa: E402
from orama.graph.dispatch_attempts import SqliteAttemptStore  # noqa: E402
from tests.test_dispatch_anchor import TrustedKeys  # noqa: E402

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors" / "dispatch-permit-v1.json").read_text(encoding="utf-8")
)
EVENT_DOMAIN = b"phylax-issuer-event-v1\x00"
KEY_ID = VECTORS["issuer_key_id"]
PUBLIC_KEY = bytes.fromhex(VECTORS["public_key"])
EVENTS = VECTORS["events"]
HEX = "0123456789abcdef"


def _b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return b""


def _ph_verify(public_key: bytes, signature: bytes, *chunks: bytes) -> bool:
    state = nacl_bindings.crypto_sign_ed25519ph_state()
    for chunk in chunks:
        nacl_bindings.crypto_sign_ed25519ph_update(state, chunk)
    try:
        return bool(nacl_bindings.crypto_sign_ed25519ph_final_verify(state, signature, public_key))
    except (nacl_exceptions.BadSignatureError, nacl_exceptions.ValueError):
        return False


class Ed25519phEventVerifier:
    """Test adapter for ``SignatureVerifier.verify_event``; permits/finalizations are not used."""

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = keys

    def verify_event(self, key_id: str, digest: str, signature: str) -> bool:
        public = self._keys.get(key_id)
        raw = _b64url_decode(signature)
        if public is None or len(raw) != 64 or len(digest) != 64:
            return False
        return _ph_verify(public, raw, EVENT_DOMAIN, digest.encode("ascii"))

    def verify_permit(self, key_id: str, body: Any, signature: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def verify_finalization(self, key_id: str, body: Any, signature: str) -> bool:  # pragma: no cover
        raise NotImplementedError


VERIFIER = Ed25519phEventVerifier({KEY_ID: PUBLIC_KEY})


@pytest.mark.parametrize("event", EVENTS, ids=lambda e: f"v{e['version']}")
def test_phylax_signed_events_verify(event: dict[str, Any]) -> None:
    assert VERIFIER.verify_event(event["issuer_key_id"], event["event_digest"], event["signature"])


def test_every_flipped_signature_bit_fails() -> None:
    event = EVENTS[1]
    raw = bytearray(_b64url_decode(event["signature"]))
    assert len(raw) == 64
    for index in range(len(raw)):
        for bit in range(8):
            mutated = bytearray(raw)
            mutated[index] ^= 1 << bit
            text = base64.urlsafe_b64encode(bytes(mutated)).decode().rstrip("=")
            assert not VERIFIER.verify_event(KEY_ID, event["event_digest"], text), (index, bit)


def test_every_changed_digest_character_fails() -> None:
    event = EVENTS[1]
    digest = event["event_digest"]
    for index, char in enumerate(digest):
        swapped = HEX[(HEX.index(char) + 1) % 16]
        mutated = digest[:index] + swapped + digest[index + 1 :]
        assert not VERIFIER.verify_event(KEY_ID, mutated, event["signature"]), index


def test_wrong_key_id_wrong_key_and_malformed_signature_fail_closed() -> None:
    event = EVENTS[1]
    other_public = bytearray(PUBLIC_KEY)
    other_public[0] ^= 1
    assert not VERIFIER.verify_event("other-key", event["event_digest"], event["signature"])
    wrong_key = Ed25519phEventVerifier({KEY_ID: bytes(other_public)})
    assert not wrong_key.verify_event(KEY_ID, event["event_digest"], event["signature"])
    for bad in ("", "AAAA", "!!!!", event["signature"][:-2], event["signature"] + "AA"):
        assert not VERIFIER.verify_event(KEY_ID, event["event_digest"], bad)


def test_signature_without_the_event_domain_or_with_another_domain_fails() -> None:
    seed = bytes(range(32))
    public, secret = nacl_bindings.crypto_sign_seed_keypair(seed)
    digest = EVENTS[1]["event_digest"]
    verifier = Ed25519phEventVerifier({KEY_ID: public})

    def sign(*chunks: bytes) -> str:
        state = nacl_bindings.crypto_sign_ed25519ph_state()
        for chunk in chunks:
            nacl_bindings.crypto_sign_ed25519ph_update(state, chunk)
        sig = nacl_bindings.crypto_sign_ed25519ph_final_create(state, secret)
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    digest_bytes = digest.encode("ascii")
    assert verifier.verify_event(KEY_ID, digest, sign(EVENT_DOMAIN, digest_bytes))
    assert not verifier.verify_event(KEY_ID, digest, sign(digest_bytes))
    assert not verifier.verify_event(KEY_ID, digest, sign(b"phylax-dispatch-permit-v1\x00", digest_bytes))
    assert not verifier.verify_event(KEY_ID, digest, sign(EVENT_DOMAIN, bytes.fromhex(digest)))


def test_pure_ed25519_over_the_same_message_is_rejected() -> None:
    seed = bytes(range(32))
    public, secret = nacl_bindings.crypto_sign_seed_keypair(seed)
    digest = EVENTS[1]["event_digest"]
    pure = nacl_bindings.crypto_sign(EVENT_DOMAIN + digest.encode("ascii"), secret)[:64]
    text = base64.urlsafe_b64encode(pure).decode().rstrip("=")

    assert not Ed25519phEventVerifier({KEY_ID: public}).verify_event(KEY_ID, digest, text)


def test_bootstrap_anchor_accepts_a_real_phylax_signed_anchor_and_refuses_tampering(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    anchor = EVENTS[1]  # version 2: the first version that can be a pruned anchor
    keys = TrustedKeys(allowed={"issuer-vector": {KEY_ID}})
    now = datetime(2026, 10, 22, tzinfo=UTC)
    store = SqliteAttemptStore(tmp_path / "s" / "a.db")

    store.bootstrap_anchor("issuer-vector", anchor, VERIFIER, trusted_keys=keys, now=now)
    assert store.anchor_record("issuer-vector")["event_digest"] == anchor["event_digest"]

    flipped = dict(anchor, signature=anchor["signature"][:-3] + "AAA")
    fresh = SqliteAttemptStore(tmp_path / "t" / "b.db")
    with pytest.raises(AnchorRefused) as caught:
        fresh.bootstrap_anchor("issuer-vector", flipped, VERIFIER, trusted_keys=keys, now=now)
    assert caught.value.reason == "event_signature"
    assert fresh.anchor_record("issuer-vector") is None
