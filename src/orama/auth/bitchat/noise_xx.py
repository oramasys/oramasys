"""Noise_XX_25519_ChaChaPoly_SHA256 handshake (BitChat session pattern).

Inline implementation of the Noise Protocol Framework XX pattern used by
BitChat for mutual authentication of static X25519 keys. Does not vendor
the Swift/Android mesh stack. Local secrets remain HTTP/gossip root.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
DHLEN = 32
HASHLEN = 32
MACLEN = 16
PROXIMITY_LABEL = b"orama-bitchat-proximity-v1"


class NoiseError(ValueError):
    """Handshake or transport failure."""


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf(chaining_key: bytes, input_key_material: bytes, num_outputs: int) -> tuple[bytes, ...]:
    temp_key = _hmac(chaining_key, input_key_material)
    output1 = _hmac(temp_key, b"\x01")
    if num_outputs == 1:
        return (output1,)
    output2 = _hmac(temp_key, output1 + b"\x02")
    if num_outputs == 2:
        return (output1, output2)
    output3 = _hmac(temp_key, output2 + b"\x03")
    return (output1, output2, output3)


def _dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytes:
    pub = X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


def _public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _nonce(n: int) -> bytes:
    return b"\x00" * 4 + int(n).to_bytes(8, "little")


@dataclass
class NoiseKeyPair:
    private: X25519PrivateKey
    public: bytes

    @classmethod
    def generate(cls) -> "NoiseKeyPair":
        priv = X25519PrivateKey.generate()
        return cls(private=priv, public=_public_bytes(priv))

    @classmethod
    def from_private_bytes(cls, secret: bytes) -> "NoiseKeyPair":
        if len(secret) != 32:
            raise ValueError("X25519 private key must be 32 bytes")
        priv = X25519PrivateKey.from_private_bytes(secret)
        return cls(private=priv, public=_public_bytes(priv))


class _CipherState:
    def __init__(self) -> None:
        self.k: bytes | None = None
        self.n: int = 0

    def initialize_key(self, key: bytes | None) -> None:
        self.k = key
        self.n = 0

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        ct = ChaCha20Poly1305(self.k).encrypt(_nonce(self.n), plaintext, ad)
        self.n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        try:
            pt = ChaCha20Poly1305(self.k).decrypt(_nonce(self.n), ciphertext, ad)
        except Exception as exc:
            raise NoiseError("decrypt failed") from exc
        self.n += 1
        return pt


class _SymmetricState:
    def __init__(self) -> None:
        if len(PROTOCOL_NAME) == HASHLEN:
            h = PROTOCOL_NAME
        else:
            h = hashlib.sha256(PROTOCOL_NAME).digest()
        self.h = h
        self.ck = h
        self.cs = _CipherState()

    def mix_hash(self, data: bytes) -> None:
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = _hkdf(self.ck, input_key_material, 2)
        self.cs.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cs.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cs.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[_CipherState, _CipherState]:
        k1, k2 = _hkdf(self.ck, b"", 2)
        c1, c2 = _CipherState(), _CipherState()
        c1.initialize_key(k1)
        c2.initialize_key(k2)
        return c1, c2


class NoiseXXSession:
    """Interactive Noise XX handshake then transport encrypt/decrypt."""

    def __init__(self, *, initiator: bool, static: NoiseKeyPair, prologue: bytes = b"") -> None:
        self.initiator = initiator
        self.static = static
        self.ephemeral = NoiseKeyPair.generate()
        self.ss = _SymmetricState()
        self.ss.mix_hash(prologue)
        self._step = 0
        self.remote_e: bytes | None = None
        self.remote_static: bytes | None = None
        self._send: _CipherState | None = None
        self._recv: _CipherState | None = None

    @property
    def complete(self) -> bool:
        return self._send is not None

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.initiator:
            if self._step == 0:
                buf = self.ephemeral.public
                self.ss.mix_hash(self.ephemeral.public)
                buf += self.ss.encrypt_and_hash(payload)
                self._step = 1
                return buf
            if self._step == 2:
                if self.remote_static is None:
                    raise NoiseError("missing remote static")
                buf = self.ss.encrypt_and_hash(self.static.public)
                self.ss.mix_key(_dh(self.static.private, self.remote_e))
                buf += self.ss.encrypt_and_hash(payload)
                self._split()
                self._step = 3
                return buf
        else:
            if self._step == 1:
                buf = self.ephemeral.public
                self.ss.mix_hash(self.ephemeral.public)
                self.ss.mix_key(_dh(self.ephemeral.private, self.remote_e))
                buf += self.ss.encrypt_and_hash(self.static.public)
                self.ss.mix_key(_dh(self.static.private, self.remote_e))
                buf += self.ss.encrypt_and_hash(payload)
                self._step = 2
                return buf
        raise NoiseError("write_message at invalid handshake step")

    def read_message(self, message: bytes) -> bytes:
        if self.initiator:
            if self._step == 1:
                if len(message) < DHLEN:
                    raise NoiseError("short handshake message")
                self.remote_e = message[:DHLEN]
                rest = message[DHLEN:]
                self.ss.mix_hash(self.remote_e)
                self.ss.mix_key(_dh(self.ephemeral.private, self.remote_e))
                if len(rest) < DHLEN + MACLEN:
                    raise NoiseError("short handshake message")
                self.remote_static = self.ss.decrypt_and_hash(rest[: DHLEN + MACLEN])
                rest = rest[DHLEN + MACLEN :]
                self.ss.mix_key(_dh(self.ephemeral.private, self.remote_static))
                payload = self.ss.decrypt_and_hash(rest)
                self._step = 2
                return payload
        else:
            if self._step == 0:
                if len(message) < DHLEN:
                    raise NoiseError("short handshake message")
                self.remote_e = message[:DHLEN]
                rest = message[DHLEN:]
                self.ss.mix_hash(self.remote_e)
                payload = self.ss.decrypt_and_hash(rest)
                self._step = 1
                return payload
            if self._step == 2:
                if len(message) < DHLEN + MACLEN:
                    raise NoiseError("short handshake message")
                self.remote_static = self.ss.decrypt_and_hash(message[: DHLEN + MACLEN])
                rest = message[DHLEN + MACLEN :]
                self.ss.mix_key(_dh(self.ephemeral.private, self.remote_static))
                payload = self.ss.decrypt_and_hash(rest)
                self._split()
                self._step = 3
                return payload
        raise NoiseError("read_message at invalid handshake step")

    def _split(self) -> None:
        c1, c2 = self.ss.split()
        if self.initiator:
            self._send, self._recv = c1, c2
        else:
            self._send, self._recv = c2, c1

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        if self._send is None:
            raise NoiseError("handshake incomplete")
        return self._send.encrypt_with_ad(ad, plaintext)

    def decrypt(self, ciphertext: bytes, ad: bytes = b"") -> bytes:
        if self._recv is None:
            raise NoiseError("handshake incomplete")
        return self._recv.decrypt_with_ad(ad, ciphertext)
