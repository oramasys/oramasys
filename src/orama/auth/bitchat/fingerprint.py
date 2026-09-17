"""BitChat-compatible Noise identity fingerprints.

BitChat: stable identity = SHA-256 of the Noise static Curve25519 public key.
Legacy mesh peer ID = first 8 bytes of that digest (16 hex chars).
Binding subject = full 64-hex fingerprint, never the short peer ID alone.
"""
from __future__ import annotations

import hashlib


def noise_fingerprint(static_public: bytes) -> str:
    if len(static_public) != 32:
        raise ValueError("Noise static public key must be 32 bytes")
    return hashlib.sha256(static_public).hexdigest()


def mesh_peer_id(static_public: bytes | None = None, *, fingerprint: str | None = None) -> str:
    """First 8 bytes of the fingerprint as 16 hex characters."""
    if fingerprint is None:
        if static_public is None:
            raise ValueError("static_public or fingerprint required")
        fingerprint = noise_fingerprint(static_public)
    fingerprint = fingerprint.lower()
    if len(fingerprint) != 64:
        raise ValueError("fingerprint must be 64 hex chars")
    return fingerprint[:16]
