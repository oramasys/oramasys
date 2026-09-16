"""NIP-98 HTTP auth event verification (inline crypto via coincurve)."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from orama.auth.nip98.replay import ReplayCache


class Nip98Error(ValueError):
    """NIP-98 verification failure."""


@dataclass(frozen=True, slots=True)
class Nip98Result:
    pubkey: str
    event_id: str
    event: Mapping[str, Any]


_DEFAULT_REPLAY = ReplayCache()


def compute_event_id(event: Mapping[str, Any]) -> str:
    """NIP-01 event id = sha256 of compact serialized [0,pubkey,created_at,kind,tags,content]."""
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _tag_value(tags: list, name: str) -> str | None:
    for tag in tags:
        if isinstance(tag, (list, tuple)) and len(tag) >= 2 and tag[0] == name:
            return str(tag[1])
    return None


def _verify_schnorr(pubkey_hex: str, message_hex: str, sig_hex: str) -> bool:
    """BIP340 Schnorr verify over 32-byte message (event id)."""
    try:
        from coincurve import PublicKeyXOnly
    except ImportError as exc:
        raise Nip98Error("coincurve required for NIP-98 verify") from exc
    try:
        pubkey = bytes.fromhex(pubkey_hex)
        message = bytes.fromhex(message_hex)
        signature = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise Nip98Error("invalid hex in pubkey/id/sig") from exc
    if len(pubkey) != 32 or len(message) != 32 or len(signature) != 64:
        return False
    try:
        return PublicKeyXOnly(pubkey).verify(signature, message)
    except Exception:
        return False


def parse_nostr_authorization(header: str | None) -> dict[str, Any] | None:
    """Parse ``Authorization: Nostr <base64(event JSON)>``. None if not Nostr scheme."""
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "nostr":
        return None
    try:
        raw = base64.b64decode(parts[1].strip(), validate=False)
        event = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Nip98Error("malformed Nostr authorization") from exc
    if not isinstance(event, dict):
        raise Nip98Error("Nostr event must be an object")
    return event


def verify_nip98(
    *,
    authorization: str | None,
    method: str,
    url: str,
    body: bytes = b"",
    skew_sec: int = 60,
    require_payload: bool = False,
    now: int | None = None,
    replay: ReplayCache | None = None,
) -> Nip98Result:
    """Verify NIP-98 header; return pubkey on success; raise Nip98Error otherwise.

    If authorization is missing or not ``Nostr``, raises Nip98Error with
    ``not_applicable`` message so callers can fall through.
    """
    event = parse_nostr_authorization(authorization)
    if event is None:
        raise Nip98Error("not_applicable")

    kind = event.get("kind")
    if kind != 27235:
        raise Nip98Error("kind must be 27235")

    created_at = event.get("created_at")
    if not isinstance(created_at, int):
        raise Nip98Error("created_at must be int")
    ts = int(time.time()) if now is None else now
    if abs(ts - created_at) > skew_sec:
        raise Nip98Error("created_at outside skew window")

    tags = event.get("tags")
    if not isinstance(tags, list):
        raise Nip98Error("tags must be a list")

    u_tag = _tag_value(tags, "u")
    if u_tag != url:
        raise Nip98Error("u tag mismatch")

    method_tag = _tag_value(tags, "method")
    if method_tag != method:
        raise Nip98Error("method tag mismatch")

    payload_tag = _tag_value(tags, "payload")
    body_methods = {"POST", "PUT", "PATCH"}
    if require_payload and method.upper() in body_methods:
        if not payload_tag:
            raise Nip98Error("payload tag required")
    if payload_tag is not None:
        expected = hashlib.sha256(body).hexdigest()
        if payload_tag != expected:
            raise Nip98Error("payload hash mismatch")

    pubkey = event.get("pubkey")
    sig = event.get("sig")
    if not isinstance(pubkey, str) or not isinstance(sig, str):
        raise Nip98Error("pubkey/sig required")

    event_id = compute_event_id(event)
    claimed_id = event.get("id")
    if claimed_id is not None and claimed_id != event_id:
        raise Nip98Error("event id mismatch")

    cache = replay if replay is not None else _DEFAULT_REPLAY
    if cache.seen(event_id, now=float(ts)):
        raise Nip98Error("replay")
    if not _verify_schnorr(pubkey, event_id, sig):
        raise Nip98Error("bad signature")
    cache.remember(event_id, now=float(ts))

    return Nip98Result(pubkey=pubkey, event_id=event_id, event=event)
