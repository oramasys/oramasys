"""The sealed command envelope for the inert driver (CONTRACT section 5; DRAFT).

The envelope is canonical JSON with exactly six members::

    {"v":1,"attempt_id":..,"operation_digest":"sha256:..","target":"inert://simulation",
     "epoch":<int>,"expires_at":"<six-digit UTC>"}

plus its sha256. ``open_envelope`` accepts only those exact bytes: any other key, order, spacing,
duplicate key, type, target or digest is refused. There is no field that carries a command, so the
driver has nothing to execute: it never runs text, a shell or a provider call.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from orama.graph.dispatch_consumer_wire import (
    WireError,
    canonical_bytes,
    is_canonical_identifier,
    parse_timestamp,
)

INERT_TARGET: Final = "inert://simulation"
ENVELOPE_VERSION: Final = 1
MAX_ENVELOPE_BYTES: Final = 4096
_KEYS: Final = frozenset({"v", "attempt_id", "operation_digest", "target", "epoch", "expires_at"})
_DIGEST_RE: Final = re.compile(r"sha256:[0-9a-f]{64}")


class EnvelopeRefused(Exception):
    """The envelope was refused; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str) -> None:
        """Store the stable refusal reason."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class SealedEnvelope:
    """A validated envelope with the exact bytes and digest it was sealed as."""

    attempt_id: str
    operation_digest: str
    target: str
    epoch: int
    expires_at: datetime
    raw: bytes
    digest: str


def _stamp(moment: datetime) -> str:
    """Return the six-digit UTC wire text for an aware datetime."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise EnvelopeRefused("envelope_expiry_invalid")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def digest_of(raw: bytes) -> str:
    """Return ``sha256:<hex>`` of the exact envelope bytes."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def seal(
    attempt_id: str, operation_digest: str, epoch: int, expires_at: datetime,
    target: str = INERT_TARGET,
) -> SealedEnvelope:
    """Build the canonical envelope bytes and digest for the given tuple, validating it first."""
    body = {
        "v": ENVELOPE_VERSION, "attempt_id": attempt_id, "operation_digest": operation_digest,
        "target": target, "epoch": epoch, "expires_at": _stamp(expires_at),
    }
    try:
        raw = canonical_bytes(body)
    except WireError as error:
        raise EnvelopeRefused("envelope_not_canonical") from error
    return open_envelope(raw, digest_of(raw))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys, which different parsers would resolve differently."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    """Reject NaN and the infinities, which are not canonical JSON."""
    raise ValueError(name)


def open_envelope(raw: bytes | str, digest: str) -> SealedEnvelope:
    """Validate ``raw`` against ``digest`` and the six-member contract; refuse anything else."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not isinstance(data, (bytes, bytearray)) or not 2 <= len(data) <= MAX_ENVELOPE_BYTES:
        raise EnvelopeRefused("envelope_size")
    data = bytes(data)
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest) or digest != digest_of(data):
        raise EnvelopeRefused("envelope_digest_mismatch")
    try:
        parsed = json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, ValueError):
        raise EnvelopeRefused("envelope_malformed") from None
    if not isinstance(parsed, dict) or set(parsed) != _KEYS:
        raise EnvelopeRefused("envelope_fields")
    try:
        if canonical_bytes(parsed) != data:
            raise EnvelopeRefused("envelope_not_canonical")
    except WireError:
        raise EnvelopeRefused("envelope_not_canonical") from None
    version, epoch = parsed["v"], parsed["epoch"]
    if type(version) is not int or version != ENVELOPE_VERSION:
        raise EnvelopeRefused("envelope_version")
    if not is_canonical_identifier(parsed["attempt_id"]):
        raise EnvelopeRefused("envelope_attempt_id")
    operation = parsed["operation_digest"]
    if not isinstance(operation, str) or not _DIGEST_RE.fullmatch(operation):
        raise EnvelopeRefused("envelope_operation_digest")
    if parsed["target"] != INERT_TARGET:
        raise EnvelopeRefused("envelope_target")
    if type(epoch) is not int or epoch < 1:
        raise EnvelopeRefused("envelope_epoch")
    try:
        expires_at = parse_timestamp(parsed["expires_at"])
    except WireError:
        raise EnvelopeRefused("envelope_expiry_invalid") from None
    return SealedEnvelope(
        attempt_id=parsed["attempt_id"], operation_digest=operation, target=INERT_TARGET,
        epoch=epoch, expires_at=expires_at, raw=data, digest=digest,
    )
