"""The claim request envelope: doc 68 section 4.2 with doc 69 section 7's claim panel.

Parsing is strict: required fields have no default, unknown fields are refused and every
value is validated before the controller looks anything up. Projections (IC-28) must equal
their canonical values exactly and are checked here, before capability or state lookup.

The request digest is SHA-256 over canonical JSON of the covered fields. It excludes the
capability proof (rotating credential material, never stored) and the projections (equal by
construction); it covers the lease token only through the token's own SHA-256.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from orama.orchestrator_controller.refusals import ClaimRefused

Operation = Literal["claim", "renew", "complete", "release", "fail"]
OPERATIONS: tuple[str, ...] = ("claim", "renew", "complete", "release", "fail")
LEASE_OPERATIONS: frozenset[str] = frozenset({"renew", "complete", "release", "fail"})
FAILURE_CLASSES: frozenset[str] = frozenset({"worker_error", "source_mismatch", "abandoned", "timeout"})
LINEAGE_KEYS: frozenset[str] = frozenset(
    {"on_behalf_of", "prior_agent", "prior_agent_status", "takeover", "superseded_ref"}
)
SCHEMA_VERSION = "1"

_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SOURCE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}")
_BASE_SHA = re.compile(r"[0-9a-f]{7,40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")
_TOPOLOGY = re.compile(
    r"""
    ^[/~]                                         # absolute or home-relative path
    | \\                                        # any backslash (Windows path)
    | /(?:home|Users|root|tmp|var|private)/       # embedded POSIX path segments
    | ^[A-Za-z]:                                  # drive letter
    | (?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9.])  # IPv4 literal
    | ::                                          # IPv6 literal
    | [A-Za-z0-9-]:[0-9]{1,5}(?![0-9])            # host:port
    | (?:^|[^A-Za-z0-9])localhost(?:$|[^A-Za-z0-9])
    | \.(?:local|lan|internal|home|localdomain)(?:$|[^A-Za-z0-9-])  # local host suffixes
    """,
    re.IGNORECASE | re.VERBOSE,
)

_REQUIRED = (
    "schema_version",
    "operation",
    "task_id",
    "principal",
    "idempotency_key",
    "expected_task_version",
    "source_ref",
    "expected_base_sha",
)
_OPTIONAL = (
    "capability_proof",
    "lease_id",
    "lease_token",
    "result_digest",
    "failure_class",
    "lineage",
    "correlation_task_id",
    "actor_principal_id",
)
_ALLOWED = frozenset(_REQUIRED + _OPTIONAL)


def contains_topology(text: str) -> bool:
    """Return whether ``text`` looks like a local path, IP literal, port or local hostname.

    This is a defense-in-depth scan (IC-22), not a proof: an arbitrary bare hostname cannot
    be distinguished from an opaque label.
    """
    return _TOPOLOGY.search(text) is not None


def validate_opaque_id(value: object, name: str) -> str:
    """Return ``value`` when it is an opaque identifier; raise ``ValueError`` otherwise.

    Opaque identifiers have no path separators, colons, whitespace or leading punctuation,
    and must not look like topology (IP literal, ``localhost``, local host suffix), so a
    local path, ``host:port`` or hostname fragment cannot enter the store (IC-22).
    """
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None or contains_topology(value):
        raise ValueError(f"{name} must be an opaque identifier")
    return value


def validate_source_ref(value: object) -> str:
    """Return ``value`` when it is an opaque reviewed source ref; raise ``ValueError`` otherwise."""
    if (
        not isinstance(value, str)
        or _SOURCE_REF.fullmatch(value) is None
        or ".." in value
        or "//" in value
    ):
        raise ValueError("source_ref must be an opaque reviewed ref")
    return value


def validate_base_sha(value: object) -> str:
    """Return ``value`` when it is 7 to 40 lowercase hex (doc 69 section 6)."""
    if not isinstance(value, str) or _BASE_SHA.fullmatch(value) is None:
        raise ValueError("expected_base_sha must be 7 to 40 lowercase hex characters")
    return value


def validate_digest(value: object, name: str) -> str:
    """Return ``value`` when it is a 64-character lowercase hex SHA-256 digest."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase hex SHA-256 digest")
    return value


def canonical_json(value: object) -> str:
    """Serialize ``value`` deterministically (sorted keys, no whitespace, ASCII only)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    """Return the lowercase hex SHA-256 of ``text`` encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _lineage(value: object) -> tuple[tuple[str, str | bool], ...] | None:
    """Validate an optional lineage mapping into a sorted, frozen tuple of items."""
    if value is None:
        return None
    if not isinstance(value, Mapping) or not value:
        raise ValueError("lineage must be a non-empty mapping")
    items: list[tuple[str, str | bool]] = []
    for key, item in value.items():
        if key not in LINEAGE_KEYS:
            raise ValueError("lineage carries an unknown key")
        if key == "takeover":
            if not isinstance(item, bool):
                raise ValueError("lineage.takeover must be a boolean")
            items.append((key, item))
        else:
            items.append((key, validate_opaque_id(item, f"lineage.{key}")))
    return tuple(sorted(items))


@dataclass(frozen=True, slots=True)
class ClaimRequest:
    """One validated, immutable controller mutation request.

    ``capability_proof`` and ``lease_token`` are excluded from ``repr`` so they cannot reach
    logs through formatting. Construct instances through ``from_mapping``.
    """

    schema_version: str
    operation: Operation
    task_id: str
    principal: str
    idempotency_key: str
    expected_task_version: int
    source_ref: str
    expected_base_sha: str
    capability_proof: str | None = field(default=None, repr=False)
    lease_id: str | None = None
    lease_token: str | None = field(default=None, repr=False)
    result_digest: str | None = None
    failure_class: str | None = None
    lineage: tuple[tuple[str, str | bool], ...] | None = None

    @classmethod
    def from_mapping(cls, body: Mapping[str, object]) -> ClaimRequest:
        """Validate a raw request body; refuse ``400`` for any structural defect.

        Projection mismatches (IC-28) refuse with ``envelope.projection_mismatch``; every
        other defect refuses with ``envelope.invalid``. Nothing is looked up here.
        """
        try:
            parsed = cls._parse(body)
        except ValueError as error:
            raise ClaimRefused("envelope.invalid") from error
        for projection, canonical in (
            ("correlation_task_id", parsed.task_id),
            ("actor_principal_id", parsed.principal),
        ):
            if projection in body and body[projection] != canonical:
                raise ClaimRefused("envelope.projection_mismatch")
        return parsed

    @classmethod
    def _parse(cls, body: Mapping[str, object]) -> ClaimRequest:
        """Do the field-by-field validation; raise ``ValueError`` on the first defect."""
        if not isinstance(body, Mapping):
            raise ValueError("request body must be a mapping")
        unknown = set(body) - _ALLOWED
        if unknown:
            raise ValueError("request carries unknown fields")
        missing = [name for name in _REQUIRED if name not in body]
        if missing:
            raise ValueError("request is missing required fields")
        if body["schema_version"] != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        operation = body["operation"]
        if operation not in OPERATIONS:
            raise ValueError("unknown operation")
        version = body["expected_task_version"]
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError("expected_task_version must be a positive integer")
        proof = body.get("capability_proof")
        if proof is not None and (not isinstance(proof, str) or not proof):
            raise ValueError("capability_proof must be a non-empty string when present")
        for projection in ("correlation_task_id", "actor_principal_id"):
            if projection in body:
                validate_opaque_id(body[projection], projection)
        lease_id = body.get("lease_id")
        lease_token = body.get("lease_token")
        if operation in LEASE_OPERATIONS:
            validate_opaque_id(lease_id, "lease_id")
            if not isinstance(lease_token, str) or _TOKEN.fullmatch(lease_token) is None:
                raise ValueError("lease_token must be an opaque token")
        elif lease_id is not None or lease_token is not None:
            raise ValueError("claim must not present a lease")
        result_digest = body.get("result_digest")
        if operation == "complete":
            validate_digest(result_digest, "result_digest")
        elif result_digest is not None:
            raise ValueError("result_digest belongs to complete only")
        failure_class = body.get("failure_class")
        if operation == "fail":
            if failure_class not in FAILURE_CLASSES:
                raise ValueError("failure_class is not in the closed vocabulary")
        elif failure_class is not None:
            raise ValueError("failure_class belongs to fail only")
        return cls(
            schema_version=SCHEMA_VERSION,
            operation=operation,  # type: ignore[arg-type]
            task_id=validate_opaque_id(body["task_id"], "task_id"),
            principal=validate_opaque_id(body["principal"], "principal"),
            idempotency_key=validate_opaque_id(body["idempotency_key"], "idempotency_key"),
            expected_task_version=version,
            source_ref=validate_source_ref(body["source_ref"]),
            expected_base_sha=validate_base_sha(body["expected_base_sha"]),
            capability_proof=proof,  # type: ignore[arg-type]
            lease_id=lease_id,  # type: ignore[arg-type]
            lease_token=lease_token,  # type: ignore[arg-type]
            result_digest=result_digest,  # type: ignore[arg-type]
            failure_class=failure_class,  # type: ignore[arg-type]
            lineage=_lineage(body.get("lineage")),
        )

    def lineage_dict(self) -> dict[str, str | bool] | None:
        """Return the validated lineage as a plain mapping, or ``None`` when absent."""
        return None if self.lineage is None else dict(self.lineage)

    def request_digest(self) -> str:
        """Return the canonical claim-scope request digest (IC-12, IC-13)."""
        covered = {
            "schema_version": self.schema_version,
            "operation": self.operation,
            "task_id": self.task_id,
            "principal": self.principal,
            "idempotency_key": self.idempotency_key,
            "expected_task_version": self.expected_task_version,
            "source_ref": self.source_ref,
            "expected_base_sha": self.expected_base_sha,
            "lease_id": self.lease_id,
            "lease_token_digest": None if self.lease_token is None else sha256_hex(self.lease_token),
            "result_digest": self.result_digest,
            "failure_class": self.failure_class,
            "lineage": self.lineage_dict(),
        }
        return sha256_hex(canonical_json(covered))
