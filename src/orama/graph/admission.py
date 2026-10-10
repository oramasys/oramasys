"""T1 slice 1: opaque callable keys and a frozen, digest-bound callable registry.

A ``CallableRef`` is a registry key, never a Python import expression. Trusted application
construction binds each key to a callable and a reviewed artifact digest, then freezes the
mapping for one invocation. Resolution is a plain dictionary lookup: no import, no
``getattr`` walk, no case folding, no alias, no fallback. Anything else refuses.

This is not a sandbox for trusted code; it only guarantees artifact strings never reach
dynamic imports. Admission decisions (Phylax, Agate, Telos) are later T1 slices.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

# Lowercase ASCII token: letter first, then letters, digits, '-' or '_'; at most 64 chars.
# fullmatch (not match with '$') so a trailing newline cannot slip through.
_KEY = re.compile(r"[a-z][a-z0-9_-]{0,63}")
# Domain-tagged digest: only sha256, lowercase hex, exact length.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class AdmissionRefused(Exception):
    """Fail-closed refusal with a redacted, actionable reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CallableRef:
    """Opaque validated registry key. Construct only through :meth:`parse`."""

    key: str

    @classmethod
    def parse(cls, raw: object) -> CallableRef:
        if not isinstance(raw, str) or _KEY.fullmatch(raw) is None:
            raise AdmissionRefused("callable_ref.malformed")
        return cls(raw)

    def __str__(self) -> str:
        return self.key


@dataclass(frozen=True, slots=True)
class CallableBinding:
    """A callable bound to the digest of the reviewed artifact that provides it."""

    target: Callable[..., Any]
    artifact_digest: str

    def __post_init__(self) -> None:
        if not callable(self.target):
            raise AdmissionRefused("callable_binding.not_callable")
        if not isinstance(self.artifact_digest, str) or _DIGEST.fullmatch(self.artifact_digest) is None:
            raise AdmissionRefused("callable_binding.bad_digest")


@dataclass(frozen=True, slots=True)
class CallableRegistry:
    """Read-only key-to-binding map, frozen for one invocation."""

    bindings: Mapping[CallableRef, CallableBinding]

    @classmethod
    def freeze(cls, source: Mapping[CallableRef, CallableBinding]) -> CallableRegistry:
        copied: dict[CallableRef, CallableBinding] = {}
        for ref, binding in source.items():
            if not isinstance(ref, CallableRef) or not isinstance(binding, CallableBinding):
                raise AdmissionRefused("callable_registry.bad_entry")
            copied[ref] = binding
        return cls(MappingProxyType(copied))

    def resolve(self, ref: object, *, expected_digest: str | None = None) -> Callable[..., Any]:
        if not isinstance(ref, CallableRef):
            raise AdmissionRefused("callable_ref.not_parsed")
        binding = self.bindings.get(ref)
        if binding is None:
            raise AdmissionRefused("callable_ref.unknown")
        if expected_digest is not None and binding.artifact_digest != expected_digest:
            raise AdmissionRefused("callable_binding.digest_changed")
        return binding.target
