"""T1 slice 1: opaque callable keys. Artifact strings never reach dynamic imports."""

from __future__ import annotations

import importlib

import pytest

from orama.graph.admission import (
    AdmissionRefused,
    CallableBinding,
    CallableRef,
    CallableRegistry,
)


def _node(state):  # pragma: no cover - never executed, only bound
    """Test helper: node."""
    return state


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


@pytest.mark.parametrize(
    "raw",
    [
        "os:system",  # import expression
        "os.path.join",  # dotted lookup
        "pkg.module:func",  # module:qualname form
        "a/b",  # path-like
        "Upper",  # no case folding
        " padded ",  # no trimming
        "",  # empty
        "x" * 65,  # over length bound
        "node\n",  # trailing newline must not slip through $
        "../escape",
        "node;rm",
        "ünïcode",
    ],
)
def test_malformed_keys_are_rejected_without_import(monkeypatch, raw):
    """Malformed keys are rejected without import."""
    def boom(*a, **k):
        """Test helper: boom."""
        raise AssertionError("dynamic import attempted")

    monkeypatch.setattr(importlib, "import_module", boom)
    with pytest.raises(AdmissionRefused):
        CallableRef.parse(raw)


def test_valid_keys_parse_and_round_trip():
    """Valid keys parse and round trip."""
    ref = CallableRef.parse("fold-totals_v2")
    assert str(ref) == "fold-totals_v2"
    assert CallableRef.parse(str(ref)) == ref


def test_non_string_keys_are_rejected():
    """Non string keys are rejected."""
    for raw in (None, 3, b"node", ("node",)):
        with pytest.raises(AdmissionRefused):
            CallableRef.parse(raw)  # type: ignore[arg-type]


def test_unknown_key_refuses_without_fallback():
    """Unknown key refuses without fallback."""
    reg = CallableRegistry.freeze({CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)})
    with pytest.raises(AdmissionRefused):
        reg.resolve(CallableRef.parse("unknown"))


def test_aliases_do_not_resolve():
    """Aliases do not resolve."""
    reg = CallableRegistry.freeze({CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)})
    for alias in ("known-", "known2", "KNOWN", "known "):
        with pytest.raises(AdmissionRefused):
            reg.resolve(alias)  # raw strings never resolve, only parsed refs


def test_registry_is_frozen_for_the_invocation():
    """Registry is frozen for the invocation."""
    source = {CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)}
    reg = CallableRegistry.freeze(source)
    source[CallableRef.parse("late")] = CallableBinding(_node, DIGEST_A)
    with pytest.raises(AdmissionRefused):
        reg.resolve(CallableRef.parse("late"))
    with pytest.raises(TypeError):
        reg.bindings[CallableRef.parse("late")] = CallableBinding(_node, DIGEST_A)  # type: ignore[index]


def test_changed_digest_refuses():
    """Changed digest refuses."""
    reg = CallableRegistry.freeze({CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)})
    assert reg.resolve(CallableRef.parse("known"), expected_digest=DIGEST_A) is _node
    with pytest.raises(AdmissionRefused):
        reg.resolve(CallableRef.parse("known"), expected_digest=DIGEST_B)


def test_binding_requires_callable_and_digest_shape():
    """Binding requires callable and digest shape."""
    with pytest.raises(AdmissionRefused):
        CallableBinding("not callable", DIGEST_A)  # type: ignore[arg-type]
    for bad in ("", "md5:" + "a" * 32, "sha256:" + "A" * 64, "sha256:" + "a" * 63, None):
        with pytest.raises(AdmissionRefused):
            CallableBinding(_node, bad)  # type: ignore[arg-type]


def test_resolution_never_calls_import_module(monkeypatch):
    """Resolution never calls import module."""
    def boom(*a, **k):
        """Test helper: boom."""
        raise AssertionError("dynamic import attempted")

    monkeypatch.setattr(importlib, "import_module", boom)
    reg = CallableRegistry.freeze({CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)})
    assert reg.resolve(CallableRef.parse("known")) is _node


def test_direct_construction_is_validated_too():
    """Direct construction is validated too."""
    with pytest.raises(AdmissionRefused):
        CallableRef("os:system")
    with pytest.raises(AdmissionRefused):
        CallableRef(None)  # type: ignore[arg-type]


def test_directly_constructed_registry_is_also_frozen():
    """Directly constructed registry is also frozen."""
    source = {CallableRef.parse("known"): CallableBinding(_node, DIGEST_A)}
    reg = CallableRegistry(source)
    source[CallableRef.parse("late")] = CallableBinding(_node, DIGEST_A)
    with pytest.raises(AdmissionRefused):
        reg.resolve(CallableRef.parse("late"))
    with pytest.raises(AdmissionRefused):
        CallableRegistry({"known": CallableBinding(_node, DIGEST_A)})  # type: ignore[dict-item]
