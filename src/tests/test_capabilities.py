"""R0-2 capability record reader and startup refusal matrix (DRAFT; no bit is ever enabled here)."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from orama.api.capabilities import (
    CAPABILITY_BITS,
    CapabilityConfig,
    StartupRefused,
    capability_config_from_environ,
    enforce_startup_matrix,
    read_capability_record,
    record_digest,
)
from orama.api.server import create_app

BIN = "sha256:" + "a" * 64
CFG = "sha256:" + "b" * 64


def make_record(**bits: bool) -> dict[str, Any]:
    """Return a well-formed record with every bit false except those named in ``bits``."""
    capabilities = {name: False for name in CAPABILITY_BITS}
    capabilities.update(bits)
    return {
        "schema": "orama-capability-record/v1",
        "record_id": "rec-0001",
        "issued_at": "2026-10-25T00:00:00Z",
        "issuer": "control-plane-test",
        "capabilities": capabilities,
        "binds": {"binary_digest": BIN, "config_digest": CFG},
        "signature": None,
    }


class Signer:
    """Injected operator-signature verifier double; the repository wires no real one."""

    def __init__(self, ok: bool = True, error: bool = False) -> None:
        """Script the answer, or raise to model an unavailable verifier."""
        self.ok, self.error, self.seen = ok, error, []

    def verify(self, record_digest: str, signature: str) -> bool:
        """Record the call and answer as scripted."""
        self.seen.append((record_digest, signature))
        if self.error:
            raise RuntimeError("signer unavailable")
        return self.ok


def signed(**bits: bool) -> dict[str, Any]:
    """Return a record with the named bits true and a placeholder signature."""
    record = make_record(**bits)
    record["signature"] = "operator-signature-placeholder"
    return record


def read(raw: Any, **kw: Any):
    """Read ``raw`` with both expected digests supplied unless overridden."""
    kw.setdefault("expected_binary_digest", BIN)
    kw.setdefault("expected_config_digest", CFG)
    return read_capability_record(raw, **kw)


def all_denied(view) -> None:
    """Assert that every effective bit is false."""
    assert [view.is_effective(n) for n in CAPABILITY_BITS] == [False] * len(CAPABILITY_BITS)


# ------------------------------------------------------------------ the pure reader


def test_missing_record_denies_every_bit_with_a_reason() -> None:
    """A missing record is deny, not 'unset means enabled'."""
    view = read_capability_record(None)
    all_denied(view)
    assert view.record_state == "capability.record_missing"
    assert set(view.reasons.values()) == {"capability.record_missing"}


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"\xff\xfe", "capability.record_unreadable"),
        (b"not json", "capability.record_unreadable"),
        (b"x" * 70_000, "capability.record_unreadable"),
        (b"[1, 2]", "capability.record_malformed"),
        (b"null", "capability.record_malformed"),
    ],
    ids=["bad-utf8", "not-json", "oversize", "array", "null"],
)
def test_unreadable_or_non_object_record_denies(raw: bytes, reason: str) -> None:
    """Undecodable, oversize or non-object input denies every bit."""
    view = read(raw)
    all_denied(view)
    assert view.record_state == reason


def _mutations() -> list[tuple[str, Any, str]]:
    """Build (name, mutator, reason) cases over a well-formed record."""
    def drop_bit(r):
        """Remove the effects bit."""
        del r["capabilities"]["effects"]

    def string_bit(r):
        """Make the serving bit a string."""
        r["capabilities"]["serving"] = "true"

    def int_bit(r):
        """Make the serving bit an integer."""
        r["capabilities"]["serving"] = 1

    def null_bit(r):
        """Make the transport bit null."""
        r["capabilities"]["transport"] = None

    return [
        ("schema", lambda r: r.update(schema="orama-capability-record/v2"), "capability.schema_unsupported"),
        ("no-schema", lambda r: r.pop("schema"), "capability.schema_unsupported"),
        ("missing-bit", drop_bit, "capability.bit_missing"),
        ("string-bit", string_bit, "capability.bit_not_boolean"),
        ("int-bit", int_bit, "capability.bit_not_boolean"),
        ("null-bit", null_bit, "capability.bit_not_boolean"),
        ("extra-bit", lambda r: r["capabilities"].update(shell=False), "capability.record_malformed"),
        ("extra-key", lambda r: r.update(extra=1), "capability.record_malformed"),
        ("blank-id", lambda r: r.update(record_id=" "), "capability.record_malformed"),
        ("bad-time", lambda r: r.update(issued_at="yesterday"), "capability.record_malformed"),
        ("bad-digest", lambda r: r["binds"].update(binary_digest="sha256:xyz"), "capability.record_malformed"),
        ("binds-extra", lambda r: r["binds"].update(more=BIN), "capability.record_malformed"),
        ("blank-signature", lambda r: r.update(signature=" "), "capability.record_malformed"),
        ("bin-mismatch", lambda r: r["binds"].update(binary_digest="sha256:" + "c" * 64), "capability.digest_mismatch"),
        ("cfg-mismatch", lambda r: r["binds"].update(config_digest="sha256:" + "c" * 64), "capability.digest_mismatch"),
    ]


@pytest.mark.parametrize(("name", "mutate", "reason"), _mutations(), ids=[m[0] for m in _mutations()])
def test_malformed_record_denies_every_bit_even_when_a_bit_says_true(name, mutate, reason) -> None:
    """Any structural or digest fault denies all bits, including ones recorded true."""
    record = signed(serving=True, effects=True)
    mutate(record)
    view = read(record, signature_verifier=Signer())
    all_denied(view)
    assert view.record_state == reason
    assert view.refusal is None


def test_valid_all_false_record_with_null_signature_is_accepted() -> None:
    """signature null is valid while every bit is false; nothing differs from the record."""
    view = read(make_record(), signature_verifier=None)
    all_denied(view)
    assert view.record_state == "valid"
    assert set(view.reasons.values()) == {None}


def test_digest_mismatch_is_checked_even_when_all_bits_are_false() -> None:
    """A record bound to a different binary denies, so it cannot be replayed onto another build."""
    view = read(make_record(), expected_binary_digest="sha256:" + "0" * 64)
    assert view.record_state == "capability.digest_mismatch"


def test_true_bit_without_expected_digests_is_unverified_and_denied() -> None:
    """A true bit cannot be honoured when the process cannot check what the record binds."""
    view = read_capability_record(signed(serving=True), signature_verifier=Signer())
    all_denied(view)
    assert view.record_state == "capability.digest_unverified"


def test_reader_is_pure_and_returns_immutable_views() -> None:
    """The reader does not mutate its input and the view cannot be edited afterwards."""
    record = make_record()
    before = copy.deepcopy(record)
    view = read(record)
    assert record == before
    with pytest.raises(TypeError):
        view.effective["serving"] = True  # type: ignore[index]


def test_reader_accepts_text_and_bytes_and_mappings_alike() -> None:
    """The three input forms produce the same view."""
    record = make_record()
    forms = [record, json.dumps(record), json.dumps(record).encode()]
    assert len({read(f).record_state for f in forms}) == 1


# --------------------------------------------------------- independence of the bits


@pytest.mark.parametrize("bit", CAPABILITY_BITS)
def test_each_bit_is_independent_when_signed(bit: str) -> None:
    """Exactly the recorded bit is effective; no other bit is inferred from it."""
    view = read(signed(**{bit: True}), signature_verifier=Signer())
    assert {n: view.is_effective(n) for n in CAPABILITY_BITS} == {
        n: n == bit for n in CAPABILITY_BITS
    }
    assert view.refusal is None


def test_serving_true_never_implies_effects() -> None:
    """serving=true leaves effects effective False, and the reason is not 'derived'."""
    view = read(signed(serving=True), signature_verifier=Signer())
    assert view.is_effective("serving") is True
    assert view.is_effective("effects") is False
    assert view.reasons["effects"] is None


def test_unsigned_and_unknown_bit_names_are_false() -> None:
    """An unknown bit name is never effective."""
    assert read(make_record()).is_effective("anything_else") is False


# ---------------------------------------------------- unsigned enablement (all bits)


@pytest.mark.parametrize("bit", CAPABILITY_BITS)
@pytest.mark.parametrize("signer", [None, Signer(ok=False), Signer(error=True)], ids=["none", "bad", "raises"])
def test_true_bit_without_a_verified_signature_is_refused(bit: str, signer) -> None:
    """In R0-2 no signing path exists, so any true bit denies and startup refuses."""
    view = read(signed(**{bit: True}), signature_verifier=signer)
    all_denied(view)
    assert view.refusal == "capability.unsigned_enablement"
    assert view.reasons[bit] == "capability.unsigned_enablement"
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=CapabilityConfig(
            record=signed(**{bit: True}), expected_binary_digest=BIN,
            expected_config_digest=CFG, signature_verifier=signer,
        ))
    assert excinfo.value.code == "capability.unsigned_enablement"


def test_true_bit_with_null_signature_is_refused_even_with_a_verifier() -> None:
    """signature null is only allowed while every bit is false."""
    view = read(make_record(serving=True), signature_verifier=Signer())
    assert view.refusal == "capability.unsigned_enablement"


def test_signature_is_computed_over_the_record_without_the_signature_member() -> None:
    """The verifier is asked about the digest of the unsigned body."""
    signer = Signer()
    record = signed(serving=True)
    read(record, signature_verifier=signer)
    assert signer.seen == [(record_digest(record), "operator-signature-placeholder")]
    assert record_digest(record) == record_digest({**record, "signature": "other"})


# ------------------------------------------------------------- startup refusal matrix


def config(record: dict[str, Any], **kw: Any) -> CapabilityConfig:
    """Build a config whose record is signed through an accepting test verifier."""
    return CapabilityConfig(
        record=record, expected_binary_digest=BIN, expected_config_digest=CFG,
        signature_verifier=Signer(), **kw,
    )


def test_matrix_serving_without_a_verify_only_authority() -> None:
    """serving true and no verify-only authority is refused at startup."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=config(signed(serving=True)))
    assert excinfo.value.code == "startup.serving_without_verifier"


def test_matrix_effects_without_a_permit_verifier() -> None:
    """effects true and no permit verifier is refused, whatever serving says."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=config(signed(effects=True)))
    assert excinfo.value.code == "startup.effects_without_permit_verifier"


def test_matrix_transport_without_a_loaded_policy() -> None:
    """transport true and no Telos policy is refused."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=config(signed(transport=True)))
    assert excinfo.value.code == "startup.transport_without_policy"


@pytest.mark.parametrize("bit", ["autonomous_settlement", "continuation"])
def test_matrix_autonomy_without_an_activation_record(bit: str) -> None:
    """autonomous_settlement or continuation true without the C4 record is refused."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=config(signed(**{bit: True})))
    assert excinfo.value.code == "startup.autonomy_without_activation"


@pytest.mark.parametrize("mode", ["allow", "fail_open", "", "DENY", None], ids=["allow", "open", "blank", "case", "none"])
def test_matrix_monitoring_failure_as_permission_is_refused_even_with_all_bits_false(mode) -> None:
    """Any failure mode other than exactly 'deny' is a monitoring-as-permission config."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=CapabilityConfig(record=make_record(), monitoring_failure_mode=mode))
    assert excinfo.value.code == "startup.monitoring_as_permission"


def test_matrix_treating_serving_as_effects_is_refused_even_with_all_bits_false() -> None:
    """A config that derives effects from serving is refused outright."""
    with pytest.raises(StartupRefused) as excinfo:
        create_app(capability_config=CapabilityConfig(effects_follow_serving=True))
    assert excinfo.value.code == "startup.serving_implies_effects"


def test_matrix_satisfied_rows_start_and_each_bit_stays_independent() -> None:
    """With each prerequisite injected the app starts; serving does not turn effects on."""
    app = create_app(
        capability_config=config(signed(serving=True), permit_verifier=object()),
        grant_verifier=object(),  # type: ignore[arg-type]
    )
    view = app.state.capabilities
    assert view.is_effective("serving") and not view.is_effective("effects")
    app = create_app(capability_config=config(signed(effects=True), permit_verifier=object()))
    assert app.state.capabilities.is_effective("effects")
    assert not app.state.capabilities.is_effective("serving")


def test_matrix_codes_are_the_contract_codes() -> None:
    """The refusal vocabulary is exactly the frozen contract list."""
    from orama.api.capabilities import STARTUP_REFUSAL_CODES

    assert STARTUP_REFUSAL_CODES == {
        "startup.serving_without_verifier", "startup.effects_without_permit_verifier",
        "startup.transport_without_policy", "startup.autonomy_without_activation",
        "startup.monitoring_as_permission", "startup.serving_implies_effects",
        "capability.unsigned_enablement",
    }
    with pytest.raises(ValueError):
        StartupRefused("startup.made_up")


def test_enforce_is_directly_callable_on_a_view() -> None:
    """The matrix can be exercised without building an app."""
    view = read(make_record())
    enforce_startup_matrix(view, CapabilityConfig(), verify_authority_available=False)


# --------------------------------------------------------- environment and readiness


def test_default_app_denies_everything_and_starts() -> None:
    """The module-level default app has no record, so every capability is denied."""
    app = create_app()
    view = app.state.capabilities
    all_denied(view)
    assert view.record_state == "capability.record_missing"


def test_environment_without_a_record_path_is_a_missing_record() -> None:
    """No variable means missing; it never means enabled."""
    cfg = capability_config_from_environ({})
    assert cfg.record is None and cfg.signature_verifier is None


def test_environment_unreadable_path_is_reported_unreadable(tmp_path: Path) -> None:
    """A path that cannot be read denies with the unreadable reason."""
    cfg = capability_config_from_environ({"ORAMA_CAPABILITY_RECORD": str(tmp_path / "absent.json")})
    assert read_capability_record(cfg.record).record_state == "capability.record_unreadable"


def test_deeply_nested_record_is_reported_unreadable() -> None:
    """A bounded but recursively malformed record denies instead of escaping startup."""
    view = read_capability_record(b"[" * 2_000)
    all_denied(view)
    assert view.record_state == "capability.record_unreadable"


def test_environment_record_file_is_read_without_enabling_anything(tmp_path: Path) -> None:
    """A valid all-false record file loads; the digests come from labels only."""
    path = tmp_path / "record.json"
    path.write_text(json.dumps(make_record()), encoding="utf-8")
    cfg = capability_config_from_environ({
        "ORAMA_CAPABILITY_RECORD": str(path),
        "ORAMA_EXPECTED_BINARY_DIGEST": BIN, "ORAMA_EXPECTED_CONFIG_DIGEST": CFG,
    })
    view = create_app(capability_config=cfg).state.capabilities
    assert view.record_state == "valid"
    all_denied(view)


async def test_health_reports_each_bit_and_the_reason_when_it_differs() -> None:
    """Readiness prints every bit's effective value and the reason; no ids or paths."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = (await client.get("/health")).json()
    bits = body["capabilities"]["bits"]
    assert set(bits) == set(CAPABILITY_BITS)
    assert all(v == {"effective": False, "reason": "capability.record_missing"} for v in bits.values())
    assert "rec-" not in json.dumps(body)


async def test_health_reports_serving_true_and_effects_false_separately() -> None:
    """A signed serving bit is visible while effects is still reported denied."""
    app = create_app(
        capability_config=config(signed(serving=True)), grant_verifier=object(),  # type: ignore[arg-type]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bits = (await client.get("/health")).json()["capabilities"]["bits"]
    assert bits["serving"] == {"effective": True, "reason": None}
    assert bits["effects"] == {"effective": False, "reason": None}
