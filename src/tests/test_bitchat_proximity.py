"""BitChat-compatible Noise XX + BLE proximity runtime tests."""
from __future__ import annotations

import hashlib
import threading

import pytest

from orama.auth import AuthManager, FleetBindingStore
from orama.auth.bitchat.ble import (
    BleNoiseRuntime,
    BleTransportError,
    MeshBleLink,
    ProximityBleMesh,
)
from orama.auth.bitchat.ceremony import CeremonyError, bind_proximity_attest
from orama.auth.bitchat.fingerprint import mesh_peer_id, noise_fingerprint
from orama.auth.bitchat.noise_xx import NoiseError, NoiseKeyPair, NoiseXXSession
from orama.auth.providers.bearer import BearerTokenProvider
from orama.auth.providers.bitchat_proximity import (
    BitChatProximityProvider,
    clear_proximity_sessions,
    remember_proximity_session,
)
from orama.auth.providers.firebase_shaped import FirebaseShapedProvider


def test_firebase_stub_still_unconfigured():
    assert FirebaseShapedProvider().is_configured() is False
    assert FirebaseShapedProvider().authenticate_request({}) is None


def test_bitchat_disabled_by_default_falls_through(monkeypatch):
    monkeypatch.delenv("ORAMA_AUTH_BITCHAT_PROXIMITY", raising=False)
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    provider = BitChatProximityProvider()
    assert provider.is_configured() is False
    mgr = AuthManager([provider, BearerTokenProvider()])
    result = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert result is not None
    assert result.provider == "bearer"


def test_fingerprint_canonicalization_vector():
    static_public = bytes(range(32))
    fp = noise_fingerprint(static_public)
    assert fp == hashlib.sha256(static_public).hexdigest()
    assert len(fp) == 64
    assert mesh_peer_id(static_public) == fp[:16]
    assert mesh_peer_id(fingerprint=fp) == fp[:16]


def test_noise_xx_handshake_and_transport():
    initiator = NoiseKeyPair.generate()
    responder = NoiseKeyPair.generate()
    i = NoiseXXSession(initiator=True, static=initiator)
    r = NoiseXXSession(initiator=False, static=responder)
    r.read_message(i.write_message())
    i.read_message(r.write_message())
    payload = r.read_message(i.write_message(b"hello"))
    assert payload == b"hello"
    assert i.complete and r.complete
    assert i.remote_static == responder.public
    assert r.remote_static == initiator.public
    assert r.decrypt(i.encrypt(b"ping")) == b"ping"
    assert i.decrypt(r.encrypt(b"pong")) == b"pong"


def test_noise_xx_rejects_tampered_handshake():
    initiator = NoiseKeyPair.generate()
    responder = NoiseKeyPair.generate()
    i = NoiseXXSession(initiator=True, static=initiator)
    r = NoiseXXSession(initiator=False, static=responder)
    msg1 = bytearray(i.write_message())
    msg1[-1] ^= 0x01
    r.read_message(bytes(msg1))  # msg1 has no MAC when k empty
    msg2 = bytearray(r.write_message())
    msg2[-1] ^= 0x01
    with pytest.raises(NoiseError):
        i.read_message(bytes(msg2))


def _run_proximity(mesh: ProximityBleMesh, a: str, b: str) -> tuple:
    phone = NoiseKeyPair.generate()
    glass = NoiseKeyPair.generate()
    errors: list[BaseException] = []
    attests: dict[str, object] = {}

    def initiator() -> None:
        try:
            runtime = BleNoiseRuntime(
                phone, MeshBleLink(mesh, a, b), initiator=True
            )
            attests["phone"] = runtime.attest()
        except BaseException as exc:  # noqa: BLE001 — capture for parent thread
            errors.append(exc)

    def responder() -> None:
        try:
            runtime = BleNoiseRuntime(
                glass, MeshBleLink(mesh, b, a), initiator=False
            )
            attests["glass"] = runtime.attest()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t_r = threading.Thread(target=responder)
    t_i = threading.Thread(target=initiator)
    t_r.start()
    t_i.start()
    t_i.join(timeout=3)
    t_r.join(timeout=3)
    return phone, glass, attests, errors


def test_ble_noise_proximity_in_range():
    mesh = ProximityBleMesh(rssi_threshold_dbm=-70)
    mesh.attach("phone", {"glass": -40})
    mesh.attach("glass", {"phone": -42})
    phone, glass, attests, errors = _run_proximity(mesh, "phone", "glass")
    assert errors == []
    phone_attest = attests["phone"]
    glass_attest = attests["glass"]
    assert phone_attest.remote_fingerprint == noise_fingerprint(glass.public)
    assert glass_attest.remote_fingerprint == noise_fingerprint(phone.public)
    assert phone_attest.remote_peer_id == mesh_peer_id(glass.public)
    assert phone_attest.nonce == glass_attest.nonce


def test_ble_noise_proximity_out_of_range_fails():
    mesh = ProximityBleMesh(rssi_threshold_dbm=-70)
    mesh.attach("phone", {"glass": -95})
    mesh.attach("glass", {"phone": -96})
    _phone, _glass, _attests, errors = _run_proximity(mesh, "phone", "glass")
    assert errors
    assert any(isinstance(exc, BleTransportError) for exc in errors)


def test_ceremony_rejects_without_local_secret(tmp_path):
    mesh = ProximityBleMesh()
    mesh.attach("phone", {"glass": -30})
    mesh.attach("glass", {"phone": -30})
    _phone, _glass, attests, errors = _run_proximity(mesh, "phone", "glass")
    assert errors == []
    store = FleetBindingStore(tmp_path / "fleet-binding.json")
    with pytest.raises(CeremonyError, match="local secret"):
        bind_proximity_attest(
            attests["glass"],
            control_plane_token="test-control-plane-token-32b",
            presented_token="wrong-token-value-here!!",
            store=store,
        )
    assert store.load() is None


def test_ceremony_binds_fingerprint_after_proximity(tmp_path):
    mesh = ProximityBleMesh()
    mesh.attach("phone", {"glass": -30})
    mesh.attach("glass", {"phone": -30})
    _phone, _glass, attests, errors = _run_proximity(mesh, "phone", "glass")
    assert errors == []
    store = FleetBindingStore(tmp_path / "fleet-binding.json")
    token = "test-control-plane-token-32b"
    binding = bind_proximity_attest(
        attests["glass"],
        control_plane_token=token,
        presented_token=token,
        gossip_secret="gossip-secret-value-ok",
        store=store,
    )
    assert binding.issuer == "bitchat-noise"
    assert binding.subject == attests["glass"].remote_fingerprint
    assert store.load() is not None


def test_ble_rssi_threshold_env_configures_mesh(monkeypatch):
    monkeypatch.setenv("ORAMA_BITCHAT_RSSI_THRESHOLD_DBM", "-50")
    mesh = ProximityBleMesh()
    assert mesh.rssi_threshold_dbm == -50
    mesh.attach("phone", {"glass": -60})
    mesh.attach("glass", {"phone": -60})
    assert mesh.in_range("phone", "glass") is False


def test_bitchat_http_attest_after_proximity(monkeypatch):
    clear_proximity_sessions()
    monkeypatch.setenv("ORAMA_AUTH_BITCHAT_PROXIMITY", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    mesh = ProximityBleMesh(rssi_threshold_dbm=-70)
    mesh.attach("phone", {"glass": -35})
    mesh.attach("glass", {"phone": -35})
    _phone, _glass, attests, errors = _run_proximity(mesh, "phone", "glass")
    assert errors == []
    credential = remember_proximity_session(attests["glass"])
    provider = BitChatProximityProvider()
    assert provider.is_configured() is True
    assert (
        provider.authenticate_request(
            {"X-BitChat-Fingerprint": attests["glass"].remote_fingerprint}
        )
        is None
    )
    result = provider.authenticate_request({"X-BitChat-Session": credential})
    assert result is not None
    assert result.issuer == "bitchat-noise"
    # Missing proximity credential still falls through to Bearer.
    mgr = AuthManager([provider, BearerTokenProvider()])
    bearer = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert bearer is not None and bearer.provider == "bearer"
    clear_proximity_sessions()
