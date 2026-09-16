"""BLE-shaped proximity radio + Noise handshake runtime.

Physical BlueZ/CoreBluetooth is not required in CI. Frames are GATT-like
length-prefixed writes on a documented characteristic. A proximity radio
drops frames when simulated RSSI is below threshold (out of range).
"""
from __future__ import annotations

import os
import secrets
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from orama.auth.bitchat.fingerprint import mesh_peer_id, noise_fingerprint
from orama.auth.bitchat.noise_xx import (
    DHLEN,
    PROXIMITY_LABEL,
    NoiseError,
    NoiseKeyPair,
    NoiseXXSession,
)

# Oramasys-owned GATT identity (not copied from Apple/BitChat app UUIDs).
ORAMA_BITCHAT_SERVICE_UUID = "6f72616d-6173-7973-626c-650000000001"
ORAMA_BITCHAT_CHAR_UUID = "6f72616d-6173-7973-626c-650000000002"
DEFAULT_RSSI_THRESHOLD_DBM = -70


class BleTransportError(RuntimeError):
    """Frame could not be delivered (out of range / no peer)."""


class BleLink(Protocol):
    def send(self, frame: bytes) -> None: ...
    def recv(self, timeout: float = 1.0) -> bytes: ...


def _encode_frame(payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("frame too large")
    return len(payload).to_bytes(2, "big") + payload


def _decode_frames(buf: bytearray) -> list[bytes]:
    out: list[bytes] = []
    while len(buf) >= 2:
        n = int.from_bytes(buf[:2], "big")
        if len(buf) < 2 + n:
            break
        out.append(bytes(buf[2 : 2 + n]))
        del buf[: 2 + n]
    return out


@dataclass
class BleDevice:
    device_id: str
    rssi_by_peer: dict[str, int] = field(default_factory=dict)
    inbox: deque[bytes] = field(default_factory=deque)
    cond: threading.Condition = field(default_factory=threading.Condition)


class ProximityBleMesh:
    """In-process BLE mesh: only in-range peers exchange GATT writes."""

    def __init__(self, rssi_threshold_dbm: int = DEFAULT_RSSI_THRESHOLD_DBM) -> None:
        self.rssi_threshold_dbm = rssi_threshold_dbm
        self._devices: dict[str, BleDevice] = {}
        self._lock = threading.Lock()

    def attach(self, device_id: str, rssi_by_peer: dict[str, int] | None = None) -> BleDevice:
        with self._lock:
            dev = BleDevice(device_id=device_id, rssi_by_peer=dict(rssi_by_peer or {}))
            self._devices[device_id] = dev
            return dev

    def in_range(self, src: str, dst: str) -> bool:
        with self._lock:
            a = self._devices.get(src)
            b = self._devices.get(dst)
            if a is None or b is None:
                return False
            rssi_ab = a.rssi_by_peer.get(dst)
            rssi_ba = b.rssi_by_peer.get(src)
            if rssi_ab is None or rssi_ba is None:
                return False
            return rssi_ab >= self.rssi_threshold_dbm and rssi_ba >= self.rssi_threshold_dbm

    def write(self, src: str, dst: str, payload: bytes) -> None:
        if not self.in_range(src, dst):
            raise BleTransportError(f"out of BLE proximity range ({src} -> {dst})")
        with self._lock:
            peer = self._devices[dst]
        frame = _encode_frame(payload)
        with peer.cond:
            peer.inbox.append(frame)
            peer.cond.notify_all()

    def read(self, device_id: str, timeout: float = 1.0) -> bytes:
        with self._lock:
            dev = self._devices[device_id]
        with dev.cond:
            if not dev.inbox:
                dev.cond.wait(timeout=timeout)
            if not dev.inbox:
                raise BleTransportError("BLE notify timeout")
            return dev.inbox.popleft()


class MeshBleLink:
    """Point-to-point GATT write/notify over ``ProximityBleMesh``."""

    def __init__(self, mesh: ProximityBleMesh, local_id: str, peer_id: str) -> None:
        self.mesh = mesh
        self.local_id = local_id
        self.peer_id = peer_id
        self._buf = bytearray()

    def send(self, frame: bytes) -> None:
        self.mesh.write(self.local_id, self.peer_id, frame)

    def recv(self, timeout: float = 1.0) -> bytes:
        encoded = self.mesh.read(self.local_id, timeout=timeout)
        self._buf.extend(encoded)
        frames = _decode_frames(self._buf)
        if not frames:
            raise BleTransportError("incomplete GATT frame")
        if len(frames) != 1:
            # Buffer extras for a later recv.
            for extra in frames[1:]:
                self._buf.extend(_encode_frame(extra))
        return frames[0]


@dataclass(frozen=True, slots=True)
class ProximityAttest:
    local_fingerprint: str
    remote_fingerprint: str
    remote_peer_id: str
    remote_static: bytes
    nonce: bytes


class BleNoiseRuntime:
    """Run Noise XX over a BLE-shaped link and emit a proximity attest."""

    def __init__(self, static: NoiseKeyPair, link: BleLink, *, initiator: bool) -> None:
        self.static = static
        self.link = link
        self.initiator = initiator
        self.session = NoiseXXSession(initiator=initiator, static=static)

    def attest(self, *, nonce: bytes | None = None) -> ProximityAttest:
        nonce = nonce if nonce is not None else secrets.token_bytes(16)
        if self.initiator:
            self.link.send(self.session.write_message())
            self.session.read_message(self.link.recv())
            self.link.send(self.session.write_message(PROXIMITY_LABEL + nonce))
            ack = self.session.decrypt(self.link.recv())
            if ack != PROXIMITY_LABEL + nonce:
                raise NoiseError("proximity ack mismatch")
        else:
            self.session.read_message(self.link.recv())
            self.link.send(self.session.write_message())
            payload = self.session.read_message(self.link.recv())
            if not payload.startswith(PROXIMITY_LABEL) or len(payload) != len(PROXIMITY_LABEL) + 16:
                raise NoiseError("proximity payload mismatch")
            nonce = payload[len(PROXIMITY_LABEL) :]
            self.link.send(self.session.encrypt(PROXIMITY_LABEL + nonce))
        if self.session.remote_static is None or len(self.session.remote_static) != DHLEN:
            raise NoiseError("remote static missing after handshake")
        return ProximityAttest(
            local_fingerprint=noise_fingerprint(self.static.public),
            remote_fingerprint=noise_fingerprint(self.session.remote_static),
            remote_peer_id=mesh_peer_id(self.session.remote_static),
            remote_static=self.session.remote_static,
            nonce=nonce,
        )


def rssi_threshold_from_env() -> int:
    raw = os.environ.get("ORAMA_BITCHAT_RSSI_THRESHOLD_DBM", "").strip()
    if not raw:
        return DEFAULT_RSSI_THRESHOLD_DBM
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_RSSI_THRESHOLD_DBM
