"""Fleet binding store: IdP issuer|subject ↔ local secret fingerprints.

Local-only path under ``.local/`` (gitignored). Never commits secrets.
IdP/Nostr binding is unlock/attest only — never replaces Bearer or gossip.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

VerifyMode = Literal["off", "attest", "strict"]


@dataclass(slots=True)
class FleetBinding:
    version: int
    created_at: str
    issuer: str
    subject: str
    cp_token_fp: str
    gossip_secret_fp: str
    nonce_id: str
    verify_mode_default: VerifyMode = "attest"
    subject_display: str | None = None


def _default_path() -> Path:
    override = os.environ.get("ORAMA_FLEET_BINDING_PATH", "").strip()
    if override:
        return Path(override)
    # Local-only; never under portable memory / git tree committed content.
    return Path(".local") / "fleet-binding.json"


def fingerprint_secret(secret: str, *, salt: str | None = None) -> str:
    """Non-invertible fingerprint (HMAC-SHA256) of a fleet secret."""
    material = (salt or os.environ.get("ORAMA_BINDING_SALT", "orama-fleet-binding")).encode()
    return hmac.new(material, secret.encode(), hashlib.sha256).hexdigest()


class FleetBindingStore:
    """Load / save / clear a single local fleet binding artifact."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _default_path()

    def load(self) -> Optional[FleetBinding]:
        if not self.path.is_file():
            return None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return FleetBinding(
            version=int(data["version"]),
            created_at=str(data["created_at"]),
            issuer=str(data["issuer"]),
            subject=str(data["subject"]),
            cp_token_fp=str(data["cp_token_fp"]),
            gossip_secret_fp=str(data.get("gossip_secret_fp", "")),
            nonce_id=str(data["nonce_id"]),
            verify_mode_default=data.get("verify_mode_default", "attest"),  # type: ignore[arg-type]
            subject_display=data.get("subject_display"),
        )

    def save(self, binding: FleetBinding) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(asdict(binding), indent=2, sort_keys=True) + "\n"
        # Atomic write with restrictive permissions.
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".fleet-binding.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
            os.chmod(self.path, 0o600)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def clear(self) -> None:
        if self.path.is_file():
            self.path.unlink()


def ceremony_bind(
    *,
    issuer: str,
    subject: str,
    control_plane_token: str,
    gossip_secret: str = "",
    nonce_id: str,
    verify_mode: VerifyMode = "attest",
    subject_display: str | None = None,
    store: FleetBindingStore | None = None,
) -> FleetBinding:
    """Write binding after operator proved IdP subject + local secret possession.

    Callers must already have verified IdP identity and local Bearer (and
    optionally gossip) possession. This function only persists fingerprints.
    """
    binding = FleetBinding(
        version=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        issuer=issuer,
        subject=subject,
        cp_token_fp=fingerprint_secret(control_plane_token),
        gossip_secret_fp=fingerprint_secret(gossip_secret) if gossip_secret else "",
        nonce_id=nonce_id,
        verify_mode_default=verify_mode,
        subject_display=subject_display,
    )
    (store or FleetBindingStore()).save(binding)
    return binding
