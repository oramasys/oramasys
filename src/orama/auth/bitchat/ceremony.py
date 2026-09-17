"""Bind a BitChat Noise fingerprint after proximity + local secret proof."""
from __future__ import annotations

from orama.api.authz.tokens import is_weak_token, token_matches
from orama.auth.binding import FleetBinding, FleetBindingStore, ceremony_bind
from orama.auth.bitchat.ble import ProximityAttest


class CeremonyError(ValueError):
    """Proximity bind refused."""


def bind_proximity_attest(
    attest: ProximityAttest,
    *,
    control_plane_token: str,
    presented_token: str,
    gossip_secret: str = "",
    store: FleetBindingStore | None = None,
) -> FleetBinding:
    """Require possession of the local control-plane token, then persist fingerprints."""
    if is_weak_token(control_plane_token):
        raise CeremonyError("control plane token missing or weak")
    if not token_matches(presented_token, (control_plane_token,)):
        raise CeremonyError("local secret proof failed")
    return ceremony_bind(
        issuer="bitchat-noise",
        subject=attest.remote_fingerprint,
        control_plane_token=control_plane_token,
        gossip_secret=gossip_secret,
        nonce_id=attest.nonce.hex(),
        subject_display=attest.remote_peer_id,
        store=store,
    )
