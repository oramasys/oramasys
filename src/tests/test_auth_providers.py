"""AuthManager, binding store, optional providers, NIP-98 unit tests."""
from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest

from orama.auth import (
    AuthManager,
    FleetBindingStore,
    build_default_auth_manager,
    ceremony_bind,
    fingerprint_secret,
)
from orama.auth.nip98 import Nip98Error, ReplayCache, compute_event_id, verify_nip98
from orama.auth.providers import (
    BearerTokenProvider,
    BitChatProximityProvider,
    BuzzNostrProvider,
    FirebaseShapedProvider,
    GoogleOidcProvider,
    TwitterXOauthProvider,
)


def test_stubs_importable_and_not_configured():
    assert BitChatProximityProvider().is_configured() is False
    assert FirebaseShapedProvider().is_configured() is False
    assert BitChatProximityProvider().authenticate_request({}) is None
    assert FirebaseShapedProvider().authenticate_request({}) is None
    assert BitChatProximityProvider().is_configured() is False
    assert FirebaseShapedProvider().is_configured() is False
    assert BitChatProximityProvider().authenticate_request({}) is None
    assert FirebaseShapedProvider().authenticate_request({}) is None


def test_optional_providers_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ORAMA_AUTH_GOOGLE_OIDC", raising=False)
    monkeypatch.delenv("ORAMA_AUTH_TWITTER_X", raising=False)
    monkeypatch.delenv("ORAMA_AUTH_BUZZ_NIP98", raising=False)
    monkeypatch.delenv("ORAMA_AUTH_BITCHAT_PROXIMITY", raising=False)
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    mgr = build_default_auth_manager()
    configured = [p.name for p in mgr.providers if p.is_configured()]
    assert configured == ["bearer"]
    result = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert result is not None
    assert result.provider == "bearer"


def test_bearer_always_last_in_default_manager():
    mgr = build_default_auth_manager()
    assert mgr.providers[-1].name == "bearer"


def test_fleet_binding_ceremony(tmp_path, monkeypatch):
    path = tmp_path / "fleet-binding.json"
    store = FleetBindingStore(path)
    monkeypatch.setenv("ORAMA_BINDING_SALT", "unit-test-salt")
    binding = ceremony_bind(
        issuer="nostr",
        subject="a" * 64,
        control_plane_token="test-control-plane-token-32b",
        gossip_secret="gossip-secret-value-ok",
        nonce_id="ceremony-1",
        store=store,
    )
    loaded = store.load()
    assert loaded is not None
    assert loaded.issuer == "nostr"
    assert loaded.subject == "a" * 64
    assert loaded.cp_token_fp == fingerprint_secret("test-control-plane-token-32b")
    assert loaded.verify_mode_default == "attest"
    assert path.stat().st_mode & 0o777 == 0o600
    store.clear()
    assert store.load() is None
    assert binding.nonce_id == "ceremony-1"


def _sign_event(privkey, event: dict) -> dict:
    from coincurve import PrivateKey

    event = dict(event)
    event["pubkey"] = privkey.public_key.format(compressed=True)[1:].hex()
    event_id = compute_event_id(event)
    sig = privkey.sign_schnorr(bytes.fromhex(event_id)).hex()
    event["id"] = event_id
    event["sig"] = sig
    return event


def _nostr_header(event: dict) -> str:
    raw = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode()
    return "Nostr " + base64.b64encode(raw).decode()


@pytest.fixture
def nostr_key():
    from coincurve import PrivateKey

    return PrivateKey()


def test_nip98_accepts_valid(nostr_key):
    now = int(time.time())
    url = "http://test/run"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", url], ["method", "POST"]],
        },
    )
    result = verify_nip98(
        authorization=_nostr_header(event),
        method="POST",
        url=url,
        body=b"{}",
        now=now,
        replay=ReplayCache(),
    )
    assert result.pubkey == event["pubkey"]


def test_nip98_rejects_bad_sig(nostr_key):
    now = int(time.time())
    url = "http://test/run"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", url], ["method", "GET"]],
        },
    )
    event["sig"] = "00" * 64
    with pytest.raises(Nip98Error, match="bad signature"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="GET",
            url=url,
            now=now,
            replay=ReplayCache(),
        )


def test_nip98_rejects_skew(nostr_key):
    now = int(time.time())
    url = "http://test/health"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now - 120,
            "tags": [["u", url], ["method", "GET"]],
        },
    )
    with pytest.raises(Nip98Error, match="skew"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="GET",
            url=url,
            skew_sec=60,
            now=now,
            replay=ReplayCache(),
        )


def test_nip98_rejects_wrong_u_or_method(nostr_key):
    now = int(time.time())
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", "http://test/a"], ["method", "GET"]],
        },
    )
    with pytest.raises(Nip98Error, match="u tag"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="GET",
            url="http://test/b",
            now=now,
            replay=ReplayCache(),
        )
    with pytest.raises(Nip98Error, match="method"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="POST",
            url="http://test/a",
            now=now,
            replay=ReplayCache(),
        )


def test_nip98_replay(nostr_key):
    now = int(time.time())
    url = "http://test/run"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", url], ["method", "GET"]],
        },
    )
    cache = ReplayCache()
    header = _nostr_header(event)
    verify_nip98(
        authorization=header, method="GET", url=url, now=now, replay=cache
    )
    with pytest.raises(Nip98Error, match="replay"):
        verify_nip98(
            authorization=header, method="GET", url=url, now=now, replay=cache
        )


def test_nip98_absent_falls_through_to_bearer(monkeypatch):
    monkeypatch.setenv("ORAMA_AUTH_BUZZ_NIP98", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    mgr = AuthManager([BuzzNostrProvider(), BearerTokenProvider()])
    result = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert result is not None
    assert result.provider == "bearer"


def test_nip98_disabled_ignores_header(monkeypatch, nostr_key):
    monkeypatch.delenv("ORAMA_AUTH_BUZZ_NIP98", raising=False)
    now = int(time.time())
    url = "http://test/run"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", url], ["method", "GET"]],
        },
    )
    provider = BuzzNostrProvider()
    assert provider.is_configured() is False
    assert (
        provider.authenticate_request(
            {"Authorization": _nostr_header(event)}, method="GET", url=url
        )
        is None
    )


def test_nip98_payload_tag(nostr_key):
    now = int(time.time())
    url = "http://test/run"
    body = b'{"ok":true}'
    digest = hashlib.sha256(body).hexdigest()
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", url], ["method", "POST"], ["payload", digest]],
        },
    )
    result = verify_nip98(
        authorization=_nostr_header(event),
        method="POST",
        url=url,
        body=body,
        require_payload=True,
        now=now,
        replay=ReplayCache(),
    )
    assert result.pubkey == event["pubkey"]


def test_google_and_twitter_feature_flags(monkeypatch):
    monkeypatch.setenv("ORAMA_AUTH_GOOGLE_OIDC", "1")
    monkeypatch.setenv("ORAMA_GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("ORAMA_AUTH_TWITTER_X", "1")
    monkeypatch.setenv("ORAMA_TWITTER_CLIENT_ID", "twitter-client")
    assert GoogleOidcProvider().is_configured() is True
    assert TwitterXOauthProvider().is_configured() is True
    cfg = GoogleOidcProvider().oauth_client_config()
    assert "accounts.google.com" in cfg["server_metadata_url"]
    x = TwitterXOauthProvider()
    assert "code_challenge_method" in x.oauth_client_config()["client_kwargs"]
