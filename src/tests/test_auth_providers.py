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
from orama.auth.providers.twitter_x import (
    issue_twitter_oauth_artifact,
    verify_twitter_oauth_artifact,
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


def test_nip98_missing_content_is_nip98_error(nostr_key):
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
    del event["content"]
    with pytest.raises(Nip98Error, match="content"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="GET",
            url=url,
            now=now,
            replay=ReplayCache(),
        )


def test_nip98_empty_url_fails_closed(nostr_key):
    now = int(time.time())
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", "http://test/run"], ["method", "GET"]],
        },
    )
    with pytest.raises(Nip98Error, match="url required"):
        verify_nip98(
            authorization=_nostr_header(event),
            method="GET",
            url="",
            now=now,
            replay=ReplayCache(),
        )


def test_nip98_replay_covers_full_skew_window(nostr_key):
    skew = 60
    created_at = 1_700_000_050
    first_now = 1_700_000_000  # event is 50s in the future
    later_now = 1_700_000_065  # cache ttl of 60s from first_now would have expired
    url = "http://test/run"
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": created_at,
            "tags": [["u", url], ["method", "GET"]],
        },
    )
    cache = ReplayCache(ttl_sec=float(skew))
    header = _nostr_header(event)
    verify_nip98(
        authorization=header,
        method="GET",
        url=url,
        skew_sec=skew,
        now=first_now,
        replay=cache,
    )
    with pytest.raises(Nip98Error, match="replay"):
        verify_nip98(
            authorization=header,
            method="GET",
            url=url,
            skew_sec=skew,
            now=later_now,
            replay=cache,
        )


def test_nip98_replay_admit_is_atomic():
    cache = ReplayCache()
    assert cache.admit("abc", now=10.0, expires_at=100.0) is True
    assert cache.admit("abc", now=11.0, expires_at=100.0) is False


def test_nip98_replay_cache_fails_closed_when_full_of_live_markers():
    cache = ReplayCache(max_size=2, ttl_sec=60)
    assert cache.admit("keep-a", now=10.0, expires_at=100.0) is True
    assert cache.admit("keep-b", now=10.0, expires_at=100.0) is True
    assert cache.admit("new-c", now=10.0, expires_at=100.0) is False
    assert cache.seen("keep-a", now=10.0) is True
    assert cache.seen("keep-b", now=10.0) is True
    assert cache.seen("new-c", now=10.0) is False


def test_nip98_replay_cache_purges_expired_regardless_of_insertion_order():
    cache = ReplayCache(max_size=1, ttl_sec=60)
    assert cache.admit("long-lived", now=10.0, expires_at=200.0) is True
    assert cache.admit("short-lived", now=11.0, expires_at=20.0) is False
    assert cache.admit("after-expiry", now=201.0, expires_at=300.0) is True
    assert cache.seen("long-lived", now=201.0) is False
    assert cache.seen("after-expiry", now=201.0) is True


def test_buzz_empty_url_does_not_fallback_to_localhost(monkeypatch, nostr_key):
    monkeypatch.setenv("ORAMA_AUTH_BUZZ_NIP98", "1")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    now = int(time.time())
    event = _sign_event(
        nostr_key,
        {
            "content": "",
            "kind": 27235,
            "created_at": now,
            "tags": [["u", "http://localhost/"], ["method", "GET"]],
        },
    )
    provider = BuzzNostrProvider()
    assert (
        provider.authenticate_request(
            {"Authorization": _nostr_header(event)}, method="GET", url=""
        )
        is None
    )
    mgr = AuthManager([provider, BearerTokenProvider()])
    result = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"},
        method="GET",
        url="",
    )
    assert result is not None
    assert result.provider == "bearer"


def test_google_expired_signed_token_rejected(monkeypatch):
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    key = RSAKey.generate_key(auto_kid=True)
    jwks = json.dumps({"keys": [key.as_dict(private=False)]})
    monkeypatch.setenv("ORAMA_AUTH_GOOGLE_OIDC", "1")
    monkeypatch.setenv("ORAMA_GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("ORAMA_GOOGLE_JWKS_JSON", jwks)
    now = int(time.time())
    header = {"alg": "RS256", "kid": key.kid}
    base_claims = {
        "sub": "user-1",
        "iss": "https://accounts.google.com",
        "aud": "google-client",
        "iat": now - 120,
        "nbf": now - 120,
    }
    expired = jwt.encode(
        header, {**base_claims, "exp": now - 30}, key
    )
    valid = jwt.encode(
        header, {**base_claims, "exp": now + 600}, key
    )
    provider = GoogleOidcProvider()
    assert provider.authenticate_request({"X-Google-ID-Token": expired}) is None
    result = provider.authenticate_request({"X-Google-ID-Token": valid})
    assert result is not None
    assert result.subject == "user-1"
    not_yet = jwt.encode(
        header, {**base_claims, "nbf": now + 600, "exp": now + 900}, key
    )
    assert provider.authenticate_request({"X-Google-ID-Token": not_yet}) is None


def test_twitter_user_id_header_alone_is_not_auth(monkeypatch):
    monkeypatch.setenv("ORAMA_AUTH_TWITTER_X", "1")
    monkeypatch.setenv("ORAMA_TWITTER_CLIENT_ID", "twitter-client")
    monkeypatch.setenv("ORAMA_TWITTER_ARTIFACT_SECRET", "twitter-artifact-hmac-secret-32b")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    provider = TwitterXOauthProvider()
    assert provider.authenticate_request({"X-Twitter-User-Id": "12345"}) is None
    artifact = issue_twitter_oauth_artifact("12345")
    assert artifact is not None
    result = provider.authenticate_request({"X-Twitter-OAuth-Artifact": artifact})
    assert result is not None
    assert result.subject == "12345"
    expired = issue_twitter_oauth_artifact("12345", ttl_sec=1, now=int(time.time()) - 30)
    assert verify_twitter_oauth_artifact(expired) is None
    mgr = AuthManager([provider, BearerTokenProvider()])
    bearer = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert bearer is not None and bearer.provider == "bearer"


def test_twitter_short_artifact_secret_fails_closed(monkeypatch):
    monkeypatch.setenv("ORAMA_AUTH_TWITTER_X", "1")
    monkeypatch.setenv("ORAMA_TWITTER_CLIENT_ID", "twitter-client")
    monkeypatch.setenv("ORAMA_TWITTER_ARTIFACT_SECRET", "too-short")
    monkeypatch.setenv("ORAMA_CONTROL_PLANE_TOKEN", "test-control-plane-token-32b")
    assert issue_twitter_oauth_artifact("12345") is None
    assert (
        TwitterXOauthProvider().authenticate_request(
            {"X-Twitter-OAuth-Artifact": "not-a-real-token"}
        )
        is None
    )
    mgr = AuthManager([TwitterXOauthProvider(), BearerTokenProvider()])
    bearer = mgr.authenticate_request(
        {"Authorization": "Bearer test-control-plane-token-32b"}
    )
    assert bearer is not None and bearer.provider == "bearer"
