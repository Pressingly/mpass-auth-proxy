import hashlib
import importlib
import base64 as _b64
import json
import subprocess
import logging
import os
import sys
import time
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from jwt.exceptions import InvalidTokenError

import main as m


class _FakePyJWK:
    """Stub for PyJWK.from_dict — avoids needing a real RSA key in tests."""
    key = object()


# ---------------------------------------------------------------------------
# Test constants — obviously-fake values; never real env URLs
# ---------------------------------------------------------------------------
_ISSUER = "https://test-idp.example.com/pool-id"
_CLIENT_ID = "test-client-id"
_MONETA_UI_URL = "https://moneta-ui.example.com"
_AUTH_HOST = "test-auth.example.com"
_CALLBACK_URL = f"https://{_AUTH_HOST}/mpass-callback"
_REDIRECT_URI = f"https://{_AUTH_HOST}/oauth2/callback"
_COOKIE_DOMAIN = ".example.com"
_PORTAL_URL = "https://portal.example.com"
_LOGOUT_URI = "https://cognito-logout.example.com/logout"
_TEST_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

client = TestClient(m.app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def stub_launchpad_lookup():
    """Keep the launchpad DB out of the unit suite.

    The email overlay runs on every /token path, so without this each test
    attempts a real asyncpg.create_pool against postgres:5432 and pays a connect
    timeout. It also fails closed now, so an unstubbed lookup would turn every
    token test into a 503. Default: no verified row (the synthetic-email case).
    Tests that care override it explicitly."""
    with patch("main._lookup_real_email", new=AsyncMock(return_value=None)):
        yield


@pytest.fixture(autouse=True)
def reset_launchpad_pool_state():
    """The pool negative-cache is module state; a failure in one test would
    otherwise suppress retries in the next."""
    m._launchpad_pool = None
    m._launchpad_pool_failed_at = None
    yield
    m._launchpad_pool = None
    m._launchpad_pool_failed_at = None


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    m._jwks_cache = None
    m._jwks_fetched_at = None
    m._token_endpoint_cache = None
    yield


@pytest.fixture()
def fake_token_endpoint():
    """Pre-populate the token-endpoint cache so refresh-token tests don't hit the
    OIDC discovery doc over the network. Tests that exercise _get_token_endpoint
    directly should NOT use this fixture."""
    m._token_endpoint_cache = "https://test-idp.example.com/oauth2/token"
    yield m._token_endpoint_cache
    m._token_endpoint_cache = None


@pytest.fixture()
def fake_redis(monkeypatch):
    store: dict[str, str] = {}

    class FakeRedis:
        async def get(self, key: str) -> str | None:
            return store.get(key)

        async def getdel(self, key: str) -> str | None:
            return store.pop(key, None)

        async def setex(self, key: str, ttl: int, value: str) -> None:
            store[key] = value

        async def delete(self, key: str) -> None:
            store.pop(key, None)

    monkeypatch.setattr(m, "redis_client", FakeRedis())
    return store


class TestHealth:
    def test_returns_ok(self):
        assert client.get("/health").json() == {"status": "ok"}


class TestRequiredEnvVars:
    def test_missing_cookie_domain_raises_at_import(self, monkeypatch):
        """main.py must raise KeyError (not silently use a default) if COOKIE_DOMAIN is unset."""
        monkeypatch.delenv("COOKIE_DOMAIN", raising=False)
        sys.modules.pop("main", None)
        try:
            with pytest.raises(KeyError):
                importlib.import_module("main")
        finally:
            sys.modules.pop("main", None)
            sys.modules["main"] = m  # restore so subsequent patch("main.*") calls work

    def test_missing_redis_url_raises_at_import(self, monkeypatch):
        """main.py must raise KeyError (not silently use a default) if REDIS_URL is unset."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        sys.modules.pop("main", None)
        try:
            with pytest.raises(KeyError):
                importlib.import_module("main")
        finally:
            sys.modules.pop("main", None)
            sys.modules["main"] = m  # restore so subsequent patch("main.*") calls work

    @pytest.mark.parametrize("secret_value", ["", "   "])
    def test_empty_or_whitespace_client_secret_emits_warning_not_exception(
        self, monkeypatch, secret_value, caplog
    ):
        """main.py must not raise when OIDC_CLIENT_SECRET is empty or whitespace-only."""
        monkeypatch.setenv("OIDC_CLIENT_SECRET", secret_value)
        sys.modules.pop("main", None)
        try:
            with caplog.at_level(logging.WARNING):
                mod = importlib.import_module("main")
            assert mod.OIDC_CLIENT_SECRET == ""
            assert any("public-client mode" in r.message for r in caplog.records)
        finally:
            sys.modules.pop("main", None)
            sys.modules["main"] = m  # restore so subsequent patch("main.*") calls work


class TestVerifyPkce:
    def _make_challenge(self, verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return _b64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def test_valid_verifier_returns_true(self):
        verifier = _TEST_PKCE_VERIFIER
        challenge = self._make_challenge(verifier)
        assert m._verify_pkce(verifier, challenge) is True

    def test_wrong_verifier_returns_false(self):
        challenge = self._make_challenge("correct-verifier")
        assert m._verify_pkce("wrong-verifier", challenge) is False

    def test_empty_verifier_returns_false(self):
        challenge = self._make_challenge("some-verifier")
        assert m._verify_pkce("", challenge) is False


class TestPortalUrlDerivation:
    def test_explicit_portal_url_with_query_is_preserved(self, monkeypatch):
        monkeypatch.setenv("PORTAL_URL", "  https://portal.example.com/?foo=bar  ")
        assert m._derive_portal_url() == "https://portal.example.com/?foo=bar"

    def test_fallback_portal_url_is_derived_from_callback_host(self, monkeypatch):
        monkeypatch.delenv("PORTAL_URL", raising=False)
        monkeypatch.setattr(m, "MPASS_CALLBACK_URL", "https://auth.local.moneta.dev/mpass-callback")
        assert m._derive_portal_url() == "https://local.moneta.dev/"


class TestBridgeAuthorize:
    def test_missing_state_returns_400(self):
        response = client.get(
            "/authorize",
            params={"redirect_uri": _REDIRECT_URI,
                    "code_challenge": "abc123"},
        )
        assert response.status_code == 400

    def test_missing_redirect_uri_returns_400(self):
        response = client.get(
            "/authorize",
            params={"state": "some-state",
                    "code_challenge": "abc123"},
        )
        assert response.status_code == 400

    def test_missing_code_challenge_returns_400(self):
        response = client.get(
            "/authorize",
            params={"state": "some-state",
                    "redirect_uri": _REDIRECT_URI},
        )
        assert response.status_code == 400

    def test_non_s256_method_returns_400(self):
        response = client.get(
            "/authorize",
            params={
                "state": "some-state",
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "abc123",
                "code_challenge_method": "plain",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400

    def test_external_redirect_uri_returns_400(self):
        response = client.get(
            "/authorize",
            params={
                "state": "some-state",
                "redirect_uri": "https://attacker.com/steal",
                "code_challenge": "abc123",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400

    def test_valid_params_stores_bridge_state_and_redirects(self, fake_redis):
        response = client.get(
            "/authorize",
            params={
                "state": "test-state-xyz",
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "scope": "openid profile email",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        location = response.headers["location"]
        assert urlparse(_MONETA_UI_URL).netloc in location
        assert f"client_id={_CLIENT_ID}" in location

        stored = json.loads(fake_redis["bridge_state:test-state-xyz"])
        assert stored["redirect_uri"] == _REDIRECT_URI
        assert stored["state"] == "test-state-xyz"
        assert stored["code_challenge"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert "code_challenge_method" not in stored

    def test_valid_params_sets_mpass_bridge_cookie(self, fake_redis):
        response = client.get(
            "/authorize",
            params={
                "state": "cookie-state-abc",
                "redirect_uri": _REDIRECT_URI,
                "code_challenge": "challenge-value",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        set_cookie = " ".join(response.headers.get_list("set-cookie"))
        assert "mpass_bridge=cookie-state-abc" in set_cookie


class TestBridgeCallback:
    def _seed_bridge_state(self, fake_redis: dict, state: str = "test-state-xyz") -> None:
        fake_redis[f"bridge_state:{state}"] = json.dumps({
            "redirect_uri": _REDIRECT_URI,
            "state": state,
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        })

    def test_missing_id_token_returns_400(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        response = client.get(
            "/mpass-callback",
            cookies={"mpass_bridge": "test-state-xyz"},
        )
        assert response.status_code == 400

    def test_missing_bridge_cookie_redirects_to_portal(self, fake_redis):
        """User-facing failure (tab lost the race, stale deep link) — redirect
        to portal with ?login_error=expired_flow instead of a 400 page."""
        response = client.get("/mpass-callback?id_token=some.token", follow_redirects=False)
        assert response.status_code == 302
        assert "login_error=expired_flow" in response.headers["location"]
        assert response.headers["location"].startswith(m.PORTAL_URL)

    def test_expired_bridge_state_redirects_to_portal(self, fake_redis):
        response = client.get(
            "/mpass-callback?id_token=some.token",
            cookies={"mpass_bridge": "nonexistent-state"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "login_error=expired_flow" in response.headers["location"]

    def test_invalid_jwt_returns_401(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks:
            mock_jwks.return_value = {"keys": []}
            response = client.get(
                "/mpass-callback?id_token=not.a.real.jwt&access_token=some.token",
                cookies={"mpass_bridge": "test-state-xyz"},
            )
        assert response.status_code == 401

    def test_wrong_issuer_returns_401(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.jwt.decode", side_effect=InvalidTokenError("iss mismatch: got 'https://evil.example.com'")):
            mock_jwks.return_value = {"keys": []}
            response = client.get(
                "/mpass-callback?id_token=fake.token&access_token=fake.access",
                cookies={"mpass_bridge": "test-state-xyz"},
            )
        assert response.status_code == 401

    def test_missing_access_token_returns_502(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        fake_claims = {
            "iss": _ISSUER,
            "sub": "alice",
            "exp": 9_999_999_999,
        }
        id_token = _make_jwt_with_kid(fake_claims, kid="k1")
        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=fake_claims):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            response = client.get(
                f"/mpass-callback?id_token={id_token}",
                cookies={"mpass_bridge": "test-state-xyz"},
            )
        assert response.status_code == 502

    def test_valid_token_creates_bridge_code_and_redirects(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        fake_claims = {
            "iss": _ISSUER,
            "sub": "alice",
            "exp": 9_999_999_999,
        }
        id_token = _make_jwt_with_kid(fake_claims, kid="k1")
        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=fake_claims):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            response = client.get(
                f"/mpass-callback?id_token={id_token}&access_token=real.access.token",
                cookies={"mpass_bridge": "test-state-xyz"},
                follow_redirects=False,
            )

        assert response.status_code == 302
        location = response.headers["location"]
        assert f"{_AUTH_HOST}/oauth2/callback" in location
        assert "code=" in location
        assert "state=test-state-xyz" in location

        parsed = urlparse(location)
        code = parse_qs(parsed.query)["code"][0]
        assert f"bridge_code:{code}" in fake_redis

        stored = json.loads(fake_redis[f"bridge_code:{code}"])
        assert stored["id_token"] == id_token
        assert stored["access_token"] == "real.access.token"
        assert stored["code_challenge"] == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert "code_challenge_method" not in stored

    def test_valid_token_clears_bridge_state_and_cookie(self, fake_redis):
        self._seed_bridge_state(fake_redis)
        fake_claims = {
            "iss": _ISSUER,
            "sub": "bob",
            "exp": 9_999_999_999,
        }
        id_token = _make_jwt_with_kid(fake_claims, kid="k1")
        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=fake_claims):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            response = client.get(
                f"/mpass-callback?id_token={id_token}&access_token=cognito.access",
                cookies={"mpass_bridge": "test-state-xyz"},
                follow_redirects=False,
            )

        assert "bridge_state:test-state-xyz" not in fake_redis
        set_cookie = " ".join(response.headers.get_list("set-cookie"))
        assert "mpass_bridge" in set_cookie
        assert 'max-age=0' in set_cookie.lower() or 'expires=' in set_cookie.lower()


def _make_jwt(claims: dict) -> str:
    """Minimal unsigned JWT suitable for get_unverified_claims in tests."""
    def b64(data: dict) -> str:
        return _b64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{b64({'alg':'RS256','typ':'JWT'})}.{b64(claims)}.fakesig"


def _make_jwt_with_kid(claims: dict, kid: str) -> str:
    """Unsigned JWT with a specific kid in the header, for key-selection tests."""
    def b64(data: dict) -> str:
        return _b64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'RS256', 'typ': 'JWT', 'kid': kid})}.{b64(claims)}.fakesig"


class TestBridgeCallbackKidSelection:
    """jwt.decode must receive the single JWK matching the token kid, not the full JWKS."""

    def _seed_state(self, fake_redis: dict, state: str = "kid-test-state") -> None:
        fake_redis[f"bridge_state:{state}"] = json.dumps({
            "redirect_uri": _REDIRECT_URI,
            "state": state,
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        })

    def test_decode_receives_matching_jwk_not_full_document(self, fake_redis):
        self._seed_state(fake_redis)
        target_key = {"kid": "key-abc", "kty": "RSA", "use": "sig"}
        other_key = {"kid": "key-xyz", "kty": "RSA", "use": "sig"}
        token = _make_jwt_with_kid({"sub": "alice", "exp": 9_999_999_999}, kid="key-abc")
        fake_claims = {"iss": _ISSUER, "sub": "alice", "exp": 9_999_999_999}

        selected_jwk = {}

        # PyJWK.from_dict is called with the selected JWK dict; capture that argument
        # so we can assert the correct key was picked without needing a real RSA key.
        def capturing_from_dict(jwk_dict):
            selected_jwk["dict"] = jwk_dict
            return _FakePyJWK()

        def capturing_decode(tok, key, **kw):
            return fake_claims

        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", side_effect=capturing_from_dict), \
             patch("main.jwt.decode", side_effect=capturing_decode):
            mock_jwks.return_value = {"keys": [other_key, target_key]}
            client.get(
                f"/mpass-callback?id_token={token}&access_token=real.token",
                cookies={"mpass_bridge": "kid-test-state"},
                follow_redirects=False,
            )

        assert selected_jwk.get("dict") == target_key, (
            f"PyJWK.from_dict should receive the matching JWK, got {selected_jwk.get('dict')!r}"
        )

    def test_no_matching_kid_returns_401_without_calling_decode(self, fake_redis):
        self._seed_state(fake_redis)
        token = _make_jwt_with_kid({"sub": "alice"}, kid="key-abc")

        decode_was_called = []

        def should_not_be_called(*a, **kw):
            decode_was_called.append(True)
            return {"iss": _ISSUER, "sub": "alice", "exp": 9_999_999_999}

        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.jwt.decode", side_effect=should_not_be_called):
            mock_jwks.return_value = {"keys": [{"kid": "different-key", "kty": "RSA"}]}
            response = client.get(
                f"/mpass-callback?id_token={token}&access_token=real.token",
                cookies={"mpass_bridge": "kid-test-state"},
            )

        assert response.status_code == 401
        assert not decode_was_called, "jwt.decode must not be called when no key matches kid"


class TestBridgeCallbackAtomicStateConsumption:
    """bridge_state must be consumed atomically (GETDEL) before token verification."""

    def _seed_state(self, fake_redis: dict, state: str = "atomic-test-state") -> None:
        fake_redis[f"bridge_state:{state}"] = json.dumps({
            "redirect_uri": _REDIRECT_URI,
            "state": state,
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        })

    def test_bridge_state_absent_from_redis_when_jwt_decode_is_called(self, fake_redis):
        """GETDEL must remove bridge_state before jwt.decode runs, closing the replay window."""
        self._seed_state(fake_redis)
        id_token = _make_jwt_with_kid({"sub": "u", "exp": 9_999_999_999}, kid="k1")
        fake_claims = {"iss": _ISSUER, "sub": "u", "exp": 9_999_999_999}

        state_key = "bridge_state:atomic-test-state"
        state_present_at_decode = []

        def capturing_decode(tok, key, **kw):
            state_present_at_decode.append(state_key in fake_redis)
            return fake_claims

        with patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", side_effect=capturing_decode):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            client.get(
                f"/mpass-callback?id_token={id_token}&access_token=real.token",
                cookies={"mpass_bridge": "atomic-test-state"},
                follow_redirects=False,
            )

        assert state_present_at_decode == [False], (
            "bridge_state must already be removed from Redis before jwt.decode is called "
            "(use GETDEL, not GET + later DELETE)"
        )



def _make_pkce_pair(verifier: str) -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = _b64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class TestBridgeToken:
    def _seed_bridge_code(
        self,
        fake_redis: dict,
        code: str = "test-code-uuid",
        verifier: str = _TEST_PKCE_VERIFIER,
        refresh_token: str = "real.cognito.refresh_token",
    ) -> None:
        _, challenge = _make_pkce_pair(verifier)
        fake_redis[f"bridge_code:{code}"] = json.dumps({
            "id_token": _make_jwt({"sub": "testuser", "exp": int(time.time()) + 3600}),
            "access_token": "real.cognito.access_token",
            "refresh_token": refresh_token,
            "code_challenge": challenge,
        })

    def test_authorization_code_returns_503_when_overlay_unavailable(
        self, fake_redis, fake_token_endpoint
    ):
        """The first-login path, not just refresh.

        This is the branch that fails first in a launchpad outage: a user who
        has never logged in cannot, where a refreshing user at least had a
        working session moments ago. It had no coverage at all."""
        self._seed_bridge_code(fake_redis)

        with patch("main._lookup_real_email",
                   new=AsyncMock(side_effect=Exception("db down"))):
            response = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "test-code-uuid",
                    "code_verifier": _TEST_PKCE_VERIFIER,
                },
            )

        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"

    def test_unsupported_grant_type_returns_400(self, fake_redis):
        response = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
        )
        assert response.status_code == 400

    def test_missing_code_returns_400(self, fake_redis):
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code_verifier": "some-verifier",
            },
        )
        assert response.status_code == 400

    def test_unknown_code_returns_400(self, fake_redis):
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "nonexistent-code",
                "code_verifier": "some-verifier",
            },
        )
        assert response.status_code == 400

    def test_wrong_code_verifier_returns_400(self, fake_redis):
        self._seed_bridge_code(fake_redis)
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code-uuid",
                "code_verifier": "totally-wrong-verifier",
            },
        )
        assert response.status_code == 400

    def test_missing_code_verifier_returns_400(self, fake_redis):
        self._seed_bridge_code(fake_redis)
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code-uuid",
            },
        )
        assert response.status_code == 400

    def test_valid_exchange_returns_tokens(self, fake_redis):
        verifier = _TEST_PKCE_VERIFIER
        self._seed_bridge_code(fake_redis, verifier=verifier)

        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code-uuid",
                "code_verifier": verifier,
                "redirect_uri": _REDIRECT_URI,
                "client_id": _CLIENT_ID,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["access_token"] == "real.cognito.access_token"
        assert body["token_type"] == "Bearer"
        assert body["refresh_token"] == "real.cognito.refresh_token"
        # expires_in must be the configured session duration, not the Cognito id_token
        # lifetime (~1h). Returning the token's exp caused oauth2-proxy to mark the
        # session as expired after 1 hour and attempt grant_type=refresh_token.
        assert body["expires_in"] == m.SESSION_EXPIRES_IN

    def test_valid_exchange_omits_refresh_token_when_absent(self, fake_redis):
        verifier = _TEST_PKCE_VERIFIER
        self._seed_bridge_code(fake_redis, verifier=verifier, refresh_token="")

        response = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": "test-code-uuid",
                  "code_verifier": verifier},
        )

        assert response.status_code == 200
        assert "refresh_token" not in response.json()

    def test_valid_exchange_deletes_code(self, fake_redis):
        verifier = _TEST_PKCE_VERIFIER
        self._seed_bridge_code(fake_redis, verifier=verifier)

        client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code-uuid",
                "code_verifier": verifier,
            },
        )

        assert "bridge_code:test-code-uuid" not in fake_redis

    def test_code_cannot_be_reused(self, fake_redis):
        verifier = _TEST_PKCE_VERIFIER
        self._seed_bridge_code(fake_redis, verifier=verifier)

        client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": "test-code-uuid",
                  "code_verifier": verifier},
        )
        second = client.post(
            "/token",
            data={"grant_type": "authorization_code", "code": "test-code-uuid",
                  "code_verifier": verifier},
        )
        assert second.status_code == 400


class TestTokenEndpointDiscovery:
    """The OIDC discovery doc resolves token_endpoint correctly even when the
    issuer URL and OAuth domain differ (e.g. AWS Cognito)."""

    _DISCOVERED_URL = "https://oauth.example.com/oauth2/token"

    def _fake_discovery_response(self, token_endpoint: str | None):
        class FakeResp:
            status_code = 200
            def raise_for_status(self): return None
            def json(self):
                doc = {"issuer": _ISSUER}
                if token_endpoint is not None:
                    doc["token_endpoint"] = token_endpoint
                return doc
        return FakeResp()

    def test_returns_token_endpoint_from_discovery_doc(self, monkeypatch):
        async def fake_get(self_inner, url, **kwargs):
            assert url.endswith("/.well-known/openid-configuration"), url
            return self._fake_discovery_response(self._DISCOVERED_URL)

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

        import asyncio
        assert asyncio.run(m._get_token_endpoint()) == self._DISCOVERED_URL

    def test_caches_after_first_call(self, monkeypatch):
        call_count = {"n": 0}

        async def counting_get(self_inner, url, **kwargs):
            call_count["n"] += 1
            return self._fake_discovery_response(self._DISCOVERED_URL)

        monkeypatch.setattr(httpx.AsyncClient, "get", counting_get)

        import asyncio
        first = asyncio.run(m._get_token_endpoint())
        second = asyncio.run(m._get_token_endpoint())
        assert first == second == self._DISCOVERED_URL
        assert call_count["n"] == 1, "discovery doc should only be fetched once"

    def test_refresh_uses_discovered_url_not_issuer(self, monkeypatch):
        """Regression test: refresh must POST to the discovered
        token_endpoint, not to OIDC_ISSUER_URL + '/oauth2/token'."""
        captured = {}

        async def fake_get(self_inner, url, **kwargs):
            return self._fake_discovery_response(self._DISCOVERED_URL)

        async def fake_post(self_inner, url, **kwargs):
            captured["url"] = url
            class FakeResp:
                status_code = 200
                text = ""
                def json(self): return {
                    "access_token": "x",
                    "id_token": _make_jwt({"sub": "u", "exp": 9_999_999_999}),
                    "token_type": "Bearer", "expires_in": 3600,
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "r"},
        )

        assert response.status_code == 200
        assert captured["url"] == self._DISCOVERED_URL, (
            f"refresh POSTed to {captured['url']!r}, expected discovered token_endpoint"
        )
        # Critical: must NOT be the old wrongly-derived URL
        assert not captured["url"].startswith(_ISSUER + "/oauth2/token")


class TestRefreshToken:
    def test_missing_refresh_token_returns_400(self):
        response = client.post("/token", data={"grant_type": "refresh_token"})
        assert response.status_code == 400

    def test_cognito_success_rotation_disabled_echoes_original(self, monkeypatch, fake_token_endpoint):
        """When Cognito has refresh-token rotation disabled (current production
        config), its /token response omits `refresh_token`. The bridge must
        echo the original back so oauth2-proxy keeps a valid token for the
        next refresh cycle."""
        idp_id_token = _make_jwt({"sub": "u", "iss": _ISSUER, "exp": 9_999_999_999})

        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 200
                text = ""
                def json(self): return {
                    "access_token": "new.cognito.access_token",
                    "id_token": idp_id_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "old.refresh.token"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["access_token"] == "new.cognito.access_token"
        # id_token is re-signed by mpass-auth-proxy (Approach A', ADR-0007), so it
        # differs from the IdP-issued token but preserves sub/exp.
        assert body["id_token"] != idp_id_token
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == m.SESSION_EXPIRES_IN
        assert body["refresh_token"] == "old.refresh.token"

    def test_cognito_success_rotation_enabled_forwards_new_token(self, monkeypatch, fake_token_endpoint):
        """When Cognito has refresh-token rotation enabled, its /token response
        includes a new `refresh_token`. The bridge must forward the new one to
        oauth2-proxy (not echo the original) so rotation actually takes effect.

        Regression test for the unconditional-echo bug — previously the bridge
        silently discarded Cognito's rotated refresh_token, locking the
        deployment into rotation-disabled mode regardless of Cognito config."""
        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 200
                text = ""
                def json(self): return {
                    "access_token": "new.cognito.access_token",
                    "id_token": _make_jwt({"sub": "u", "iss": _ISSUER, "exp": 9_999_999_999}),
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "rotated.refresh.token",
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "old.refresh.token"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["refresh_token"] == "rotated.refresh.token", (
            "Bridge must forward Cognito's new refresh_token when rotation is "
            "enabled, not echo the original"
        )

    def test_cognito_error_is_forwarded(self, monkeypatch, fake_token_endpoint):
        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 400
                text = "invalid_grant"
                def json(self): return {}
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "expired.token"},
        )

        assert response.status_code == 400

    def test_cognito_network_failure_returns_502(self, monkeypatch, fake_token_endpoint):
        async def fake_post(self_inner, url, **kwargs):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "some.token"},
        )

        assert response.status_code == 502


class TestMpassLogin:
    def test_redirects_to_oauth2_sign_in(self):
        response = client.get("/mpass/login", follow_redirects=False)

        assert response.status_code == 302
        assert response.headers["location"] == "/oauth2/sign_in"


class TestMpassLogout:
    def test_full_logout_redirects_to_sign_out_with_cognito_rd(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", _LOGOUT_URI)
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", _PORTAL_URL)

        response = client.get("/mpass/logout", follow_redirects=False)

        assert response.status_code == 302
        location = response.headers["location"]
        assert "/oauth2/sign_out" in location
        assert "rd=" in location

    def test_rd_param_decodes_to_valid_cognito_url(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", _LOGOUT_URI)
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", _PORTAL_URL)

        response = client.get("/mpass/logout", follow_redirects=False)
        location = response.headers["location"]

        parsed = urlparse(location)
        rd_raw = parse_qs(parsed.query)["rd"][0]
        rd_decoded = unquote(rd_raw)
        assert urlparse(_LOGOUT_URI).netloc in rd_decoded
        assert f"client_id={_CLIENT_ID}" in rd_decoded
        assert f"logout_uri={_PORTAL_URL}" in rd_decoded

    def test_rd_param_is_single_encoded(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", _LOGOUT_URI)
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", _PORTAL_URL)

        response = client.get("/mpass/logout", follow_redirects=False)
        location = response.headers["location"]

        parsed = urlparse(location)
        rd_raw = parse_qs(parsed.query)["rd"][0]
        # Double-encoding produces %25 sequences — must not be present
        assert "%25" not in rd_raw

    def test_no_cognito_config_redirects_to_sign_out_only(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", "")
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", "")

        response = client.get("/mpass/logout", follow_redirects=False)

        assert response.status_code == 302
        assert response.headers["location"] == "/oauth2/sign_out"

    def test_clears_mpass_bridge_cookie(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", "")
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", "")

        response = client.get("/mpass/logout", follow_redirects=False)

        set_cookie = " ".join(response.headers.get_list("set-cookie"))
        assert "mpass_bridge" in set_cookie
        assert "max-age=0" in set_cookie.lower() or "expires=" in set_cookie.lower()

    def test_partial_cognito_config_falls_back_to_sign_out_only(self, monkeypatch):
        monkeypatch.setattr(m, "OIDC_LOGOUT_URI", _LOGOUT_URI)
        monkeypatch.setattr(m, "LOGOUT_REDIRECT_URL", "")

        response = client.get("/mpass/logout", follow_redirects=False)

        assert response.status_code == 302
        assert response.headers["location"] == "/oauth2/sign_out"


def test_jwks_endpoint_returns_valid_structure():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    body = response.json()
    assert "keys" in body
    assert len(body["keys"]) == 1
    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "n" in key
    assert "e" in key
    assert "kid" in key


_CORPORATE_ID = "corp-uuid-1234"

# Cognito access_token claims for corporate-id tests
def _cognito_access_claims(**overrides):
    base = {
        "sub": "alice",
        "client_id": _CLIENT_ID,
        "token_use": "access",
        "iss": _ISSUER,
        "exp": 9_999_999_999,
        "custom:is_corporate": "true",
        "custom:corporate_id": _CORPORATE_ID,
    }
    base.update(overrides)
    return base


class TestCorporateIdValidation:
    """Layer 1 — mpass-auth-proxy corporate-id check in _bridge_callback_impl."""

    def _seed_bridge_state(self, fake_redis: dict, state: str = "corp-state") -> None:
        fake_redis[f"bridge_state:{state}"] = json.dumps({
            "redirect_uri": _REDIRECT_URI,
            "state": state,
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        })

    def _do_callback(self, fake_redis, access_claims, *, enforce_id=_CORPORATE_ID):
        self._seed_bridge_state(fake_redis)
        id_token = _make_jwt_with_kid({"sub": "alice", "exp": 9_999_999_999}, kid="k1")
        access_token = _make_jwt_with_kid(access_claims, kid="k1")
        id_claims = {"iss": _ISSUER, "sub": "alice", "exp": 9_999_999_999}

        with patch.object(m, "SMB_CORPORATE_ID", enforce_id), \
             patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode") as mock_decode, \
             patch("main.jwt.get_unverified_header") as mock_header:
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            mock_header.side_effect = lambda t: {"alg": "RS256", "typ": "JWT", "kid": "k1"}
            # First call is id_token decode, second is access_token decode
            mock_decode.side_effect = [id_claims, access_claims]
            return client.get(
                f"/mpass-callback?id_token={id_token}&access_token={access_token}",
                cookies={"mpass_bridge": "corp-state"},
                follow_redirects=False,
            )

    def test_enforcement_disabled_allows_any_user(self, fake_redis):
        response = self._do_callback(fake_redis, _cognito_access_claims(), enforce_id="")
        assert response.status_code == 302
        assert "login_error" not in response.headers.get("location", "")

    def test_matching_corporate_id_succeeds(self, fake_redis):
        response = self._do_callback(fake_redis, _cognito_access_claims())
        assert response.status_code == 302
        assert "login_error" not in response.headers.get("location", "")

    def test_mismatched_corporate_id_rejects(self, fake_redis):
        claims = _cognito_access_claims(**{"custom:corporate_id": "wrong-corp-id"})
        response = self._do_callback(fake_redis, claims)
        assert response.status_code == 302
        assert "login_error=access_denied" in response.headers["location"]

    def test_individual_account_rejected(self, fake_redis):
        claims = _cognito_access_claims()
        del claims["custom:is_corporate"]
        response = self._do_callback(fake_redis, claims)
        assert response.status_code == 302
        assert "login_error=access_denied" in response.headers["location"]

    def test_wrong_client_id_rejected(self, fake_redis):
        claims = _cognito_access_claims(client_id="other-client")
        response = self._do_callback(fake_redis, claims)
        assert response.status_code == 302
        assert "login_error=access_denied" in response.headers["location"]


class TestRefreshTokenCorporateId:
    """Layer 1 — corporate-id check during token refresh."""

    def test_matching_corporate_id_succeeds(self, monkeypatch, fake_token_endpoint):
        access_claims = _cognito_access_claims()
        new_access_token = _make_jwt_with_kid(access_claims, kid="k1")

        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 200
                text = ""
                def json(self_resp): return {
                    "access_token": new_access_token,
                    "id_token": "new.id.token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        with patch.object(m, "SMB_CORPORATE_ID", _CORPORATE_ID), \
             patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=access_claims), \
             patch("main.jwt.get_unverified_header", return_value={"alg": "RS256", "kid": "k1"}):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            response = client.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": "old.refresh"},
            )

        assert response.status_code == 200

    def test_mismatched_corporate_id_returns_403(self, monkeypatch, fake_token_endpoint):
        bad_claims = _cognito_access_claims(**{"custom:corporate_id": "wrong-corp"})
        new_access_token = _make_jwt_with_kid(bad_claims, kid="k1")

        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 200
                text = ""
                def json(self_resp): return {
                    "access_token": new_access_token,
                    "id_token": "new.id.token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        with patch.object(m, "SMB_CORPORATE_ID", _CORPORATE_ID), \
             patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=bad_claims), \
             patch("main.jwt.get_unverified_header", return_value={"alg": "RS256", "kid": "k1"}):
            mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
            response = client.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": "old.refresh"},
            )

        assert response.status_code == 403

    def test_enforcement_disabled_passes(self, monkeypatch, fake_token_endpoint):
        async def fake_post(self_inner, url, **kwargs):
            class FakeResp:
                status_code = 200
                text = ""
                def json(self_resp): return {
                    "access_token": "new.access",
                    "id_token": _make_jwt({"sub": "u", "exp": 9_999_999_999}),
                    "token_type": "Bearer", "expires_in": 3600,
                }
            return FakeResp()

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        with patch.object(m, "SMB_CORPORATE_ID", ""):
            response = client.post(
                "/token",
                data={"grant_type": "refresh_token", "refresh_token": "old.refresh"},
            )

        assert response.status_code == 200


class TestTestConstants:
    """Guard: module-level constants must be defined and obviously-fake."""
    def test_auth_host_is_example_domain(self):
        assert _AUTH_HOST.endswith(".example.com"), (
            f"_AUTH_HOST must use .example.com, got {_AUTH_HOST!r}"
        )

    def test_logout_uri_is_example_domain(self):
        assert urlparse(_LOGOUT_URI).netloc.endswith(".example.com"), (
            f"_LOGOUT_URI must use .example.com, got {urlparse(_LOGOUT_URI).netloc!r}"
        )

    def test_issuer_matches_env(self):
        assert _ISSUER == os.environ["OIDC_ISSUER_URL"]

    def test_cognito_issuer_constant_is_gone(self):
        import tests.test_main as _self
        assert not hasattr(_self, "COGNITO_ISSUER"), (
            "Remove module-level COGNITO_ISSUER; use _ISSUER instead"
        )


@pytest.mark.asyncio
async def test_overlay_replaces_email_for_verified_user():
    from main import _apply_email_overlay
    claims = {"sub": "test-sid", "cognito:username": "test-sid", "email": "test-sid@synthetic.example.com"}
    with patch("main._lookup_real_email", new=AsyncMock(return_value="real@example.com")):
        out = await _apply_email_overlay(claims)
    assert out["email"] == "real@example.com"


@pytest.mark.asyncio
async def test_overlay_sets_synthetic_email_for_unverified_user():
    """Input carries a real-looking address deliberately: with a synthetic input
    the assertion holds whether the code overwrites the claim or leaves it, so
    it could not detect a regression either way."""
    from main import _apply_email_overlay
    claims = {"sub": "test-sid", "cognito:username": "test-sid", "email": "stale@corp.example"}
    with patch("main._lookup_real_email", new=AsyncMock(return_value=None)):
        out = await _apply_email_overlay(claims)
    assert out["email"] == "test-sid@synthetic.example.com"


@pytest.mark.asyncio
async def test_overlay_raises_on_db_error():
    """A lookup failure must not be reported as "no verified email".

    Falling back to the synthetic address would issue a verified user a token
    identifying them as the synthetic address for the duration of the outage,
    and every
    downstream app keys identity on that claim -- so the same human arrives as
    two different principals, intermittently."""
    from main import _apply_email_overlay, EmailOverlayUnavailable
    claims = {"sub": "test-sid", "cognito:username": "test-sid", "email": "test-sid@synthetic.example.com"}
    with patch("main._lookup_real_email", new=AsyncMock(side_effect=Exception("db down"))):
        with pytest.raises(EmailOverlayUnavailable):
            await _apply_email_overlay(claims)


@pytest.mark.asyncio
async def test_token_refresh_returns_503_when_overlay_unavailable(
    monkeypatch, fake_token_endpoint
):
    """The 503 must reach the client rather than a downgraded identity."""
    async def fake_post(self_inner, url, **kwargs):
        class FakeResp:
            status_code = 200
            text = ""
            def json(self_resp): return {
                "access_token": "new.access",
                "id_token": _make_jwt({"sub": "u", "exp": 9_999_999_999}),
                "token_type": "Bearer", "expires_in": 3600,
            }
        return FakeResp()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    with patch("main._lookup_real_email", new=AsyncMock(side_effect=Exception("db down"))):
        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "old.refresh"},
        )

    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"


@pytest.mark.asyncio
async def test_pool_failure_is_negatively_cached(monkeypatch):
    """A down launchpad DB must cost one connect attempt per cooldown window,
    not one per login and refresh across the whole platform."""
    from main import EmailOverlayUnavailable
    attempts = {"n": 0}

    async def failing_create_pool(*args, **kwargs):
        attempts["n"] += 1
        raise OSError("connection refused")

    monkeypatch.setattr(m.asyncpg, "create_pool", failing_create_pool)

    with pytest.raises(OSError):
        await m._get_launchpad_pool()
    assert attempts["n"] == 1

    # Second call inside the cooldown must not touch the network.
    with pytest.raises(EmailOverlayUnavailable):
        await m._get_launchpad_pool()
    assert attempts["n"] == 1


def test_load_signing_key_no_env_falls_back_to_ephemeral(monkeypatch, caplog):
    """Without GCP env vars, generates ephemeral key + warning log.

    Only reachable because tests/.env.test sets
    MPASS_SIGNING_KEY_ALLOW_EPHEMERAL=true; see the refusal test below."""
    monkeypatch.delenv("MPASS_SIGNING_KEY_GCP_PROJECT", raising=False)
    monkeypatch.delenv("MPASS_SIGNING_KEY_GCP_SECRET", raising=False)

    import main
    with caplog.at_level("WARNING"):
        key, kid = main._load_signing_key()

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    assert isinstance(key, RSAPrivateKey)
    assert len(kid) == 32  # UUID hex
    assert any("ephemeral" in r.message.lower() for r in caplog.records)
    assert any("local development" in r.message.lower() for r in caplog.records)


def test_load_signing_key_refuses_ephemeral_when_not_opted_in(monkeypatch):
    """Without the opt-in, a missing GCP config must stop the process.

    _EPHEMERAL_SIGNING_KEY_ALLOWED is read from the environment at import time,
    so this patches the module attribute rather than the env var -- setenv here
    would be a no-op and the test would pass without exercising anything."""
    monkeypatch.delenv("MPASS_SIGNING_KEY_GCP_PROJECT", raising=False)
    monkeypatch.delenv("MPASS_SIGNING_KEY_GCP_SECRET", raising=False)

    import main
    monkeypatch.setattr(main, "_EPHEMERAL_SIGNING_KEY_ALLOWED", False)
    with pytest.raises(RuntimeError, match="ephemeral RSA signing key"):
        main._load_signing_key()


def test_load_signing_key_refuses_when_gcp_load_fails(monkeypatch):
    """A configured-but-unreachable Secret Manager must also stop the process.

    Previously this path logged a warning and silently degraded to an ephemeral
    key, which is the same platform-wide forced re-login as having no config at
    all -- only harder to notice, because the vars look correctly set."""
    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_PROJECT", "test-project")
    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_SECRET", "test-secret")

    import main
    monkeypatch.setattr(main, "_EPHEMERAL_SIGNING_KEY_ALLOWED", False)

    import sys, types
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    def _boom(*a, **k):
        raise RuntimeError("secret manager unreachable")
    fake_sm.SecretManagerServiceClient = _boom
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)

    with pytest.raises(RuntimeError, match="ephemeral RSA signing key"):
        main._load_signing_key()


def test_load_signing_key_with_gcp_loads_from_secret_manager(monkeypatch, caplog):
    """With GCP env vars + valid secret, loads key from Secret Manager."""
    from unittest.mock import patch, MagicMock
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    test_pem = test_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_PROJECT", "test-project")
    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_SECRET", "test-secret")

    mock_response = MagicMock()
    mock_response.payload.data = test_pem
    mock_client = MagicMock()
    mock_client.access_secret_version.return_value = mock_response

    with patch("google.cloud.secretmanager.SecretManagerServiceClient", return_value=mock_client):
        import main
        with caplog.at_level("INFO"):
            key, kid = main._load_signing_key()

    test_pub_der = test_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded_pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert test_pub_der == loaded_pub_der
    assert len(kid) == 32
    assert any("GCP Secret Manager" in r.message for r in caplog.records)


def test_load_signing_key_with_gcp_falls_back_on_error(monkeypatch, caplog):
    """With GCP env vars but Secret Manager fetch failing, falls back + warns."""
    from unittest.mock import patch, MagicMock

    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_PROJECT", "test-project")
    monkeypatch.setenv("MPASS_SIGNING_KEY_GCP_SECRET", "test-secret")

    mock_client = MagicMock()
    mock_client.access_secret_version.side_effect = Exception("permission denied")

    with patch("google.cloud.secretmanager.SecretManagerServiceClient", return_value=mock_client):
        import main
        with caplog.at_level("WARNING"):
            key, kid = main._load_signing_key()

    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    assert isinstance(key, RSAPrivateKey)
    assert any("Failed to load" in r.message for r in caplog.records)
    assert any("permission denied" in r.message.lower() for r in caplog.records)


def test_resign_id_token_produces_token_verifiable_with_jwks():
    """Re-signed token must verify against our own JWKS."""
    import jwt as _jwt
    from main import _resign_id_token, _jwks_document, _SIGNING_KID

    original_claims = {
        "sub": "test-user-123",
        "cognito:username": "test-user-123",
        "email": "test-user-123@synthetic.example.com",
        "aud": "test-client",
        "iss": "https://cognito.example/abc",
        "exp": 9999999999,
        "iat": 1000000000,
    }
    new_token = _resign_id_token(original_claims)
    # Verify the new token against OUR JWKS (Approach A')
    jwks = _jwks_document()
    key = _jwt.PyJWK.from_dict(jwks["keys"][0])
    decoded = _jwt.decode(
        new_token,
        key.key,
        algorithms=["RS256"],
        audience="test-client",
        issuer="http://mpass-auth-proxy:8000",
    )
    # Original sub/email preserved; iss replaced with ours
    assert decoded["sub"] == "test-user-123"
    assert decoded["email"] == "test-user-123@synthetic.example.com"
    assert decoded["iss"] == "http://mpass-auth-proxy:8000"
    # kid header matches our JWKS
    header = _jwt.get_unverified_header(new_token)
    assert header["kid"] == _SIGNING_KID


class TestEmailCaptureDisabled:
    """The off state is the whole point of the flag: this branch must be inert
    on merge. _EMAIL_CAPTURE_ENABLED is read at import, so these patch the
    module attribute rather than the environment."""

    @pytest.mark.asyncio
    async def test_issue_id_token_echoes_idp_token_unchanged(self):
        """No overlay, no re-signing -- byte-for-byte what the IdP issued.

        oauth2-proxy is pointed at the IdP's JWKS when the flag is off, so
        anything other than a verbatim echo fails verification for every user."""
        idp_token = _make_jwt({"sub": "u", "email": "real@corp.example",
                               "exp": 9_999_999_999})
        with patch.object(m, "_EMAIL_CAPTURE_ENABLED", False):
            out = await m._issue_id_token(idp_token)
        assert out == idp_token

    @pytest.mark.asyncio
    async def test_disabled_path_never_touches_the_launchpad_database(self):
        """A launchpad DB that does not exist yet must not affect logins."""
        lookup = AsyncMock(side_effect=AssertionError("must not be called"))
        idp_token = _make_jwt({"sub": "u", "exp": 9_999_999_999})
        with patch.object(m, "_EMAIL_CAPTURE_ENABLED", False), \
             patch("main._lookup_real_email", new=lookup):
            out = await m._issue_id_token(idp_token)
        assert out == idp_token
        lookup.assert_not_awaited()

    def test_jwks_endpoint_404s_when_disabled(self):
        """Serving a key set while oauth2-proxy trusts the IdP would be worse
        than 404: verification would fail with no indication why."""
        with patch.object(m, "_EMAIL_CAPTURE_ENABLED", False):
            response = client.get("/.well-known/jwks.json")
        assert response.status_code == 404
        assert "not the token signer" in response.json()["detail"]

    def test_jwks_endpoint_serves_a_key_when_enabled(self):
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert len(response.json()["keys"]) == 1


class TestEmailCaptureImportTime:
    """The flag is read at import, and the other tests patch it afterwards --
    so nothing in this file otherwise covers what happens at import. These run
    a real subprocess because that is the only way to exercise it."""

    _BASE_ENV = {
        "OIDC_ISSUER_URL": "https://idp.example.com/pool",
        "OIDC_CLIENT_ID": "test-client-id",
        "MONETA_HOSTED_UI_URL": "https://ui.example.com",
        "MPASS_CALLBACK_URL": "https://auth.example.com/mpass-callback",
        "REDIS_URL": "redis://localhost:6379/0",
        "COOKIE_DOMAIN": ".example.com",
    }

    def _import_with(self, **overrides) -> subprocess.CompletedProcess:
        env = {"PATH": os.environ["PATH"], **self._BASE_ENV, **overrides}
        return subprocess.run(
            [sys.executable, "-c", "import main"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=env, capture_output=True, text=True,
        )

    def test_disabled_imports_with_nothing_configured(self):
        """The inert state must not need a signing key, a synthetic domain or a
        database password. If it did, merging this branch would require every
        deployment to configure a feature it is not running."""
        result = self._import_with(LAUNCHPAD_EMAIL_CAPTURE="false")
        assert result.returncode == 0, result.stderr

    def test_enabled_without_signing_key_refuses_to_start(self):
        result = self._import_with(
            LAUNCHPAD_EMAIL_CAPTURE="true",
            SYNTHETIC_EMAIL_DOMAIN="synthetic.example.com",
            LAUNCHPAD_DB_PASSWORD="pw",
        )
        assert result.returncode != 0
        assert "ephemeral RSA signing key" in result.stderr

    def test_enabled_without_db_password_refuses_to_start(self):
        result = self._import_with(
            LAUNCHPAD_EMAIL_CAPTURE="true",
            SYNTHETIC_EMAIL_DOMAIN="synthetic.example.com",
            MPASS_SIGNING_KEY_ALLOW_EPHEMERAL="true",
        )
        assert result.returncode != 0
        assert "LAUNCHPAD_DB_PASSWORD is empty" in result.stderr

    def test_enabled_without_synthetic_domain_refuses_to_start(self):
        result = self._import_with(
            LAUNCHPAD_EMAIL_CAPTURE="true",
            LAUNCHPAD_DB_PASSWORD="pw",
            MPASS_SIGNING_KEY_ALLOW_EPHEMERAL="true",
        )
        assert result.returncode != 0
        assert "SYNTHETIC_EMAIL_DOMAIN is required" in result.stderr

    def test_enabled_fully_configured_imports(self):
        result = self._import_with(
            LAUNCHPAD_EMAIL_CAPTURE="true",
            SYNTHETIC_EMAIL_DOMAIN="synthetic.example.com",
            LAUNCHPAD_DB_PASSWORD="pw",
            MPASS_SIGNING_KEY_ALLOW_EPHEMERAL="true",
        )
        assert result.returncode == 0, result.stderr
