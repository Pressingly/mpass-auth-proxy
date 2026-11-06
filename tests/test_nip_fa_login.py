import hashlib
import json
import logging
from datetime import datetime
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

import main as m
from nip_fa.sealing import LOGIN_CODE_RECORD, SESSION_RECORD, RecordSealer
from nip_fa.sessions import REVALIDATION_INTERVAL_SECONDS, Identity, Session, decode_record, encode_record, session_key
from nip_fa.bodies import RequestTooLarge, read_body_within
from nip_fa.validation import b64url_sha256, is_loopback_callback, is_sha256_challenge, with_query_params
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    _CLIENT_ID,
    _ISSUER,
    _FakePyJWK,
    _cognito_access_claims,
    _make_jwt_with_kid,
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)

client = TestClient(m.app, raise_server_exceptions=True)

_HANDOFF_SECRET = "handoff-secret-NEVER-LOG-0123456789abcdefghij"
_HANDOFF_CHALLENGE = b64url_sha256(_HANDOFF_SECRET)
_RETURN_TO = "http://127.0.0.1:53682/callback"
_MPASS_ID = "mpass-id-1234"
_COGNITO_SUB = "cognito-sub-uuid-5678"
_REFRESH_TOKEN = "refresh-token-NEVER-LOG-abcdef"
_ROTATED_REFRESH_TOKEN = "rotated-refresh-NEVER-LOG-ghijk"
_T0 = 1_800_000_000
_OTHER_MASTER_SECRET = bytes.fromhex("cd" * 32)


def _sealer() -> RecordSealer:
    return m._buzz_adapter.sealer


def _stored_session(redis_store, token) -> Session:
    return decode_record(_sealer(), token, redis_store.values[session_key(token)])


class _RecordingRedis:
    def __init__(self):
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key):
        return self.values.get(key)

    async def getdel(self, key):
        self.ttls.pop(key, None)
        return self.values.pop(key, None)

    async def setex(self, key, ttl, value):
        self.values[key] = value
        self.ttls[key] = ttl

    async def set(self, key, value, *, xx=False, keepttl=False):
        if xx and key not in self.values:
            return None
        self.values[key] = value
        if not keepttl:
            self.ttls.pop(key, None)
        return True

    async def delete(self, key):
        self.values.pop(key, None)
        self.ttls.pop(key, None)

    async def exists(self, key):
        return int(key in self.values)

    def keys_with_prefix(self, prefix):
        return [key for key in self.values if key.startswith(prefix)]


@pytest.fixture()
def redis_store(monkeypatch):
    store = _RecordingRedis()
    monkeypatch.setattr(m, "redis_client", store)
    return store


class _Clock:
    def __init__(self, now: int):
        self.now = now

    def __call__(self) -> float:
        return float(self.now)


@pytest.fixture()
def clock(monkeypatch):
    fake = _Clock(_T0)
    monkeypatch.setattr(m._buzz_adapter.sessions, "_clock", fake)
    return fake


def _start_params(**overrides):
    params = {
        "return_to": _RETURN_TO,
        "handoff_challenge": _HANDOFF_CHALLENGE,
        "handoff_challenge_method": "S256",
    }
    params.update(overrides)
    return {key: value for key, value in params.items() if value is not None}


def _start(**overrides):
    return client.get("/nip-fa/v1/login/start", params=_start_params(**overrides), follow_redirects=False)


def _bridge_state(start_response) -> str:
    cookie = SimpleCookie()
    for header in start_response.headers.get_list("set-cookie"):
        cookie.load(header)
    return cookie["mpass_bridge"].value


def _id_claims(**overrides):
    claims = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": _COGNITO_SUB,
        "cognito:username": _MPASS_ID,
        "email": "cognito:default_val",
        "exp": 9_999_999_999,
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def _callback(
    state, *, id_claims=None, access_claims=None, corporate_id="", refresh_token=_REFRESH_TOKEN,
    real_email="jane.doe@corp.example",
):
    id_claims = id_claims or _id_claims()
    access_claims = access_claims or _cognito_access_claims()
    id_token = _make_jwt_with_kid(id_claims, kid="k1")
    access_token = _make_jwt_with_kid(access_claims, kid="k1")
    query = {"id_token": id_token, "access_token": access_token}
    if refresh_token:
        query["refresh_token"] = refresh_token
    with patch.object(m, "SMB_CORPORATE_ID", corporate_id), \
         patch("main._get_jwks", new_callable=AsyncMock) as mock_jwks, \
         patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
         patch("main.jwt.decode", side_effect=[id_claims, access_claims]), \
         patch("main._lookup_real_email", new=AsyncMock(return_value=real_email)):
        mock_jwks.return_value = {"keys": [{"kid": "k1", "kty": "RSA"}]}
        return client.get(
            "/mpass-callback",
            params=query,
            cookies={"mpass_bridge": state},
            follow_redirects=False,
        )


def _login_code(**callback_kwargs) -> str:
    start = _start()
    response = _callback(_bridge_state(start), **callback_kwargs)
    assert response.status_code == 302, response.text
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def _exchange(code, secret=_HANDOFF_SECRET, **extra):
    return client.post("/nip-fa/v1/login/exchange", json={"code": code, "handoff_secret": secret, **extra})


def _session(token):
    return client.get("/nip-fa/v1/session", headers={"Authorization": f"Bearer {token}"})


def _signed_in(redis_store, clock) -> str:
    response = _exchange(_login_code())
    assert response.status_code == 200, response.text
    return response.json()["session_token"]


def _idp_refresh_response(status_code=200, body=None):
    body = body if body is not None else {"access_token": "new.access", "id_token": "new.id"}

    async def fake_post(self_inner, url, **kwargs):
        return httpx.Response(status_code, json=body)

    return fake_post


class TestReturnToValidation:
    @pytest.mark.parametrize("return_to", [
        "http://127.0.0.1:1/",
        "http://127.0.0.1:53682/callback",
        "http://127.0.0.1:65535",
        "http://[::1]:8080/cb",
        "http://[::1]:49152/oauth/callback?client=buzz",
    ])
    def test_accepts_exact_loopback_literal_on_any_port(self, return_to):
        assert is_loopback_callback(return_to)

    @pytest.mark.parametrize("return_to", [
        "http://localhost:8080/cb",
        "http://127.0.0.2:8080/cb",
        "http://127.1:8080/cb",
        "http://0.0.0.0:8080/cb",
        "http://[0:0:0:0:0:0:0:1]:8080/cb",
        "http://[::ffff:127.0.0.1]:8080/cb",
        "https://127.0.0.1:8080/cb",
        "HTTP://127.0.0.1:8080/cb",
        "http://user@127.0.0.1:8080/cb",
        "http://user:pw@127.0.0.1:8080/cb",
        "http://127.0.0.1:80@evil.example.com/cb",
        "http://evil.example.com#@127.0.0.1:8080",
        "http://127.0.0.1.:8080/cb",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:/cb",
        "http://127.0.0.1:0/cb",
        "http://127.0.0.1:080/cb",
        "http://127.0.0.1:65536/cb",
        "http://127.0.0.1:8080/cb#frag",
        "http://127.0.0.1:8080/c b",
        "http://127.0.0.1:8080/cb\\x",
        "http://[::1:8080/cb",
        "http://[zz]:8080/cb",
        "http://::1]:8080/cb",
        "http://[::1]]:8080/cb",
        "http://127.0.0.1:8080/cb?code=planted",
        "http://127.0.0.1:8080/cb?a=1&error=planted",
        "http://127.0.0.1:8080/cb?error_description=x",
        "http://127.0.0.1:8080/cb?%63ode=planted",
        "/callback",
        "127.0.0.1:8080/cb",
        "",
    ])
    def test_rejects_everything_else(self, return_to):
        assert not is_loopback_callback(return_to)

    def test_rejected_return_to_is_400_without_redirect(self, redis_store):
        response = _start(return_to="http://localhost:8080/cb")
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert response.headers["cache-control"] == "no-store"
        assert "location" not in response.headers
        assert redis_store.values == {}


    @pytest.mark.parametrize("return_to", ["http://[::1:8080/cb", "http://127.0.0.1:8080/cb?code=planted"])
    def test_malformed_or_reserved_return_to_is_400_at_the_route(self, redis_store, return_to):
        response = _start(return_to=return_to)
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert response.headers["cache-control"] == "no-store"
        assert redis_store.values == {}

    @pytest.mark.parametrize(("return_to", "expected"), [
        ("http://127.0.0.1:5000/cb", "http://127.0.0.1:5000/cb?code=C"),
        ("http://127.0.0.1:5000/cb?a=b%20c", "http://127.0.0.1:5000/cb?a=b%20c&code=C"),
        ("http://127.0.0.1:5000/cb?flag", "http://127.0.0.1:5000/cb?flag&code=C"),
        ("http://127.0.0.1:5000/cb?x=%2F&y=+", "http://127.0.0.1:5000/cb?x=%2F&y=+&code=C"),
        ("http://127.0.0.1:5000/cb?", "http://127.0.0.1:5000/cb?code=C"),
        ("http://127.0.0.1:5000/cb?a=1&", "http://127.0.0.1:5000/cb?a=1&code=C"),
    ])
    def test_callback_url_keeps_return_to_byte_for_byte(self, return_to, expected):
        assert with_query_params(return_to, {"code": "C"}) == expected


class TestLoginStart:
    def test_parks_tagged_bridge_state_and_redirects_to_moneta(self, redis_store):
        response = _start()

        assert response.status_code == 302
        assert response.headers["location"] == m._moneta_login_url()
        assert response.headers["cache-control"] == "no-store"
        state = _bridge_state(response)
        assert json.loads(redis_store.values[f"bridge_state:{state}"]) == {
            "flow": "nip-fa",
            "return_to": _RETURN_TO,
            "handoff_challenge": _HANDOFF_CHALLENGE,
        }
        assert redis_store.ttls[f"bridge_state:{state}"] == m.BRIDGE_STATE_TTL

    @pytest.mark.parametrize("method", ["plain", "s256", "", None])
    def test_rejects_non_s256_methods(self, redis_store, method):
        response = _start(handoff_challenge_method=method)
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}

    @pytest.mark.parametrize("challenge", [
        None,
        "",
        "too-short",
        _HANDOFF_CHALLENGE + "A",
        _HANDOFF_CHALLENGE[:-1] + "+",
        _HANDOFF_CHALLENGE[:-1] + "B",
    ])
    def test_rejects_challenges_that_are_not_b64url_sha256(self, redis_store, challenge):
        assert _start(handoff_challenge=challenge).status_code == 400

    def test_challenge_shape(self):
        assert is_sha256_challenge(_HANDOFF_CHALLENGE)
        assert len(_HANDOFF_CHALLENGE) == 43

    def test_rejects_repeated_parameters(self, redis_store):
        response = client.get(
            "/nip-fa/v1/login/start",
            params=[*_start_params().items(), ("return_to", "http://127.0.0.1:1/other")],
            follow_redirects=False,
        )
        assert response.status_code == 400


class TestLoginCallback:
    def test_success_redirects_to_return_to_with_code_only(self, redis_store, clock):
        start = _start()
        response = _callback(_bridge_state(start))

        assert response.status_code == 302
        assert response.headers["cache-control"] == "no-store"
        location = urlsplit(response.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == _RETURN_TO
        assert set(parse_qs(location.query)) == {"code"}
        assert redis_store.keys_with_prefix("bridge_code:") == []

    def test_code_is_stored_hashed_with_short_ttl(self, redis_store, clock):
        code = _login_code()
        code_keys = redis_store.keys_with_prefix("nip_fa_code:")
        assert len(code_keys) == 1
        assert code not in code_keys[0]
        assert 60 <= redis_store.ttls[code_keys[0]] <= 120

    def test_code_record_is_sealed_whole(self, redis_store, clock):
        code = _login_code()
        raw = redis_store.values[redis_store.keys_with_prefix("nip_fa_code:")[0]]
        for plaintext in (_REFRESH_TOKEN, _MPASS_ID, _COGNITO_SUB, _HANDOFF_CHALLENGE, "jane.doe@corp.example"):
            assert plaintext not in raw
        record = _sealer().unseal(code, raw, LOGIN_CODE_RECORD)
        assert record["refresh_token"] == _REFRESH_TOKEN
        assert record["handoff_challenge"] == _HANDOFF_CHALLENGE
        assert record["identity"]["sub"] == _MPASS_ID

    def test_preserves_existing_return_to_query(self, redis_store, clock):
        return_to = "http://[::1]:4000/cb?client=buzz%20desktop&flag"
        start = _start(return_to=return_to)
        response = _callback(_bridge_state(start))
        location = response.headers["location"]
        assert location.startswith(return_to + "&code=")
        code = location.removeprefix(return_to + "&code=")
        assert code and "&" not in code

    def test_corporate_id_failure_redirects_to_return_to_with_access_denied(self, redis_store, clock):
        start = _start()
        response = _callback(
            _bridge_state(start),
            access_claims=_cognito_access_claims(**{"custom:corporate_id": "other-corp"}),
            corporate_id="corp-uuid-1234",
        )

        assert response.status_code == 302
        location = urlsplit(response.headers["location"])
        assert response.headers["location"].startswith(_RETURN_TO)
        assert parse_qs(location.query) == {"error": ["access_denied"], "error_description": ["wrong_organization"]}
        assert "login_error" not in response.headers["location"]
        assert redis_store.keys_with_prefix("nip_fa_code:") == []

    def test_missing_cognito_username_fails_closed(self, redis_store, clock):
        start = _start()
        response = _callback(_bridge_state(start), id_claims=_id_claims(**{"cognito:username": None}))

        assert parse_qs(urlsplit(response.headers["location"]).query) == {"error": ["server_error"]}
        assert redis_store.keys_with_prefix("nip_fa_code:") == []

    def test_missing_refresh_token_fails_closed(self, redis_store, clock):
        start = _start()
        response = _callback(_bridge_state(start), refresh_token="")

        assert parse_qs(urlsplit(response.headers["location"]).query) == {"error": ["server_error"]}

    def test_email_overlay_outage_fails_closed(self, redis_store, clock):
        start = _start()
        with patch("main._lookup_verified_email", side_effect=m.EmailOverlayUnavailable("down")):
            response = _callback(_bridge_state(start))

        assert parse_qs(urlsplit(response.headers["location"]).query) == {"error": ["temporarily_unavailable"]}
        assert redis_store.keys_with_prefix("nip_fa_code:") == []


class TestCodeExchange:
    def test_happy_path_and_session_check_share_expires_at(self, redis_store, clock):
        exchange = _exchange(_login_code())

        assert exchange.status_code == 200
        assert exchange.headers["cache-control"] == "no-store"
        body = exchange.json()
        assert set(body) == {"session_token", "expires_at", "email", "profile_projection"}
        assert body["email"] == "jane.doe@corp.example"
        assert body["profile_projection"] == {"username": "jane.doe", "display_name": "jane.doe"}
        assert body["expires_at"].endswith("Z")
        expires_at = datetime.fromisoformat(body["expires_at"])
        assert expires_at.timestamp() == _T0 + m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds

        clock.now += 600
        session = _session(body["session_token"])
        assert session.status_code == 200
        assert session.headers["cache-control"] == "no-store"
        assert session.json() == {key: value for key, value in body.items() if key != "session_token"}
        assert datetime.fromisoformat(session.json()["expires_at"]) == expires_at

    def test_session_subject_is_the_mpass_id(self, redis_store, clock):
        token = _exchange(_login_code()).json()["session_token"]

        identity = _stored_session(redis_store, token).identity
        assert identity.sub == _MPASS_ID
        assert identity.cognito_sub == _COGNITO_SUB

    def test_session_is_stored_under_token_hash_with_matching_ttl(self, redis_store, clock):
        token = _exchange(_login_code()).json()["session_token"]

        session_keys = redis_store.keys_with_prefix("nip_fa_session:")
        assert session_keys == [session_key(token)]
        assert token not in session_keys[0]
        assert token not in redis_store.values[session_keys[0]]
        assert redis_store.ttls[session_keys[0]] == m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds
        assert len(token) >= 43

    def test_code_is_single_use(self, redis_store, clock):
        code = _login_code()
        assert _exchange(code).status_code == 200

        replay = _exchange(code)
        assert replay.status_code == 400
        assert replay.json() == {"error": "invalid_request"}
        assert len(redis_store.keys_with_prefix("nip_fa_session:")) == 1

    def test_wrong_handoff_secret_is_rejected_and_burns_the_code(self, redis_store, clock):
        code = _login_code()

        wrong = _exchange(code, secret="not-the-handoff-secret")
        assert wrong.status_code == 400
        assert wrong.json() == {"error": "invalid_request"}
        assert redis_store.keys_with_prefix("nip_fa_code:") == []
        assert _exchange(code).status_code == 400
        assert redis_store.keys_with_prefix("nip_fa_session:") == []

    def test_unknown_fields_are_rejected_without_burning_the_code(self, redis_store, clock):
        code = _login_code()

        response = _exchange(code, extra_field="x")
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert _exchange(code).status_code == 200

    @pytest.mark.parametrize("body", [
        b"",
        b"not json",
        b"[]",
        b'{"code": "c"}',
        b'{"handoff_secret": "s"}',
        b'{"code": 1, "handoff_secret": "s"}',
        b'{"code": "c", "handoff_secret": ""}',
    ])
    def test_malformed_bodies_are_invalid_request(self, redis_store, body):
        response = client.post(
            "/nip-fa/v1/login/exchange", content=body, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert response.headers["cache-control"] == "no-store"

    def test_oversized_body_is_rejected(self, redis_store):
        response = client.post(
            "/nip-fa/v1/login/exchange",
            content=json.dumps({"code": "c" * 5000, "handoff_secret": "s"}),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json() == {"error": "request_too_large"}

    def test_oversized_chunked_body_is_rejected(self, redis_store):
        def chunks():
            for _ in range(100):
                yield b"x" * 1024

        response = client.post(
            "/nip-fa/v1/login/exchange", content=chunks(), headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 413
        assert response.json() == {"error": "request_too_large"}

    def test_content_encoded_body_is_rejected(self, redis_store):
        response = client.post(
            "/nip-fa/v1/login/exchange",
            content=b"\x1f\x8b",
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        assert response.status_code == 400


class TestEmailVerification:
    def test_capture_on_refuses_a_user_without_a_verified_email(self, redis_store, clock, caplog):
        start = _start()
        with caplog.at_level(logging.INFO):
            response = _callback(_bridge_state(start), real_email=None)

        assert response.status_code == 302
        assert response.headers["location"].startswith(_RETURN_TO + "?")
        assert parse_qs(urlsplit(response.headers["location"]).query) == {
            "error": ["access_denied"],
            "error_description": ["email_verification_required"],
        }
        assert redis_store.keys_with_prefix("nip_fa_code:") == []
        refusals = [r.getMessage() for r in caplog.records if "email_verification_required" in r.getMessage()]
        assert refusals == [
            f"nip-fa: login refused for mpass_id={_MPASS_ID} reason=email_verification_required"
        ]

    def test_capture_on_verified_user_gets_the_verified_email(self, redis_store, clock):
        body = _exchange(_login_code(real_email="jane.doe@corp.example")).json()
        assert body["email"] == "jane.doe@corp.example"

    def test_capture_off_uses_the_id_token_email_without_a_lookup(self, redis_store, clock):
        lookup = AsyncMock(side_effect=AssertionError("launchpad must not be queried"))
        with patch.object(m, "_EMAIL_CAPTURE_ENABLED", False), patch("main._lookup_verified_email", new=lookup):
            body = _exchange(_login_code(id_claims=_id_claims(email="jane@corp.example"))).json()

        lookup.assert_not_awaited()
        assert body["email"] == "jane@corp.example"
        assert body["profile_projection"] == {"username": "jane", "display_name": "jane"}

    def test_capture_off_drops_cognitos_placeholder_email(self, redis_store, clock):
        with patch.object(m, "_EMAIL_CAPTURE_ENABLED", False):
            body = _exchange(_login_code()).json()

        assert "email" not in body
        assert body["profile_projection"] is None


_RECORD = {"refresh_token": _REFRESH_TOKEN}


class TestRecordSealing:
    def test_stored_session_record_is_sealed_whole(self, redis_store, clock):
        token = _signed_in(redis_store, clock)

        raw = redis_store.values[session_key(token)]
        for plaintext in (_REFRESH_TOKEN, _MPASS_ID, _COGNITO_SUB, "jane.doe@corp.example", "expires_at"):
            assert plaintext not in raw
        assert _stored_session(redis_store, token).refresh_token == _REFRESH_TOKEN

    def test_seal_round_trips_with_a_fresh_nonce_each_time(self):
        sealer = _sealer()
        first = sealer.seal("token-a", _RECORD, SESSION_RECORD)
        second = sealer.seal("token-a", _RECORD, SESSION_RECORD)
        assert first != second
        assert sealer.unseal("token-a", first, SESSION_RECORD) == _RECORD
        assert sealer.unseal("token-a", second, SESSION_RECORD) == _RECORD

    @pytest.mark.parametrize("sealed", ["", "not base64!", "AAAA", None, json.dumps(_RECORD)])
    def test_unseal_fails_closed_on_garbage(self, sealed):
        assert _sealer().unseal("token-a", sealed, SESSION_RECORD) is None

    def test_unseal_with_another_token_fails(self):
        sealer = _sealer()
        assert sealer.unseal("token-b", sealer.seal("token-a", _RECORD, SESSION_RECORD), SESSION_RECORD) is None

    def test_labels_do_not_open_each_other(self):
        sealer = _sealer()
        sealed = sealer.seal("secret", _RECORD, LOGIN_CODE_RECORD)
        assert sealer.unseal("secret", sealed, SESSION_RECORD) is None
        assert sealer.unseal("secret", sealed, LOGIN_CODE_RECORD) == _RECORD

    def test_another_master_secret_cannot_open_or_forge(self):
        foreign = RecordSealer(_OTHER_MASTER_SECRET)
        assert foreign.unseal("token-a", _sealer().seal("token-a", _RECORD, SESSION_RECORD), SESSION_RECORD) is None
        assert _sealer().unseal("token-a", foreign.seal("token-a", _RECORD, SESSION_RECORD), SESSION_RECORD) is None

    def test_sealer_repr_hides_its_key_material(self):
        assert repr(_sealer()) == "RecordSealer(<redacted>)"

    @pytest.mark.parametrize("forge", ["plaintext_json", "foreign_master"])
    def test_forged_session_for_an_invented_token_is_refused(self, redis_store, clock, forge):
        invented = "attacker-chosen-session-token-0123456789abcdef"
        session = Session(
            identity=Identity(sub="victim-mpass-id", cognito_sub="x", email="victim@corp.example"),
            refresh_token="r",
            expires_at=_T0 + 3600,
            revalidated_at=_T0,
        )
        forged = {
            "plaintext_json": json.dumps({
                "identity": {"sub": "victim-mpass-id", "cognito_sub": "x", "email": "victim@corp.example"},
                "refresh_token": "r", "expires_at": _T0 + 3600, "revalidated_at": _T0,
            }),
            "foreign_master": encode_record(RecordSealer(_OTHER_MASTER_SECRET), invented, session),
        }[forge]
        redis_store.values[session_key(invented)] = forged

        response = _session(invented)
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}

    def test_forged_login_code_is_refused(self, redis_store, clock):
        invented_code = "attacker-chosen-login-code-0123456789abcdef"
        forged = RecordSealer(_OTHER_MASTER_SECRET).seal(invented_code, {
            "handoff_challenge": _HANDOFF_CHALLENGE,
            "identity": {"sub": "victim-mpass-id", "cognito_sub": "x", "email": None},
            "refresh_token": "r",
        }, LOGIN_CODE_RECORD)
        redis_store.values["nip_fa_code:" + hashlib.sha256(invented_code.encode()).hexdigest()] = forged

        response = _exchange(invented_code)
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert redis_store.keys_with_prefix("nip_fa_session:") == []

    def test_record_moved_under_another_token_is_not_trusted(self, redis_store, clock):
        victim = _signed_in(redis_store, clock)
        attacker = _signed_in(redis_store, clock)
        redis_store.values[session_key(attacker)] = redis_store.values[session_key(victim)]

        response = _session(attacker)
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}
        assert _session(victim).status_code == 200


class _StubRequest:
    def __init__(self, headers: dict, chunks: list[bytes]):
        self.headers = headers
        self._chunks = chunks
        self.chunks_read = 0

    async def stream(self):
        for chunk in self._chunks:
            self.chunks_read += 1
            yield chunk


class TestBoundedBodyReader:
    @pytest.mark.asyncio
    async def test_declared_oversize_is_refused_before_reading(self):
        request = _StubRequest({"content-length": "4097"}, [b"x"])
        with pytest.raises(RequestTooLarge):
            await read_body_within(request, 4096)
        assert request.chunks_read == 0

    @pytest.mark.asyncio
    async def test_streamed_oversize_stops_at_the_chunk_that_crosses_the_limit(self):
        request = _StubRequest({}, [b"x" * 3000, b"x" * 3000, b"x" * 3000])
        with pytest.raises(RequestTooLarge):
            await read_body_within(request, 4096)
        assert request.chunks_read == 2

    @pytest.mark.asyncio
    async def test_understated_content_length_is_still_bounded(self):
        request = _StubRequest({"content-length": "10"}, [b"x" * 5000])
        with pytest.raises(RequestTooLarge):
            await read_body_within(request, 4096)

    @pytest.mark.asyncio
    async def test_body_at_the_limit_is_returned_whole(self):
        request = _StubRequest({"content-length": "8192"}, [b"a" * 4096, b"b" * 4096])
        assert await read_body_within(request, 8192) == b"a" * 4096 + b"b" * 4096


class TestSessionCheck:
    def test_missing_authorization_is_session_required(self, redis_store):
        response = client.get("/nip-fa/v1/session")
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}
        assert response.headers["cache-control"] == "no-store"

    def test_unknown_token_is_session_required(self, redis_store):
        response = _session("not-a-real-session-token")
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}

    @pytest.mark.parametrize("value", ["Bearer", "Bearer    "])
    def test_empty_bearer_is_session_required(self, redis_store, value):
        response = client.get("/nip-fa/v1/session", headers={"Authorization": value})
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}

    def test_non_bearer_scheme_is_invalid_request(self, redis_store):
        response = client.get("/nip-fa/v1/session", headers={"Authorization": "Basic dXNlcjpwdw=="})
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}

    def test_repeated_authorization_is_invalid_request(self, redis_store, clock):
        token = _signed_in(redis_store, clock)
        response = client.get(
            "/nip-fa/v1/session",
            headers=[("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}

    def test_session_past_expires_at_is_session_expired_and_deleted(self, redis_store, clock):
        token = _signed_in(redis_store, clock)
        clock.now += m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds

        response = _session(token)
        assert response.status_code == 401
        assert response.json() == {"error": "session_expired"}
        assert session_key(token) not in redis_store.values


class TestSessionRevalidation:
    def test_within_the_hour_does_not_call_the_idp(self, redis_store, clock, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        refresh = AsyncMock()
        monkeypatch.setattr(m, "_post_refresh_grant", refresh)
        clock.now += REVALIDATION_INTERVAL_SECONDS - 1

        assert _session(token).status_code == 200
        refresh.assert_not_awaited()

    def test_after_an_hour_refreshes_and_keeps_expires_at(self, redis_store, clock, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        original_expires_at = _session(token).json()["expires_at"]
        posted = {}

        async def fake_post(self_inner, url, **kwargs):
            posted.update(kwargs["data"])
            return httpx.Response(200, json={
                "access_token": "new.access", "id_token": "new.id", "refresh_token": _ROTATED_REFRESH_TOKEN,
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _session(token)
        assert response.status_code == 200
        assert response.json()["expires_at"] == original_expires_at
        assert posted["grant_type"] == "refresh_token"
        assert posted["refresh_token"] == _REFRESH_TOKEN
        raw = redis_store.values[session_key(token)]
        assert _ROTATED_REFRESH_TOKEN not in raw
        renewed = decode_record(_sealer(), token, raw)
        assert renewed.refresh_token == _ROTATED_REFRESH_TOKEN
        assert renewed.revalidated_at == clock.now
        assert redis_store.ttls[session_key(token)] == m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds

    def test_session_deleted_during_revalidation_is_not_resurrected(
        self, redis_store, clock, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)

        async def revoked_while_refreshing(self_inner, url, **kwargs):
            await redis_store.delete(session_key(token))
            return httpx.Response(200, json={
                "access_token": "new.access", "id_token": "new.id", "refresh_token": _ROTATED_REFRESH_TOKEN,
            })

        monkeypatch.setattr(httpx.AsyncClient, "post", revoked_while_refreshing)
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _session(token)
        assert response.status_code == 401
        assert response.json() == {"error": "session_expired"}
        assert session_key(token) not in redis_store.values

    def test_invalid_grant_ends_the_session(self, redis_store, clock, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(400, {"error": "invalid_grant"}))
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _session(token)
        assert response.status_code == 401
        assert response.json() == {"error": "session_expired"}
        assert session_key(token) not in redis_store.values
        assert _session(token).json() == {"error": "session_required"}

    def test_corporate_id_failure_ends_the_session(self, redis_store, clock, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        with patch("main._validate_corporate_id", side_effect=m.CorporateIdMismatch("gone", reason="wrong_organization")):
            response = _session(token)

        assert response.status_code == 401
        assert response.json() == {"error": "session_expired"}
        assert session_key(token) not in redis_store.values

    @pytest.mark.parametrize("failure", ["network", "idp_5xx", "idp_other_4xx", "bad_json"])
    def test_transient_idp_failure_keeps_the_session_and_retries_next_time(
        self, redis_store, clock, monkeypatch, fake_token_endpoint, failure
    ):
        """/v1/session answers 200 from the stored record while the IdP is
        unreachable: the session is still within its fixed lifetime, and
        revalidated_at is left alone so the next call asks the IdP again.
        Assertion issuance (next slice) turns the same outcome into 503
        issuance_unavailable instead."""
        token = _signed_in(redis_store, clock)
        before = redis_store.values[session_key(token)]

        async def network_down(self_inner, url, **kwargs):
            raise httpx.ConnectError("connection refused")

        async def bad_json(self_inner, url, **kwargs):
            return httpx.Response(200, content=b"<html>")

        fakes = {
            "network": network_down,
            "idp_5xx": _idp_refresh_response(503, {"error": "server_error"}),
            "idp_other_4xx": _idp_refresh_response(400, {"error": "invalid_client"}),
            "bad_json": bad_json,
        }
        monkeypatch.setattr(httpx.AsyncClient, "post", fakes[failure])
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _session(token)
        assert response.status_code == 200
        assert redis_store.values[session_key(token)] == before

    def test_jwks_outage_during_corporate_check_keeps_the_session(
        self, redis_store, clock, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        with patch("main._validate_corporate_id", side_effect=httpx.ConnectError("jwks down")):
            assert _session(token).status_code == 200
        assert session_key(token) in redis_store.values


def _is_test_client_request_line(record: logging.LogRecord) -> bool:
    """The suite's own TestClient logs each request URL it sends, including the
    simulated Moneta redirect's query string. That is the harness, not the service."""
    return record.name == "httpx" and "http://testserver/" in record.getMessage()


class TestRevalidationErrorHandling:
    def test_unexpected_error_from_the_refresh_call_is_not_swallowed(
        self, redis_store, clock, monkeypatch, fake_token_endpoint,
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(m, "_post_refresh_grant", AsyncMock(side_effect=TypeError("bug")))
        clock.now += REVALIDATION_INTERVAL_SECONDS

        with pytest.raises(TypeError):
            _session(token)

    @pytest.mark.parametrize("discovery", [
        httpx.Response(200, json={"issuer": "no token_endpoint"}),
        httpx.Response(200, content=b"<html>not json</html>"),
        httpx.Response(503, content=b"down"),
    ])
    def test_unusable_discovery_document_keeps_the_session(self, redis_store, clock, monkeypatch, discovery):
        token = _signed_in(redis_store, clock)
        before = redis_store.values[session_key(token)]
        m._token_endpoint_cache = None
        discovery.request = httpx.Request("GET", m.OIDC_DISCOVERY_URL)

        async def fake_get(self_inner, url, **kwargs):
            return discovery

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        clock.now += REVALIDATION_INTERVAL_SECONDS

        assert _session(token).status_code == 200
        assert redis_store.values[session_key(token)] == before

    def test_refresh_grant_uses_the_shared_idp_timeout(self, redis_store, clock, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        timeouts = []
        real_init = httpx.AsyncClient.__init__

        def recording_init(self_inner, *args, **kwargs):
            timeouts.append(kwargs.get("timeout"))
            real_init(self_inner, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", recording_init)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        assert _session(token).status_code == 200
        assert timeouts[-1] == m._IDP_REFRESH_TIMEOUT_SECONDS == 20.0

    def test_unexpected_error_from_the_corporate_check_is_not_swallowed(
        self, redis_store, clock, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        with patch("main._validate_corporate_id", side_effect=TypeError("bug")), pytest.raises(TypeError):
            _session(token)

    def test_jwt_error_in_the_corporate_check_keeps_the_session(
        self, redis_store, clock, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        with patch("main._validate_corporate_id", side_effect=pyjwt.InvalidTokenError("clock skew")):
            assert _session(token).status_code == 200
        assert session_key(token) in redis_store.values


class TestCredentialsNeverLogged:
    def test_no_secret_reaches_the_logs(self, redis_store, clock, monkeypatch, fake_token_endpoint, caplog):
        with caplog.at_level(logging.DEBUG):
            burned_code = _login_code()
            assert _exchange(burned_code, secret="wrong-secret-NEVER-LOG").status_code == 400

            code = _login_code()
            exchange = _exchange(code)
            token = exchange.json()["session_token"]

            async def rotate(self_inner, url, **kwargs):
                return httpx.Response(200, json={
                    "access_token": "new.access", "id_token": "new.id", "refresh_token": _ROTATED_REFRESH_TOKEN,
                })

            monkeypatch.setattr(httpx.AsyncClient, "post", rotate)
            clock.now += REVALIDATION_INTERVAL_SECONDS
            assert _session(token).status_code == 200

            monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(400, {"error": "invalid_grant"}))
            clock.now += REVALIDATION_INTERVAL_SECONDS
            assert _session(token).status_code == 401
            assert _exchange(code).status_code == 400

        logged = "\n".join(
            record.getMessage() + (record.exc_text or "")
            for record in caplog.records
            if not _is_test_client_request_line(record)
        )
        assert "nip-fa: session opened for mpass_id=" + _MPASS_ID in logged
        for secret in (
            burned_code,
            code,
            token,
            _HANDOFF_SECRET,
            "wrong-secret-NEVER-LOG",
            _REFRESH_TOKEN,
            _ROTATED_REFRESH_TOKEN,
            "jane.doe@corp.example",
        ):
            assert secret not in logged


    def test_corporate_id_revalidation_failure_does_not_log_the_username(
        self, redis_store, clock, monkeypatch, fake_token_endpoint, caplog
    ):
        token = _signed_in(redis_store, clock)
        alias_email = "alice.alias@corp.example"
        refused_access_token = _make_jwt_with_kid(
            _cognito_access_claims(username=alias_email, **{"custom:corporate_id": "other-corp"}), kid="k1"
        )
        monkeypatch.setattr(
            httpx.AsyncClient, "post",
            _idp_refresh_response(body={"access_token": refused_access_token, "id_token": "new.id"}),
        )
        clock.now += REVALIDATION_INTERVAL_SECONDS
        refused_claims = _cognito_access_claims(username=alias_email, **{"custom:corporate_id": "other-corp"})

        with caplog.at_level(logging.DEBUG), \
             patch.object(m, "SMB_CORPORATE_ID", "corp-uuid-1234"), \
             patch("main._get_jwks", new_callable=AsyncMock, return_value={"keys": [{"kid": "k1"}]}), \
             patch("main.PyJWK.from_dict", return_value=_FakePyJWK()), \
             patch("main.jwt.decode", return_value=refused_claims):
            assert _session(token).json() == {"error": "session_expired"}

        adapter_lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("nip-fa:")]
        assert any("reason=wrong_organization" in line for line in adapter_lines)
        assert not any(alias_email in line for line in adapter_lines)


class TestExistingFlowUnaffected:
    def test_authorize_flow_still_issues_bridge_code(self, redis_store):
        authorize = client.get(
            "/authorize",
            params={
                "state": "oauth2-state",
                "redirect_uri": "https://test-auth.example.com/oauth2/callback",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302
        assert json.loads(redis_store.values["bridge_state:oauth2-state"]) == {
            "redirect_uri": "https://test-auth.example.com/oauth2/callback",
            "state": "oauth2-state",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        }

        response = _callback("oauth2-state")
        assert response.status_code == 302
        location = urlsplit(response.headers["location"])
        assert location.netloc == "test-auth.example.com"
        assert parse_qs(location.query)["state"] == ["oauth2-state"]
        assert len(redis_store.keys_with_prefix("bridge_code:")) == 1
        assert redis_store.keys_with_prefix("nip_fa_code:") == []
