import asyncio
import base64
import json
import logging
from dataclasses import replace

import httpx
import jwt as pyjwt
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

import main as m
from nip_fa.adapter import ASSERTION_RATE_LIMIT, ASSERTION_RATE_WINDOW_SECONDS
from nip_fa.assertions import AssertionRateLimiter, is_publishable_profile, parse_assertion_body
from nip_fa.identities import IdentityStoreUnavailable, StoredIdentity
from nip_fa.sessions import REVALIDATION_INTERVAL_SECONDS, Identity, session_key
from nip_fa.urls import relay_audience
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)
from tests.test_nip_fa_identity_key import _expected_keypair, identity_store  # noqa: F401
from tests.test_nip_fa_login import (  # noqa: F401  (fixtures apply by import)
    _MPASS_ID,
    _T0,
    _RecordingRedis,
    _idp_refresh_response,
    _is_test_client_request_line,
    _signed_in,
    client,
    clock,
)
from tests.test_nip_fa_nip98 import OTHER_SECRET, encode_proof, http_auth_tags, pubkey_of, signed_event

_ROUTE = "/nip-fa/v1/identity/assertions"


class _FakePipeline:
    def __init__(self, redis):
        self._redis = redis
        self._ops = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def incr(self, key):
        self._ops.append((self._redis.incr_now, key))

    def expire(self, key, seconds, nx=False):
        self._ops.append((self._redis.expire_now, key, seconds, nx))

    def ttl(self, key):
        self._ops.append((self._redis.ttl_now, key))

    async def execute(self):
        if self._redis.counter_failure is not None:
            raise self._redis.counter_failure
        return [op(*args) for op, *args in self._ops]


class _CountingRedis(_RecordingRedis):
    def __init__(self):
        super().__init__()
        self.counter_failure: Exception | None = None
        self.transactions: list[bool] = []

    def pipeline(self, transaction=True):
        self.transactions.append(transaction)
        return _FakePipeline(self)

    def incr_now(self, key):
        self.values[key] = str(int(self.values.get(key, "0")) + 1)
        return int(self.values[key])

    def expire_now(self, key, seconds, nx):
        if nx and key in self.ttls:
            return False
        self.ttls[key] = seconds
        return True

    def ttl_now(self, key):
        return self.ttls.get(key, -1)


@pytest.fixture()
def redis_store(monkeypatch):
    store = _CountingRedis()
    monkeypatch.setattr(m, "redis_client", store)
    return store


def _config():
    return m._BUZZ_ADAPTER_CONFIG


def _relay() -> str:
    return sorted(_config().relay_urls)[0]


def _user_secret() -> bytes:
    return bytes.fromhex(_expected_keypair().secret_key_hex)


def _body(relay_url=None, nostr_pubkey=None, **extra) -> bytes:
    body = {
        "relay_url": relay_url or _relay(),
        "nostr_pubkey": nostr_pubkey or _expected_keypair().pubkey_hex,
        **extra,
    }
    return json.dumps(body).encode("utf-8")


def _tags(body: bytes, url=None, method="POST"):
    return http_auth_tags(body, url or _config().assertions_url, method)


def _proof(body: bytes, *, secret=None, tags=None, created_at=None, **event_overrides) -> str:
    event = signed_event(
        secret or _user_secret(),
        tags=tags if tags is not None else _tags(body),
        created_at=created_at if created_at is not None else _T0,
        **event_overrides,
    )
    return encode_proof(event)


def _request_assertion(token, body=None, proof=None, extra_headers=()):
    body = body if body is not None else _body()
    headers = [("Content-Type", "application/json")]
    if token is not None:
        headers.append(("Authorization", f"Bearer {token}"))
    if proof is not False:
        headers.append(("Nostr-Authorization", proof if proof is not None else _proof(body)))
    return client.post(_ROUTE, content=body, headers=[*headers, *extra_headers])


def _jwks_key(kid: str):
    jwks = client.get("/.well-known/jwks.json").json()
    published = next(key for key in jwks["keys"] if key["kid"] == kid)
    return pyjwt.PyJWK.from_dict(published).key


def _decode(assertion: str) -> tuple[dict, dict]:
    header = pyjwt.get_unverified_header(assertion)
    claims = pyjwt.decode(
        assertion,
        _jwks_key(header["kid"]),
        algorithms=["RS256"],
        audience=relay_audience(_relay()),
        issuer=_config().nip_fi_issuer,
        options={"verify_exp": False, "verify_iat": False},
    )
    return header, claims


def _open_session(identity: Identity, ttl_seconds: int) -> str:
    token, _ = asyncio.run(m._buzz_adapter.sessions.open(identity, "refresh-token", ttl_seconds))
    return token


def _denial(response) -> tuple[int, dict]:
    assert response.headers["cache-control"] == "no-store"
    return response.status_code, response.json()


class TestAssertionBody:
    _PUBKEY = "a" * 64

    def test_accepts_exactly_the_two_fields(self):
        parsed = parse_assertion_body(_body("wss://r.example.com", self._PUBKEY))
        assert (parsed.relay_url, parsed.nostr_pubkey) == ("wss://r.example.com", self._PUBKEY)

    @pytest.mark.parametrize("raw", [
        b"",
        b"[]",
        b"not json",
        b'{"relay_url": "wss://r.example.com"}',
        b'{"nostr_pubkey": "' + b"a" * 64 + b'"}',
        b'{"relay_url": "wss://r.example.com", "nostr_pubkey": "' + b"a" * 64 + b'", "x": 1}',
        b'{"relay_url": 1, "nostr_pubkey": "' + b"a" * 64 + b'"}',
        b'{"relay_url": "wss://r.example.com", "nostr_pubkey": "' + b"A" * 64 + b'"}',
        b'{"relay_url": "wss://r.example.com", "nostr_pubkey": "' + b"a" * 63 + b'"}',
        b'{"relay_url": "wss://r.example.com", "nostr_pubkey": "npub1xyz"}',
        b'{"relay_url": "wss://a.example.com", "relay_url": "wss://r.example.com", "nostr_pubkey": "'
        + b"a" * 64 + b'"}',
        b"[" * 2048 + b"]" * 2048,
    ])
    def test_rejects_everything_else(self, raw):
        assert parse_assertion_body(raw) is None


class TestPublishableProfile:
    @pytest.mark.parametrize("profile, publishable", [
        ({"username": "jane.doe", "display_name": "jane.doe"}, True),
        ({"username": "j_d-1", "display_name": "j_d-1"}, True),
        ({"username": "Jane.Doe", "display_name": "Jane.Doe"}, False),
        ({"username": "jane+tag", "display_name": "jane+tag"}, False),
        ({"username": "a" * 65, "display_name": "a" * 65}, False),
        (None, False),
    ])
    def test_follows_the_relay_rules(self, profile, publishable):
        assert is_publishable_profile(profile) is publishable


class TestAssertionIssuance:
    def test_issues_a_nip_fi_assertion(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)

        response = _request_assertion(token)

        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert set(body) == {"assertion", "nostr_pubkey", "expires_at"}
        header, claims = _decode(body["assertion"])
        assert header == {"alg": "RS256", "typ": "nip-fi+jwt", "kid": m._SIGNING_KID}
        pubkey = _expected_keypair().pubkey_hex
        assert claims == {
            "iss": _config().nip_fi_issuer,
            "sub": _MPASS_ID,
            "aud": relay_audience(_relay()),
            "iat": _T0,
            "exp": _T0 + _config().assertion_ttl_seconds,
            "nostr_pubkey": pubkey,
            "nostr_public_profile": {"display_name": "jane.doe", "username": "jane.doe"},
        }
        assert body["nostr_pubkey"] == pubkey
        assert body["expires_at"] == claims["exp"]
        assert identity_store.calls == [(_MPASS_ID, pubkey, "jane.doe@corp.example")]

    def test_typ_survives_in_the_protected_header_bytes(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        assertion = _request_assertion(token).json()["assertion"]
        protected = assertion.split(".")[0]
        decoded = json.loads(base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)))
        assert decoded["typ"] == "nip-fi+jwt"

    def test_audience_follows_the_requested_relay(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        for relay in sorted(_config().relay_urls):
            body = _body(relay_url=relay)
            assertion = _request_assertion(token, body=body).json()["assertion"]
            assert pyjwt.decode(assertion, options={"verify_signature": False})["aud"] == relay_audience(relay)

    def test_exp_is_capped_by_the_session_expiry(self, redis_store, clock, identity_store):
        identity = Identity(sub=_MPASS_ID, cognito_sub="c", email="jane.doe@corp.example")
        token = _open_session(identity, ttl_seconds=120)

        body = _request_assertion(token).json()

        assert body["expires_at"] == _T0 + 120
        assert pyjwt.decode(body["assertion"], options={"verify_signature": False})["exp"] == _T0 + 120

    def test_ttl_comes_from_config(self, redis_store, clock, identity_store, monkeypatch):
        monkeypatch.setattr(m._buzz_adapter, "_config", replace(_config(), assertion_ttl_seconds=45))
        token = _signed_in(redis_store, clock)
        assert _request_assertion(token).json()["expires_at"] == _T0 + 45

    def test_profile_claim_is_omitted_without_an_email(self, redis_store, clock, identity_store):
        token = _open_session(Identity(sub=_MPASS_ID, cognito_sub="c", email=None), ttl_seconds=3600)

        response = _request_assertion(token)

        assert response.status_code == 200, response.text
        claims = pyjwt.decode(response.json()["assertion"], options={"verify_signature": False})
        assert "nostr_public_profile" not in claims
        assert set(claims) == {"iss", "sub", "aud", "iat", "exp", "nostr_pubkey"}

    def test_profile_claim_is_omitted_when_the_relay_would_drop_it(self, redis_store, clock, identity_store):
        identity = Identity(sub=_MPASS_ID, cognito_sub="c", email="Jane.Doe+buzz@corp.example")
        token = _open_session(identity, ttl_seconds=3600)

        claims = pyjwt.decode(_request_assertion(token).json()["assertion"], options={"verify_signature": False})

        assert "nostr_public_profile" not in claims

    def test_no_email_or_cognito_sub_in_the_assertion(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        assertion = _request_assertion(token).json()["assertion"]
        payload = assertion.split(".")[1]
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
        assert "corp.example" not in decoded
        assert "cognito-sub-uuid-5678" not in decoded


class TestSessionDenials:
    def test_missing_session_is_session_required_even_with_a_bad_body(self, redis_store, clock, identity_store):
        response = _request_assertion(None, body=b"not json", proof=False)
        assert _denial(response) == (401, {"error": "session_required"})

    def test_unknown_session_is_session_required(self, redis_store, clock, identity_store):
        assert _denial(_request_assertion("not-a-session")) == (401, {"error": "session_required"})
        assert identity_store.calls == []

    def test_repeated_authorization_is_invalid_request(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        response = _request_assertion(None, extra_headers=[("Authorization", f"Bearer {token}")] * 2)
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_non_bearer_session_is_invalid_request(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        response = _request_assertion(None, extra_headers=[("Authorization", f"Nostr {token}")])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_expired_session_is_session_expired(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        clock.now += _config().session_ttl_seconds
        assert _denial(_request_assertion(token)) == (401, {"error": "session_expired"})
        assert identity_store.calls == []

    def test_session_ended_on_revalidation(self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(400, {"error": "invalid_grant"}))
        clock.now += REVALIDATION_INTERVAL_SECONDS
        body = _body()
        response = _request_assertion(token, body=body, proof=_proof(body, created_at=clock.now))
        assert _denial(response) == (401, {"error": "session_expired"})

    def test_revalidation_outage_is_issuance_unavailable(
        self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(500, {}))
        clock.now += REVALIDATION_INTERVAL_SECONDS
        body = _body()
        response = _request_assertion(token, body=body, proof=_proof(body, created_at=clock.now))
        assert _denial(response) == (503, {"error": "issuance_unavailable"})
        assert identity_store.calls == []

    def test_revalidated_session_gets_an_assertion(
        self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS
        body = _body()
        response = _request_assertion(token, body=body, proof=_proof(body, created_at=clock.now))
        assert response.status_code == 200, response.text
        assert response.json()["expires_at"] == clock.now + _config().assertion_ttl_seconds


class TestRequestShapeDenials:
    @pytest.mark.parametrize("proofs", [[], ["Nostr a", "Nostr b"]])
    def test_missing_or_repeated_proof_header_is_invalid_request(self, redis_store, clock, identity_store, proofs):
        token = _signed_in(redis_store, clock)
        response = _request_assertion(token, proof=False, extra_headers=[("Nostr-Authorization", p) for p in proofs])
        assert _denial(response) == (400, {"error": "invalid_request"})
        assert identity_store.calls == []

    @pytest.mark.parametrize("encoding", ["gzip", "identity", ""])
    def test_any_content_encoding_is_invalid_request(self, redis_store, clock, identity_store, encoding):
        token = _signed_in(redis_store, clock)
        response = _request_assertion(token, extra_headers=[("Content-Encoding", encoding)])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_oversize_body_is_request_too_large(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        body = _body(padding="x" * 4096)
        assert _denial(_request_assertion(token, body=body)) == (413, {"error": "request_too_large"})

    def test_body_at_the_limit_is_read(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        base = _body()
        body = base[:-1] + b" " * (4096 - len(base)) + b"}"
        assert len(body) == 4096
        assert _request_assertion(token, body=body).status_code == 200

    @pytest.mark.parametrize("body", [
        b"not json",
        b'{"relay_url": "wss://relay.example.com"}',
        _body(extra="field"),
        b'{"relay_url": "wss://relay.example.com", "nostr_pubkey": "' + b"A" * 64 + b'"}',
    ])
    def test_malformed_body_is_invalid_request(self, redis_store, clock, identity_store, body):
        token = _signed_in(redis_store, clock)
        assert _denial(_request_assertion(token, body=body)) == (400, {"error": "invalid_request"})
        assert identity_store.calls == []


class TestProofDenials:
    @pytest.mark.parametrize("name, make_proof", [
        ("wrong u", lambda body: _proof(body, tags=_tags(body, url="https://other.example.com" + _ROUTE))),
        ("internal u", lambda body: _proof(body, tags=_tags(body, url="http://testserver" + _ROUTE))),
        ("wrong method", lambda body: _proof(body, tags=_tags(body, method="GET"))),
        ("wrong payload", lambda body: _proof(body, tags=_tags(b"other body"))),
        ("stale", lambda body: _proof(body, created_at=_T0 - 61)),
        ("future", lambda body: _proof(body, created_at=_T0 + 6)),
        ("not base64", lambda body: "Nostr !!!"),
        ("wrong scheme", lambda body: "Bearer " + _proof(body)[len("Nostr "):]),
    ])
    def test_failed_proof_is_invalid_proof(self, redis_store, clock, identity_store, name, make_proof):
        token = _signed_in(redis_store, clock)
        body = _body()
        response = _request_assertion(token, body=body, proof=make_proof(body))
        assert _denial(response) == (403, {"error": "invalid_proof"}), name
        assert identity_store.calls == []

    def test_tampered_signature_bytes_is_invalid_proof(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        body = _body()
        event = signed_event(_user_secret(), tags=_tags(body), created_at=_T0)
        event["sig"] = ("0" if event["sig"][0] != "0" else "1") + event["sig"][1:]
        assert _denial(_request_assertion(token, body=body, proof=encode_proof(event))) == (
            403, {"error": "invalid_proof"},
        )

    def test_signer_must_be_the_body_key(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        body = _body()
        response = _request_assertion(token, body=body, proof=_proof(body, secret=OTHER_SECRET))
        assert _denial(response) == (403, {"error": "invalid_proof"})
        assert identity_store.calls == []

    def test_proof_window_edges_are_accepted(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        for created_at in (_T0 - 60, _T0 + 5):
            body = _body()
            assert _request_assertion(token, body=body, proof=_proof(body, created_at=created_at)).status_code == 200


class TestAuthorizationDenials:
    def test_unknown_relay_is_authorization_denied(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        for relay in ("wss://unknown.example.com", _relay() + "/", _relay().upper()):
            body = _body(relay_url=relay)
            assert _denial(_request_assertion(token, body=body)) == (403, {"error": "authorization_denied"})
        assert identity_store.calls == []

    def test_proof_is_checked_before_the_relay(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        body = _body(relay_url="wss://unknown.example.com")
        response = _request_assertion(token, body=body, proof=_proof(body, created_at=_T0 - 61))
        assert _denial(response) == (403, {"error": "invalid_proof"})

    def test_revoked_identity_is_authorization_denied(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows[_MPASS_ID] = StoredIdentity(_expected_keypair().pubkey_hex, revoked=True)
        assert _denial(_request_assertion(token)) == (403, {"error": "authorization_denied"})

    def test_stored_binding_mismatch_is_binding_mismatch(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows[_MPASS_ID] = StoredIdentity("ab" * 32, revoked=False)
        assert _denial(_request_assertion(token)) == (403, {"error": "binding_mismatch"})

    def test_key_bound_to_someone_else_is_binding_mismatch(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows["another-mpass-id"] = StoredIdentity(_expected_keypair().pubkey_hex, revoked=False)
        assert _denial(_request_assertion(token)) == (403, {"error": "binding_mismatch"})

    def test_a_key_other_than_the_custodial_one_is_binding_mismatch(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        body = _body(nostr_pubkey=pubkey_of(OTHER_SECRET))
        response = _request_assertion(token, body=body, proof=_proof(body, secret=OTHER_SECRET))
        assert _denial(response) == (403, {"error": "binding_mismatch"})

    def test_store_outage_is_issuance_unavailable(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.failure = IdentityStoreUnavailable()
        assert _denial(_request_assertion(token)) == (503, {"error": "issuance_unavailable"})


class TestRateLimit:
    def test_limits_each_session_and_sets_retry_after(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        other = _signed_in(redis_store, clock)

        statuses = [_request_assertion(token).status_code for _ in range(ASSERTION_RATE_LIMIT)]
        limited = _request_assertion(token)

        assert statuses == [200] * ASSERTION_RATE_LIMIT
        assert _denial(limited) == (429, {"error": "rate_limited"})
        assert limited.headers["retry-after"] == str(ASSERTION_RATE_WINDOW_SECONDS)
        assert _request_assertion(other).status_code == 200

    def test_counter_is_keyed_by_the_session_record_key(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        _request_assertion(token)

        counters = redis_store.keys_with_prefix(AssertionRateLimiter.KEY_PREFIX)
        assert counters == [AssertionRateLimiter.KEY_PREFIX + session_key(token)]
        assert token not in counters[0]
        assert redis_store.ttls[counters[0]] == ASSERTION_RATE_WINDOW_SECONDS
        assert redis_store.transactions == [True]

    def test_window_is_not_extended_by_later_requests(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        _request_assertion(token)
        key = AssertionRateLimiter.KEY_PREFIX + session_key(token)
        redis_store.ttls[key] = 7
        _request_assertion(token)
        assert redis_store.ttls[key] == 7

    def test_counts_requests_before_the_proof_is_checked(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        for _ in range(ASSERTION_RATE_LIMIT):
            _request_assertion(token, proof="Nostr !!!")
        assert _denial(_request_assertion(token)) == (429, {"error": "rate_limited"})

    def test_redis_failure_is_issuance_unavailable(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        redis_store.counter_failure = RedisConnectionError("valkey down")
        assert _denial(_request_assertion(token)) == (503, {"error": "issuance_unavailable"})
        assert identity_store.calls == []


class TestAssertionLogging:
    def test_one_issuance_line_and_no_credentials_in_the_logs(self, redis_store, clock, identity_store, caplog):
        with caplog.at_level(logging.DEBUG):
            token = _signed_in(redis_store, clock)
            body = _body()
            proof = _proof(body)
            response = _request_assertion(token, body=body, proof=proof)
            bad_body = _body(relay_url="wss://unknown.example.com")
            bad_proof = _proof(bad_body, created_at=_T0 - 61)
            assert _request_assertion(token, body=bad_body, proof=bad_proof).status_code == 403

        assertion = response.json()["assertion"]
        lines = [
            record.getMessage() + (record.exc_text or "")
            for record in caplog.records
            if not _is_test_client_request_line(record)
        ]
        issued = [line for line in lines if "assertion issued" in line]
        exp = response.json()["expires_at"]
        relay_host = _relay()[len("wss://"):]
        assert issued == [
            f"nip-fa: assertion issued mpass_id={_MPASS_ID} pubkey={_expected_keypair().pubkey_hex} "
            f"relay={relay_host} exp={exp}"
        ]
        logged = "\n".join(lines)
        for secret in (assertion, assertion.split(".")[2], token, proof, proof[len("Nostr "):], bad_proof,
                       body.decode(), bad_body.decode(), _expected_keypair().secret_key_hex):
            assert secret not in logged
        assert "reason=invalid_proof detail=stale" in logged


class TestRouteMounting:
    def test_only_post_is_routed(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        assert client.get(_ROUTE, headers={"Authorization": f"Bearer {token}"}).status_code == 405
