import json
import logging
from urllib.parse import urlencode

import jwt as pyjwt
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

import main as m
from nip_fa.agent_grants import AGENT_GRANT_TOKEN_TYPE, SESSION_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE, grant_hash
from nip_fa.agent_routes import AGENT_GRANT_RATE_LIMIT, AGENT_REVOKE_RATE_LIMIT
from nip_fa.agents import AgentStoreUnavailable, Enrollment, Revocation, StoredGrant
from nip_fa.identities import IdentityStoreUnavailable, StoredIdentity
from nip_fa.relay_commands import DisconnectReport
from nip_fa.sessions import REVALIDATION_INTERVAL_SECONDS, session_key
from nip_fa.urls import relay_audience
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)
from tests.test_nip_fa_agent_units import _pubkey, attestation
from tests.test_nip_fa_assertions import _CountingRedis, _jwks_key
from tests.test_nip_fa_identity_key import _expected_keypair, identity_store  # noqa: F401
from tests.test_nip_fa_login import (  # noqa: F401  (fixtures apply by import)
    _MPASS_ID,
    _T0,
    _idp_refresh_response,
    _signed_in,
    client,
    clock,
)
from tests.test_nip_fa_nip98 import OTHER_SECRET, encode_proof, http_auth_tags, signed_event

_GRANT_ROUTE = "/nip-fa/v1/nip-fi/agent-grant"
_ASSERTION_ROUTE = "/nip-fa/v1/nip-fi/agent-assertion"
_REVOKE_ROUTE = "/nip-fa/v1/nip-fi/agent-revoke"
_AGENT_SECRET = bytes.fromhex("22" * 32)
_AGENT = _pubkey(_AGENT_SECRET)
_FORM = "application/x-www-form-urlencoded"


class _AgentRedis(_CountingRedis):
    def __init__(self):
        super().__init__()
        self.set_failure: Exception | None = None

    async def set(self, key, value, *, xx=False, keepttl=False, nx=False, ex=None):
        if self.set_failure is not None and key.startswith("nip_fa_proof:"):
            raise self.set_failure
        if (nx and key in self.values) or (xx and key not in self.values):
            return None
        self.values[key] = value
        if ex is not None:
            self.ttls[key] = ex
        elif not keepttl:
            self.ttls.pop(key, None)
        return True


class _FakeAgentStore:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.revoked_owners: set[str] = set()
        self.enrollments: list = []
        self.revocations: list = []
        self.failure: Exception | None = None
        self.forced: Enrollment | None = None

    def _check(self):
        if self.failure is not None:
            raise self.failure

    async def enroll(self, request):
        self.enrollments.append(request)
        self._check()
        if self.forced is not None:
            return self.forced
        existing = self.rows.get(request.agent_pubkey)
        if existing and (existing["owner_sub"] != request.owner_sub or existing["revoked"]):
            return Enrollment.AGENT_REFUSED
        others = [
            agent for agent, row in self.rows.items()
            if row["owner_sub"] == request.owner_sub and not row["revoked"] and agent != request.agent_pubkey
        ]
        if len(others) >= request.max_agents:
            return Enrollment.CAP_REACHED
        self.rows[request.agent_pubkey] = {
            "owner_sub": request.owner_sub,
            "owner_pubkey": request.owner_pubkey,
            "grant_hash": request.grant_hash,
            "expires_at": request.expires_at,
            "revoked": False,
        }
        return Enrollment.ENROLLED

    async def grant(self, hashed):
        self._check()
        for agent, row in self.rows.items():
            if row["grant_hash"] == hashed:
                return StoredGrant(
                    agent_pubkey=agent,
                    owner_sub=row["owner_sub"],
                    owner_pubkey=row["owner_pubkey"],
                    expires_at=row["expires_at"],
                    revoked=row["revoked"],
                    owner_revoked=row["owner_sub"] in self.revoked_owners,
                )
        return None

    async def revoke(self, owner_sub, agent_pubkey):
        self.revocations.append((owner_sub, agent_pubkey))
        self._check()
        row = self.rows.get(agent_pubkey)
        if row is None or row["owner_sub"] != owner_sub:
            return Revocation.NOT_FOUND
        if row["revoked"]:
            return Revocation.ALREADY_REVOKED
        row.update(revoked=True, grant_hash=None, expires_at=None)
        return Revocation.REVOKED


class _FakeDisconnector:
    def __init__(self):
        self.calls: list[str] = []
        self.failed: tuple[str, ...] = ()

    async def disconnect(self, target_pubkey):
        self.calls.append(target_pubkey)
        return DisconnectReport(failed_relays=self.failed)


@pytest.fixture()
def redis_store(monkeypatch):
    store = _AgentRedis()
    monkeypatch.setattr(m, "redis_client", store)
    return store


@pytest.fixture()
def agent_store(monkeypatch, identity_store):
    store = _FakeAgentStore()
    agents = m._buzz_adapter.agents
    monkeypatch.setattr(agents, "store", store)
    monkeypatch.setattr(agents, "identity_keys", m._buzz_adapter.identity_keys)
    return store


@pytest.fixture()
def disconnector(monkeypatch):
    fake = _FakeDisconnector()
    monkeypatch.setattr(m._buzz_adapter.agents, "disconnector", fake)
    return fake


@pytest.fixture()
def agents_off(monkeypatch):
    monkeypatch.setattr(m._buzz_adapter.agents, "_agents", None)


def _agents():
    return m._BUZZ_ADAPTER_CONFIG.agents


def _relay() -> str:
    return sorted(m._BUZZ_ADAPTER_CONFIG.relay_urls)[0]


def _owner_secret() -> bytes:
    return bytes.fromhex(_expected_keypair().secret_key_hex)


def _owner_pubkey() -> str:
    return _expected_keypair().pubkey_hex


def _grant_body(session_token, agent=_AGENT, owner_attestation=None, **overrides) -> bytes:
    fields = {
        "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": session_token,
        "subject_token_type": SESSION_TOKEN_TYPE,
        "requested_token_type": AGENT_GRANT_TOKEN_TYPE,
        "agent_pubkey": agent,
        "owner_attestation": owner_attestation or attestation(agent, _owner_secret()),
    }
    fields.update(overrides)
    return urlencode(fields).encode("ascii")


def _proof(body: bytes, url: str, *, secret=_AGENT_SECRET, created_at=None, content="") -> str:
    event = signed_event(
        secret, tags=http_auth_tags(body, url), created_at=created_at if created_at is not None else _T0,
        content=content,
    )
    return encode_proof(event)


def _post(route, body, headers):
    return client.post(route, content=body, headers=headers)


def _request_grant(body: bytes, *, proof=None, secret=_AGENT_SECRET, content_type=_FORM, extra_headers=()):
    headers = [("Content-Type", content_type)]
    if proof is not False:
        headers.append(("Nostr-Authorization", proof or _proof(body, _agents().grant_url, secret=secret)))
    return _post(_GRANT_ROUTE, body, [*headers, *extra_headers])


def _enrolled(redis_store, clock) -> tuple[str, str]:
    session_token = _signed_in(redis_store, clock)
    response = _request_grant(_grant_body(session_token))
    assert response.status_code == 200, response.text
    return session_token, response.json()["access_token"]


def _assertion_body(relay_url=None, nostr_pubkey=_AGENT) -> bytes:
    return json.dumps({"relay_url": relay_url or _relay(), "nostr_pubkey": nostr_pubkey}).encode("utf-8")


def _request_assertion(grant, body=None, *, proof=None, secret=_AGENT_SECRET, extra_headers=()):
    body = body if body is not None else _assertion_body()
    headers = [("Content-Type", "application/json")]
    if grant is not None:
        headers.append(("Authorization", f"Bearer {grant}"))
    if proof is not False:
        headers.append(("Nostr-Authorization", proof or _proof(body, _agents().assertion_url, secret=secret)))
    return _post(_ASSERTION_ROUTE, body, [*headers, *extra_headers])


def _request_revoke(session_token, body=None, extra_headers=()):
    body = body if body is not None else urlencode({"agent_pubkey": _AGENT}).encode("ascii")
    headers = [("Content-Type", _FORM)]
    if session_token is not None:
        headers.append(("Authorization", f"Bearer {session_token}"))
    return _post(_REVOKE_ROUTE, body, [*headers, *extra_headers])


def _denial(response) -> tuple[int, dict]:
    assert response.headers["cache-control"] == "no-store"
    return response.status_code, response.json()


def _decode_agent_assertion(assertion: str) -> tuple[dict, dict]:
    header = pyjwt.get_unverified_header(assertion)
    claims = pyjwt.decode(
        assertion,
        _jwks_key(header["kid"]),
        algorithms=["RS256"],
        audience=relay_audience(_relay()),
        issuer=m._BUZZ_ADAPTER_CONFIG.nip_fi_issuer,
        options={"verify_exp": False, "verify_iat": False},
    )
    return header, claims


class TestRoutes:
    def test_agent_routes_live_under_the_nip_fa_prefix(self):
        paths = {route.path for route in m.app.routes}
        assert {_GRANT_ROUTE, _ASSERTION_ROUTE, _REVOKE_ROUTE} <= paths

    @pytest.mark.parametrize("route", [_GRANT_ROUTE, _ASSERTION_ROUTE, _REVOKE_ROUTE])
    def test_agents_off_answers_agent_unsupported(self, agents_off, route):
        assert _denial(client.post(route, content=b"")) == (403, {"error": "agent_unsupported"})


class TestAgentGrant:
    def test_issues_a_grant(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)

        response = _request_grant(_grant_body(session_token))

        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        token = body.pop("access_token")
        assert body == {
            "issued_token_type": "urn:nostr:params:oauth:token-type:nip-fi-agent-grant",
            "token_type": "N_A",
            "expires_in": _agents().grant_ttl_seconds,
            "nostr_owner_pubkey": _owner_pubkey(),
            "nip_fi_issuer": m._BUZZ_ADAPTER_CONFIG.nip_fi_issuer,
        }
        [enrollment] = agent_store.enrollments
        assert enrollment.owner_sub == _MPASS_ID
        assert enrollment.owner_pubkey == _owner_pubkey()
        assert enrollment.agent_pubkey == _AGENT
        assert enrollment.grant_hash == grant_hash(token)
        assert enrollment.expires_at == _T0 + _agents().grant_ttl_seconds
        assert enrollment.max_agents == _agents().max_agents_per_user

    def test_re_enrolling_replaces_the_grant(self, redis_store, clock, agent_store):
        session_token, first = _enrolled(redis_store, clock)
        body = _grant_body(session_token)
        second = _request_grant(body, proof=_proof(body, _agents().grant_url, content="retry"))
        assert second.status_code == 200, second.text
        assert _denial(_request_assertion(first)) == (401, {"error": "invalid_grant"})
        assert _request_assertion(second.json()["access_token"]).status_code == 200

    @pytest.mark.parametrize("extra_headers", [
        [("Authorization", "Bearer x")],
        [("Cookie", "_foss_oauth2_proxy=x")],
        [("Content-Encoding", "gzip")],
    ])
    def test_header_rules(self, redis_store, clock, agent_store, extra_headers):
        body = _grant_body(_signed_in(redis_store, clock))
        assert _denial(_request_grant(body, extra_headers=extra_headers)) == (400, {"error": "invalid_request"})
        assert agent_store.enrollments == []

    def test_session_as_bearer_with_subject_token_is_refused(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        bearer = [("Authorization", f"Bearer {session_token}")]
        response = _request_grant(_grant_body(session_token), extra_headers=bearer)
        assert _denial(response) == (400, {"error": "invalid_request"})

    @pytest.mark.parametrize("content_type", ["application/json", "text/plain", ""])
    def test_requires_a_form_body(self, redis_store, clock, agent_store, content_type):
        body = _grant_body(_signed_in(redis_store, clock))
        assert _request_grant(body, content_type=content_type).status_code == 400

    def test_form_content_type_parameters_are_accepted(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock))
        assert _request_grant(body, content_type=f"{_FORM}; charset=UTF-8").status_code == 200

    def test_exactly_one_proof_header(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock))
        proof = _proof(body, _agents().grant_url)
        assert _request_grant(body, proof=False).status_code == 400
        assert _request_grant(body, extra_headers=[("Nostr-Authorization", proof)]).status_code == 400

    def test_body_limit(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock), owner_attestation="x" * 8192)
        assert _denial(_request_grant(body)) == (413, {"error": "request_too_large"})

    @pytest.mark.parametrize("overrides", [
        {"runtime": "local"},
        {"subject_token_type": "urn:builderlab:params:oauth:token-type:bb-session"},
        {"requested_token_type": "urn:builderlab:params:oauth:token-type:nip-fi-agent-grant"},
        {"agent_pubkey": "AB" * 32},
    ])
    def test_malformed_forms(self, redis_store, clock, agent_store, overrides):
        body = _grant_body(_signed_in(redis_store, clock), **overrides)
        assert _denial(_request_grant(body)) == (400, {"error": "invalid_request"})

    def test_unknown_session(self, redis_store, clock, agent_store):
        assert _denial(_request_grant(_grant_body("no-such-session"))) == (400, {"error": "invalid_request"})

    def test_ended_session(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        clock.now += m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds
        body = _grant_body(session_token)
        response = _request_grant(body, proof=_proof(body, _agents().grant_url, created_at=clock.now))
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_idp_outage_is_unavailable(self, redis_store, clock, agent_store, monkeypatch):
        session_token = _signed_in(redis_store, clock)
        clock.now += REVALIDATION_INTERVAL_SECONDS
        monkeypatch.setattr("httpx.AsyncClient.post", _idp_refresh_response(503, {}))
        body = _grant_body(session_token)
        response = _request_grant(body, proof=_proof(body, _agents().grant_url, created_at=clock.now))
        assert _denial(response) == (503, {"error": "issuance_unavailable"})

    def test_proof_must_be_signed_by_the_agent(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock))
        assert _denial(_request_grant(body, secret=OTHER_SECRET)) == (400, {"error": "invalid_request"})

    def test_proof_must_cover_this_url_and_body(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        body = _grant_body(session_token)
        wrong_url = _proof(body, _agents().assertion_url)
        wrong_body = _proof(_grant_body(session_token, owner_attestation="x"), _agents().grant_url)
        assert _request_grant(body, proof=wrong_url).status_code == 400
        assert _request_grant(body, proof=wrong_body).status_code == 400

    def test_a_proof_is_single_use(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock))
        proof = _proof(body, _agents().grant_url)
        assert _request_grant(body, proof=proof).status_code == 200
        assert _denial(_request_grant(body, proof=proof)) == (400, {"error": "invalid_request"})
        assert len(agent_store.enrollments) == 1

    def test_replay_guard_outage_is_unavailable(self, redis_store, clock, agent_store):
        body = _grant_body(_signed_in(redis_store, clock))
        redis_store.set_failure = RedisConnectionError("down")
        assert _denial(_request_grant(body)) == (503, {"error": "issuance_unavailable"})

    def test_revoked_owner_identity_is_refused(self, redis_store, clock, agent_store, identity_store):
        identity_store.rows[_MPASS_ID] = StoredIdentity(pubkey_hex=_owner_pubkey(), revoked=True)
        body = _grant_body(_signed_in(redis_store, clock))
        assert _denial(_request_grant(body)) == (400, {"error": "invalid_request"})

    def test_identity_store_outage_is_unavailable(self, redis_store, clock, agent_store, identity_store):
        body = _grant_body(_signed_in(redis_store, clock))
        identity_store.failure = IdentityStoreUnavailable()
        assert _denial(_request_grant(body)) == (503, {"error": "issuance_unavailable"})

    @pytest.mark.parametrize("make_attestation", [
        lambda: attestation(_AGENT, OTHER_SECRET),
        lambda: attestation(_AGENT, _owner_secret(), "kind=1"),
        lambda: attestation(_pubkey(OTHER_SECRET), _owner_secret()),
        lambda: "not a tag",
    ])
    def test_owner_attestation_must_be_the_owners_for_this_agent(
        self, redis_store, clock, agent_store, make_attestation
    ):
        body = _grant_body(_signed_in(redis_store, clock), owner_attestation=make_attestation())
        assert _denial(_request_grant(body)) == (400, {"error": "invalid_grant"})
        assert agent_store.enrollments == []

    def test_an_oversized_condition_is_invalid_grant(self, redis_store, clock, agent_store):
        tag = json.dumps(["auth", _owner_pubkey(), "kind=" + "1" * 5000, "ab" * 64], separators=(",", ":"))
        body = _grant_body(_signed_in(redis_store, clock), owner_attestation=tag)
        assert _denial(_request_grant(body)) == (400, {"error": "invalid_grant"})

    def test_owner_key_cannot_be_its_own_agent(self, redis_store, clock, agent_store):
        owner = _owner_pubkey()
        session_token = _signed_in(redis_store, clock)
        body = _grant_body(session_token, agent=owner, owner_attestation=attestation(owner, _owner_secret()))
        assert _denial(_request_grant(body, secret=_owner_secret())) == (400, {"error": "invalid_grant"})

    @pytest.mark.parametrize("outcome, expected", [
        (Enrollment.AGENT_REFUSED, (400, {"error": "invalid_grant"})),
        (Enrollment.OWNER_REFUSED, (400, {"error": "invalid_request"})),
        (Enrollment.CAP_REACHED, (429, {"error": "rate_limited"})),
    ])
    def test_enrollment_refusals(self, redis_store, clock, agent_store, outcome, expected):
        agent_store.forced = outcome
        response = _request_grant(_grant_body(_signed_in(redis_store, clock)))
        assert _denial(response) == expected

    def test_an_agent_of_another_owner_is_refused(self, redis_store, clock, agent_store):
        agent_store.rows[_AGENT] = {
            "owner_sub": "someone-else", "owner_pubkey": "ee" * 32, "grant_hash": "ff" * 32,
            "expires_at": _T0 + 60, "revoked": False,
        }
        response = _request_grant(_grant_body(_signed_in(redis_store, clock)))
        assert _denial(response) == (400, {"error": "invalid_grant"})

    def test_agent_store_outage_is_unavailable(self, redis_store, clock, agent_store):
        agent_store.failure = AgentStoreUnavailable()
        response = _request_grant(_grant_body(_signed_in(redis_store, clock)))
        assert _denial(response) == (503, {"error": "issuance_unavailable"})

    def test_rate_limited_per_session(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        body = _grant_body(session_token)
        for attempt in range(AGENT_GRANT_RATE_LIMIT):
            proof = _proof(body, _agents().grant_url, content=str(attempt))
            assert _request_grant(body, proof=proof).status_code == 200
        response = _request_grant(body, proof=_proof(body, _agents().grant_url, content="over"))
        assert _denial(response) == (429, {"error": "rate_limited"})
        assert response.headers["retry-after"]

    def test_logs_no_credentials(self, redis_store, clock, agent_store, caplog):
        session_token = _signed_in(redis_store, clock)
        body = _grant_body(session_token)
        owner_attestation = attestation(_AGENT, _owner_secret())
        with caplog.at_level(logging.DEBUG):
            token = _request_grant(body).json()["access_token"]
        signature = json.loads(owner_attestation)[3]
        for record in caplog.records:
            message = record.getMessage()
            assert session_token not in message
            assert token not in message
            assert signature not in message


class TestAgentAssertion:
    def test_issues_an_agent_assertion(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)

        response = _request_assertion(grant)

        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        header, claims = _decode_agent_assertion(body["assertion"])
        assert header == {"alg": "RS256", "typ": "nip-fi-agent+jwt", "kid": m._SIGNING_KID}
        assert claims == {
            "iss": m._BUZZ_ADAPTER_CONFIG.nip_fi_issuer,
            "sub": _MPASS_ID,
            "aud": relay_audience(_relay()),
            "iat": _T0,
            "exp": _T0 + m._BUZZ_ADAPTER_CONFIG.assertion_ttl_seconds,
            "nostr_pubkey": _AGENT,
            "nostr_owner_pubkey": _owner_pubkey(),
        }
        assert body == {"assertion": body["assertion"], "nostr_pubkey": _AGENT, "expires_at": claims["exp"]}

    def test_exp_is_capped_by_the_grant_expiry(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        agent_store.rows[_AGENT]["expires_at"] = _T0 + 42
        assertion = _request_assertion(grant).json()["assertion"]
        assert pyjwt.decode(assertion, options={"verify_signature": False})["exp"] == _T0 + 42

    def test_outlives_the_owner_session(self, redis_store, clock, agent_store):
        session_token, grant = _enrolled(redis_store, clock)
        del redis_store.values[session_key(session_token)]
        assert _request_assertion(grant).status_code == 200

    @pytest.mark.parametrize("headers, expected", [
        ([], (401, {"error": "invalid_grant"})),
        ([("Authorization", "Bearer ")], (401, {"error": "invalid_grant"})),
        ([("Authorization", "Basic abc")], (400, {"error": "invalid_request"})),
        ([("Authorization", "Bearer a"), ("Authorization", "Bearer b")], (400, {"error": "invalid_request"})),
    ])
    def test_grant_header_rules(self, redis_store, clock, agent_store, headers, expected):
        body = _assertion_body()
        response = _post(_ASSERTION_ROUTE, body, [
            ("Content-Type", "application/json"),
            ("Nostr-Authorization", _proof(body, _agents().assertion_url)),
            *headers,
        ])
        assert _denial(response) == expected

    def test_an_adapter_session_is_not_a_grant(self, redis_store, clock, agent_store):
        session_token, _ = _enrolled(redis_store, clock)
        assert _denial(_request_assertion(session_token)) == (401, {"error": "invalid_grant"})

    def test_revoked_agent(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        agent_store.rows[_AGENT]["revoked"] = True
        assert _denial(_request_assertion(grant)) == (401, {"error": "invalid_grant"})

    def test_revoked_owner_ends_every_grant(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        agent_store.revoked_owners.add(_MPASS_ID)
        assert _denial(_request_assertion(grant)) == (401, {"error": "invalid_grant"})

    def test_expired_grant(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        clock.now = _T0 + _agents().grant_ttl_seconds
        body = _assertion_body()
        response = _request_assertion(grant, body, proof=_proof(body, _agents().assertion_url, created_at=clock.now))
        assert _denial(response) == (401, {"error": "invalid_grant"})

    def test_proof_must_be_signed_by_the_agent(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        assert _denial(_request_assertion(grant, secret=OTHER_SECRET)) == (403, {"error": "invalid_proof"})

    def test_proof_for_the_grant_route_does_not_work_here(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        body = _assertion_body()
        response = _request_assertion(grant, body, proof=_proof(body, _agents().grant_url))
        assert _denial(response) == (403, {"error": "invalid_proof"})

    def test_a_proof_is_single_use(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        body = _assertion_body()
        proof = _proof(body, _agents().assertion_url)
        assert _request_assertion(grant, body, proof=proof).status_code == 200
        assert _denial(_request_assertion(grant, body, proof=proof)) == (400, {"error": "invalid_request"})

    def test_only_the_grants_agent_key(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        body = _assertion_body(nostr_pubkey=_pubkey(OTHER_SECRET))
        response = _request_assertion(grant, body, proof=_proof(body, _agents().assertion_url, secret=OTHER_SECRET))
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_proof_must_be_signed_by_the_named_key(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        body = _assertion_body(nostr_pubkey=_pubkey(OTHER_SECRET))
        response = _request_assertion(grant, body, proof=_proof(body, _agents().assertion_url))
        assert _denial(response) == (403, {"error": "invalid_proof"})

    @pytest.mark.parametrize("token", ["short", "x" * 44, "a" * 42 + "=", "a" * 42 + "."])
    def test_a_token_not_shaped_like_a_grant_skips_the_store(self, redis_store, clock, agent_store, token):
        agent_store.failure = AgentStoreUnavailable()
        assert _denial(_request_assertion(token)) == (401, {"error": "invalid_grant"})

    def test_unknown_relay(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        body = _assertion_body(relay_url="wss://elsewhere.example.com")
        response = _request_assertion(grant, body, proof=_proof(body, _agents().assertion_url))
        assert _denial(response) == (403, {"error": "authorization_denied"})

    @pytest.mark.parametrize("body, extra_headers, expected", [
        (b"x" * 4097, [], (413, {"error": "request_too_large"})),
        (b'{"relay_url": "wss://a"}', [], (400, {"error": "invalid_request"})),
        (None, [("Content-Encoding", "gzip")], (400, {"error": "invalid_request"})),
    ])
    def test_body_rules(self, redis_store, clock, agent_store, body, extra_headers, expected):
        _, grant = _enrolled(redis_store, clock)
        assert _denial(_request_assertion(grant, body, extra_headers=extra_headers)) == expected

    def test_store_outage_is_unavailable(self, redis_store, clock, agent_store):
        _, grant = _enrolled(redis_store, clock)
        agent_store.failure = AgentStoreUnavailable()
        assert _denial(_request_assertion(grant)) == (503, {"error": "issuance_unavailable"})

    def test_logs_no_credentials(self, redis_store, clock, agent_store, caplog):
        _, grant = _enrolled(redis_store, clock)
        with caplog.at_level(logging.DEBUG):
            assertion = _request_assertion(grant).json()["assertion"]
        for record in caplog.records:
            assert grant not in record.getMessage()
            assert assertion not in record.getMessage()


class TestAgentRevoke:
    def test_revokes_and_disconnects(self, redis_store, clock, agent_store, disconnector):
        session_token, grant = _enrolled(redis_store, clock)

        response = _request_revoke(session_token)

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {"revoked": True}
        assert agent_store.revocations == [(_MPASS_ID, _AGENT)]
        assert disconnector.calls == [_AGENT]
        assert _denial(_request_assertion(grant)) == (401, {"error": "invalid_grant"})

    def test_revocation_is_final(self, redis_store, clock, agent_store, disconnector):
        session_token, _ = _enrolled(redis_store, clock)
        _request_revoke(session_token)
        body = _grant_body(session_token)
        response = _request_grant(body, proof=_proof(body, _agents().grant_url, content="again"))
        assert _denial(response) == (400, {"error": "invalid_grant"})

    def test_revoking_again_succeeds_and_disconnects_again(self, redis_store, clock, agent_store, disconnector):
        session_token, _ = _enrolled(redis_store, clock)
        _request_revoke(session_token)

        response = _request_revoke(session_token)

        assert (response.status_code, response.json()) == (200, {"revoked": True})
        assert disconnector.calls == [_AGENT, _AGENT]

    def test_another_owners_agent_is_not_found(self, redis_store, clock, agent_store, disconnector):
        session_token = _signed_in(redis_store, clock)
        agent_store.rows[_AGENT] = {
            "owner_sub": "someone-else", "owner_pubkey": "ee" * 32, "grant_hash": "ff" * 32,
            "expires_at": _T0 + 60, "revoked": False,
        }
        assert _denial(_request_revoke(session_token)) == (404, {"error": "agent_not_found"})
        assert agent_store.rows[_AGENT]["revoked"] is False
        assert disconnector.calls == []

    def test_unknown_agent_is_not_found(self, redis_store, clock, agent_store, disconnector):
        session_token = _signed_in(redis_store, clock)
        assert _denial(_request_revoke(session_token)) == (404, {"error": "agent_not_found"})

    def test_incomplete_disconnect_is_retryable(self, redis_store, clock, agent_store, disconnector):
        session_token, _ = _enrolled(redis_store, clock)
        disconnector.failed = ("wss://relay.local.test",)
        assert _denial(_request_revoke(session_token)) == (503, {"error": "issuance_unavailable"})
        assert agent_store.rows[_AGENT]["revoked"] is True

        disconnector.failed = ()
        assert _request_revoke(session_token).json() == {"revoked": True}

    @pytest.mark.parametrize("headers, expected", [
        (None, (401, {"error": "session_required"})),
        ("no-such-session", (401, {"error": "session_required"})),
    ])
    def test_needs_the_owner_session(self, redis_store, clock, agent_store, disconnector, headers, expected):
        assert _denial(_request_revoke(headers)) == expected
        assert agent_store.revocations == []

    @pytest.mark.parametrize("body, expected", [
        (b"agent_pubkey=" + _AGENT.encode() + b"&agent_pubkey=" + _AGENT.encode(), 400),
        (b"agent_pubkey=" + _AGENT.encode() + b"&x=1", 400),
        (b"", 400),
        (b"agent_pubkey=" + b"a" * 1100, 413),
    ])
    def test_form_rules(self, redis_store, clock, agent_store, disconnector, body, expected):
        session_token = _signed_in(redis_store, clock)
        assert _request_revoke(session_token, body).status_code == expected

    def test_rate_limited_per_session(self, redis_store, clock, agent_store, disconnector):
        session_token = _signed_in(redis_store, clock)
        for _ in range(AGENT_REVOKE_RATE_LIMIT):
            assert _request_revoke(session_token).status_code == 404
        assert _denial(_request_revoke(session_token)) == (429, {"error": "rate_limited"})

    def test_content_encoding_is_refused(self, redis_store, clock, agent_store, disconnector):
        session_token = _signed_in(redis_store, clock)
        response = _request_revoke(session_token, extra_headers=[("Content-Encoding", "gzip")])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_store_outage_is_unavailable(self, redis_store, clock, agent_store, disconnector):
        session_token = _signed_in(redis_store, clock)
        agent_store.failure = AgentStoreUnavailable()
        assert _denial(_request_revoke(session_token)) == (503, {"error": "issuance_unavailable"})

    def test_revokes_even_while_the_idp_is_unreachable(
        self, redis_store, clock, agent_store, disconnector, monkeypatch
    ):
        session_token, _ = _enrolled(redis_store, clock)
        clock.now += REVALIDATION_INTERVAL_SECONDS
        monkeypatch.setattr("httpx.AsyncClient.post", _idp_refresh_response(503, {}))
        assert _request_revoke(session_token).json() == {"revoked": True}

    def test_does_not_touch_the_owner_session(self, redis_store, clock, agent_store, disconnector):
        session_token, _ = _enrolled(redis_store, clock)
        _request_revoke(session_token)
        assert client.get("/nip-fa/v1/session", headers={"Authorization": f"Bearer {session_token}"}).status_code == 200


class TestHumanAssertionsAreUnaffected:
    def test_user_session_still_gets_its_own_assertion(self, redis_store, clock, agent_store):
        from tests.test_nip_fa_assertions import _request_assertion as request_user_assertion

        session_token, _ = _enrolled(redis_store, clock)
        assert request_user_assertion(session_token).status_code == 200
