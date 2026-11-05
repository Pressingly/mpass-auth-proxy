import asyncio
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import urlencode

import asyncpg
import httpx
import jwt as pyjwt
import pytest
from coincurve import PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from redis.exceptions import ConnectionError as RedisConnectionError

from nip_fa import agents as agent_sql
from nip_fa.agent_grants import (
    AGENT_GRANT_TOKEN_TYPE,
    SESSION_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    grant_hash,
    grant_response,
    is_grant_token,
    new_grant_token,
    parse_agent_grant_form,
    parse_agent_revoke_form,
)
from nip_fa.agent_routes import grant_refusal_reason
from nip_fa.agents import (
    AgentStoreUnavailable,
    Enrollment,
    EnrollmentRequest,
    LaunchpadAgentStore,
    Revocation,
    StoredGrant,
)
from nip_fa.assertions import SigningKey
from nip_fa.config import RelayEndpoint
from nip_fa.identities import IdentityStoreUnavailable
from nip_fa.owner_attestation import (
    NO_SUPPORTED_CLAUSES,
    condition_clauses,
    parse_owner_attestation,
    signing_digest,
    verified_owner,
)
from nip_fa.proof_replay import PROOF_MEMORY_SECONDS, ProofReplayGuard, ReplayGuardUnavailable
from nip_fa.relay_commands import (
    COMMAND_TTL_SECONDS,
    CommandIssuer,
    RelayDisconnector,
    default_http_client,
    disconnect_claims,
)

# NIP-OA "Test Vectors" (block/buzz docs/nips/NIP-OA.md)
_VECTOR_OWNER = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
_VECTOR_AGENT = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
_VECTOR_CONDITIONS = "kind=1&created_at<1713957000"
_VECTOR_DIGEST = "08cdecd55af4c28d3801fd69615dcf5cc04fab3bc134b38a840bf157197069a6"
_VECTOR_SIG = (
    "8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb"
    "2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369"
)
_VECTOR_TAG = json.dumps(["auth", _VECTOR_OWNER, _VECTOR_CONDITIONS, _VECTOR_SIG], separators=(",", ":"))

_OWNER_SECRET = bytes.fromhex("11" * 32)
_AGENT_SECRET = bytes.fromhex("22" * 32)


def _pubkey(secret: bytes) -> str:
    return PrivateKey(secret).public_key_xonly.format().hex()


def attestation(agent_pubkey: str, owner_secret: bytes, conditions: str = "") -> str:
    signature = PrivateKey(owner_secret).sign_schnorr(signing_digest(agent_pubkey, conditions)).hex()
    return json.dumps(["auth", _pubkey(owner_secret), conditions, signature], separators=(",", ":"))


class TestOwnerAttestation:
    def test_matches_the_nip_oa_vector(self):
        assert signing_digest(_VECTOR_AGENT, _VECTOR_CONDITIONS).hex() == _VECTOR_DIGEST
        supported = frozenset({"kind=", "created_at<"})
        assert verified_owner(_VECTOR_TAG, _VECTOR_AGENT, supported) == _VECTOR_OWNER

    def test_refuses_clauses_the_adapter_does_not_support(self):
        assert verified_owner(_VECTOR_TAG, _VECTOR_AGENT) is None
        assert verified_owner(_VECTOR_TAG, _VECTOR_AGENT, frozenset({"kind="})) is None

    def test_accepts_empty_conditions(self):
        agent = _pubkey(_AGENT_SECRET)
        assert verified_owner(attestation(agent, _OWNER_SECRET), agent, NO_SUPPORTED_CLAUSES) == _pubkey(_OWNER_SECRET)

    def test_is_bound_to_the_agent_key(self):
        tag = attestation(_pubkey(_AGENT_SECRET), _OWNER_SECRET)
        assert verified_owner(tag, _VECTOR_AGENT) is None

    def test_refuses_self_attestation(self):
        owner = _pubkey(_OWNER_SECRET)
        assert verified_owner(attestation(owner, _OWNER_SECRET), owner) is None

    @pytest.mark.parametrize("conditions", [
        "kind=1&", "&kind=1", "kind=1&&kind=2", "kind=01", "kind=65536", "kind= 1", "Kind=1",
        "created_at<4294967296", "created_at=1", "expires=1", "kind=" + "1" * 5000,
    ])
    def test_malformed_conditions(self, conditions):
        assert condition_clauses(conditions) is None

    def test_condition_clause_names_keep_their_order(self):
        assert condition_clauses("created_at>5&kind=0&kind=1") == ("created_at>", "kind=", "kind=")
        assert condition_clauses("") == ()

    @pytest.mark.parametrize("raw", [
        "",
        "not json",
        json.dumps(["auth", _VECTOR_OWNER, _VECTOR_CONDITIONS]),
        json.dumps(["auth", _VECTOR_OWNER, _VECTOR_CONDITIONS, _VECTOR_SIG, "extra"]),
        json.dumps(["delegation", _VECTOR_OWNER, _VECTOR_CONDITIONS, _VECTOR_SIG]),
        json.dumps(["auth", _VECTOR_OWNER.upper(), _VECTOR_CONDITIONS, _VECTOR_SIG]),
        json.dumps(["auth", _VECTOR_OWNER, _VECTOR_CONDITIONS, _VECTOR_SIG[:-2]]),
        json.dumps(["auth", _VECTOR_OWNER, 1, _VECTOR_SIG]),
        json.dumps({"auth": _VECTOR_OWNER}),
    ])
    def test_malformed_tags(self, raw):
        assert parse_owner_attestation(raw) is None

    def test_a_tampered_signature_fails(self):
        agent = _pubkey(_AGENT_SECRET)
        tag = json.loads(attestation(agent, _OWNER_SECRET))
        tag[3] = ("0" if tag[3][0] != "0" else "1") + tag[3][1:]
        assert verified_owner(json.dumps(tag), agent) is None


def grant_form(**overrides) -> dict:
    form = {
        "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": "session-token",
        "subject_token_type": SESSION_TOKEN_TYPE,
        "requested_token_type": AGENT_GRANT_TOKEN_TYPE,
        "agent_pubkey": "ab" * 32,
        "owner_attestation": '["auth","x","","y"]',
    }
    form.update(overrides)
    return {key: value for key, value in form.items() if value is not None}


class TestAgentGrantForm:
    def test_parses_the_six_fields(self):
        parsed = parse_agent_grant_form(urlencode(grant_form()).encode())
        assert (parsed.subject_token, parsed.agent_pubkey, parsed.owner_attestation) == (
            "session-token", "ab" * 32, '["auth","x","","y"]',
        )
        assert "session-token" not in repr(parsed)

    def test_uses_the_nip_fa_token_types(self):
        assert SESSION_TOKEN_TYPE == "urn:nostr:params:oauth:token-type:nip-fa-session"
        assert AGENT_GRANT_TOKEN_TYPE == "urn:nostr:params:oauth:token-type:nip-fi-agent-grant"

    @pytest.mark.parametrize("overrides", [
        {"grant_type": None},
        {"subject_token": None},
        {"owner_attestation": None},
        {"subject_token": ""},
        {"grant_type": "authorization_code"},
        {"subject_token_type": "urn:builderlab:params:oauth:token-type:bb-session"},
        {"requested_token_type": "urn:builderlab:params:oauth:token-type:nip-fi-agent-grant"},
        {"agent_pubkey": "AB" * 32},
        {"agent_pubkey": "ab" * 31},
        {"runtime": "local"},
    ])
    def test_refuses_any_other_form(self, overrides):
        assert parse_agent_grant_form(urlencode(grant_form(**overrides)).encode()) is None

    @pytest.mark.parametrize("raw", [
        b"",
        b"grant_type",
        urlencode(grant_form()).encode() + b"&agent_pubkey=" + b"ab" * 32,
        urlencode(grant_form()).encode() + b"&",
        urlencode(grant_form()).encode().replace(b"subject_token=session-token", b"subject_token=%ff"),
        b"\xff",
    ])
    def test_refuses_malformed_or_repeated_fields(self, raw):
        assert parse_agent_grant_form(raw) is None


class TestAgentRevokeForm:
    def test_parses_the_one_field(self):
        assert parse_agent_revoke_form(b"agent_pubkey=" + b"ab" * 32) == "ab" * 32

    @pytest.mark.parametrize("raw", [
        b"",
        b"agent_pubkey=" + b"AB" * 32,
        b"agent_pubkey=" + b"ab" * 32 + b"&agent_pubkey=" + b"ab" * 32,
        b"agent_pubkey=" + b"ab" * 32 + b"&reason=x",
        b'{"agent_pubkey": "' + b"ab" * 32 + b'"}',
    ])
    def test_refuses_any_other_form(self, raw):
        assert parse_agent_revoke_form(raw) is None


class TestGrantTokens:
    def test_issued_tokens_have_the_grant_shape(self):
        assert all(is_grant_token(new_grant_token()) for _ in range(50))

    def test_tokens_are_random_and_only_their_hash_is_stored(self):
        first, second = new_grant_token(), new_grant_token()
        assert first != second
        assert len(first) <= 1024 and not any(char.isspace() for char in first)
        assert grant_hash(first) == hashlib.sha256(first.encode()).hexdigest()

    def test_grant_response_is_rfc_8693(self):
        assert grant_response("tok", 60, "ab" * 32, "https://issuer.example.com") == {
            "access_token": "tok",
            "issued_token_type": AGENT_GRANT_TOKEN_TYPE,
            "token_type": "N_A",
            "expires_in": 60,
            "nostr_owner_pubkey": "ab" * 32,
            "nip_fi_issuer": "https://issuer.example.com",
        }


class _SetRedis:
    def __init__(self, failure=None):
        self.values: dict[str, str] = {}
        self.calls: list[tuple] = []
        self.failure = failure

    async def set(self, key, value, *, nx=False, ex=None):
        self.calls.append((key, nx, ex))
        if self.failure is not None:
            raise self.failure
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True


class TestProofReplayGuard:
    @pytest.mark.asyncio
    async def test_a_proof_is_accepted_once_per_route(self):
        redis = _SetRedis()
        grant_guard = ProofReplayGuard(lambda: redis, "agent-grant")
        assertion_guard = ProofReplayGuard(lambda: redis, "agent-assertion")

        assert await grant_guard.first_use("e1") is True
        assert await grant_guard.first_use("e1") is False
        assert await assertion_guard.first_use("e1") is True
        assert redis.calls[0] == ("nip_fa_proof:agent-grant:e1", True, PROOF_MEMORY_SECONDS)

    def test_memory_outlasts_the_proof_window(self):
        assert PROOF_MEMORY_SECONDS > 60 + 5

    @pytest.mark.asyncio
    async def test_redis_failure_is_unavailable(self):
        guard = ProofReplayGuard(lambda: _SetRedis(RedisConnectionError("down")), "agent-grant")
        with pytest.raises(ReplayGuardUnavailable):
            await guard.first_use("e1")


_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_SIGNING_KEY = SigningKey(private_key=_RSA_KEY, kid="kid-1")
_ISSUER = CommandIssuer(
    issuer="https://auth.example.com/nip-fi", principal="svc@auth", signing_key=lambda: _SIGNING_KEY
)
_RELAYS = (
    RelayEndpoint("wss://a.example.com", "http://relay-a:3000", "https://a.example.com"),
    RelayEndpoint("wss://b.example.com:8443", "http://relay-b:3000", "https://relay-b-admin.example.com"),
)
_TARGET = "cd" * 32
_NOW = 1_800_000_000


def _disconnector(handler, relays=_RELAYS) -> RelayDisconnector:
    def client():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    return RelayDisconnector(relays, _ISSUER, deny_seconds=300, clock=lambda: float(_NOW), http_client=client)


def _accepting(requests: list):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"disconnected": True})

    return handler


def _command(request: httpx.Request) -> tuple[dict, dict]:
    scheme, _, token = request.headers["nostr-federated-identity"].partition(" ")
    assert scheme == "Bearer"
    header = pyjwt.get_unverified_header(token)
    claims = pyjwt.decode(
        token,
        _RSA_KEY.public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": False, "verify_iat": False},
    )
    return header, claims


class TestRelayDisconnector:
    def test_claims_follow_the_nip_fi_command_contract(self):
        assert disconnect_claims(_ISSUER, "https://a.example.com", _TARGET, _NOW, _NOW + 300, "jti-1") == {
            "iss": "https://auth.example.com/nip-fi",
            "sub": "svc@auth",
            "aud": "https://a.example.com",
            "iat": _NOW,
            "exp": _NOW + COMMAND_TTL_SECONDS,
            "jti": "jti-1",
            "method": "POST",
            "path": "/api/nip-fi/disconnect",
            "cmd": "disconnect",
            "target_pubkey": _TARGET,
            "until": _NOW + 300,
        }

    def test_command_lifetime_fits_the_relay_bound(self):
        assert 0 < COMMAND_TTL_SECONDS <= 60

    @pytest.mark.asyncio
    async def test_disconnects_on_every_relay(self):
        requests: list[httpx.Request] = []

        report = await _disconnector(_accepting(requests)).disconnect(_TARGET)

        assert report.complete
        assert sorted(str(request.url) for request in requests) == [
            "http://relay-a:3000/api/nip-fi/disconnect",
            "http://relay-b:3000/api/nip-fi/disconnect",
        ]
        commands = {str(request.url): _command(request) for request in requests}
        header, claims = commands["http://relay-b:3000/api/nip-fi/disconnect"]
        assert header == {"alg": "RS256", "typ": "nip-fi-command+jwt", "kid": "kid-1"}
        assert claims["aud"] == "https://relay-b-admin.example.com"
        assert claims["target_pubkey"] == _TARGET
        assert claims["until"] == _NOW + 300
        assert len({claims["jti"] for _, claims in commands.values()}) == 2
        assert all(json.loads(request.content) == {"pubkey": _TARGET} for request in requests)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("response", [
        httpx.Response(503, text="deny set full\n"),
        httpx.Response(403),
        httpx.Response(200, json={"disconnected": False}),
        httpx.Response(200, text="ok"),
        httpx.Response(302, headers={"Location": "http://relay-a:3000/elsewhere"}),
    ])
    async def test_anything_but_a_disconnected_200_fails_that_relay(self, response):
        def handler(request):
            if request.url.host == "relay-a":
                return response
            return httpx.Response(200, json={"disconnected": True})

        report = await _disconnector(handler).disconnect(_TARGET)

        assert report.failed_relays == ("wss://a.example.com",)
        assert not report.complete

    @pytest.mark.asyncio
    async def test_transport_errors_fail_that_relay(self):
        def handler(request):
            raise httpx.ConnectTimeout("timeout", request=request)

        report = await _disconnector(handler).disconnect(_TARGET)

        assert report.failed_relays == ("wss://a.example.com", "wss://b.example.com:8443")

    @pytest.mark.asyncio
    async def test_never_logs_the_command(self, caplog):
        requests: list[httpx.Request] = []
        with caplog.at_level("DEBUG"):
            await _disconnector(_accepting(requests)).disconnect(_TARGET)
        token = requests[0].headers["nostr-federated-identity"].partition(" ")[2]
        assert all(token not in record.getMessage() for record in caplog.records)

    @pytest.mark.asyncio
    async def test_default_client_follows_no_redirects_and_ignores_proxy_env(self):
        async with default_http_client() as client:
            assert client.follow_redirects is False
            assert client._trust_env is False


def _row(**values):
    return values


class _ScriptedConnection:
    """Answers each statement from a script keyed by the SQL text."""

    def __init__(self, answers: dict, error: Exception | None = None):
        self.answers = answers
        self.error = error
        self.statements: list[tuple] = []
        self.transactions = 0

    def transaction(self):
        connection = self

        class _Transaction:
            async def __aenter__(self):
                connection.transactions += 1

            async def __aexit__(self, *exc):
                return False

        return _Transaction()

    async def _answer(self, sql, args):
        self.statements.append((sql, args))
        if self.error is not None:
            raise self.error
        return self.answers.get(sql)

    async def fetchrow(self, sql, *args):
        return await self._answer(sql, args)

    async def fetchval(self, sql, *args):
        return await self._answer(sql, args)


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                return pool.connection

            async def __aexit__(self, *exc):
                return False

        return _Acquire()


def _store(connection) -> LaunchpadAgentStore:
    async def pool_factory():
        return _Pool(connection)

    return LaunchpadAgentStore(pool_factory)


_OWNER_PUBKEY = "aa" * 32
_REVOKED = datetime(2026, 1, 1, tzinfo=UTC)
_AGENT = "bb" * 32
_ENROLL = EnrollmentRequest(
    owner_sub="owner-1", owner_pubkey=_OWNER_PUBKEY, agent_pubkey=_AGENT, grant_hash="cc" * 32,
    expires_at=_NOW + 600, max_agents=2,
)


def _enroll_answers(**overrides) -> dict:
    answers = {
        agent_sql.LOCK_OWNER_SQL: _row(pubkey_hex=_OWNER_PUBKEY, revoked_at=None),
        agent_sql.IS_IDENTITY_KEY_SQL: False,
        agent_sql.EXISTING_AGENT_SQL: None,
        agent_sql.OTHER_ACTIVE_AGENTS_SQL: 1,
        agent_sql.ENROLL_SQL: _AGENT,
    }
    answers.update(overrides)
    return answers


class TestLaunchpadAgentStore:
    @pytest.mark.asyncio
    async def test_enrolls_inside_one_transaction_holding_the_owner(self):
        connection = _ScriptedConnection(_enroll_answers())

        assert await _store(connection).enroll(_ENROLL) is Enrollment.ENROLLED

        assert connection.transactions == 1
        assert [sql for sql, _ in connection.statements] == [
            agent_sql.LOCK_OWNER_SQL,
            agent_sql.IS_IDENTITY_KEY_SQL,
            agent_sql.EXISTING_AGENT_SQL,
            agent_sql.OTHER_ACTIVE_AGENTS_SQL,
            agent_sql.ENROLL_SQL,
        ]
        assert "FOR NO KEY UPDATE" in agent_sql.LOCK_OWNER_SQL
        assert connection.statements[-1][1] == (
            _AGENT, "owner-1", "cc" * 32, datetime.fromtimestamp(_NOW + 600, UTC),
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("answers, outcome", [
        ({agent_sql.LOCK_OWNER_SQL: None}, Enrollment.OWNER_REFUSED),
        ({agent_sql.LOCK_OWNER_SQL: _row(pubkey_hex=_OWNER_PUBKEY, revoked_at=_REVOKED)}, Enrollment.OWNER_REFUSED),
        ({agent_sql.LOCK_OWNER_SQL: _row(pubkey_hex="dd" * 32, revoked_at=None)}, Enrollment.OWNER_REFUSED),
        ({agent_sql.IS_IDENTITY_KEY_SQL: True}, Enrollment.AGENT_REFUSED),
        ({agent_sql.EXISTING_AGENT_SQL: _row(owner_sub="owner-2", revoked_at=None)}, Enrollment.AGENT_REFUSED),
        ({agent_sql.EXISTING_AGENT_SQL: _row(owner_sub="owner-1", revoked_at=_REVOKED)}, Enrollment.AGENT_REFUSED),
        ({agent_sql.OTHER_ACTIVE_AGENTS_SQL: 2}, Enrollment.CAP_REACHED),
        ({agent_sql.ENROLL_SQL: None}, Enrollment.AGENT_REFUSED),
    ])
    async def test_refusals(self, answers, outcome):
        assert await _store(_ScriptedConnection(_enroll_answers() | answers)).enroll(_ENROLL) is outcome

    @pytest.mark.asyncio
    async def test_re_enrolling_an_own_active_agent_is_not_capped_by_itself(self):
        connection = _ScriptedConnection(
            _enroll_answers() | {agent_sql.EXISTING_AGENT_SQL: _row(owner_sub="owner-1", revoked_at=None)}
        )
        assert await _store(connection).enroll(_ENROLL) is Enrollment.ENROLLED
        assert connection.statements[3][1] == ("owner-1", _AGENT)

    @pytest.mark.asyncio
    async def test_reads_a_grant(self):
        expires = datetime.fromtimestamp(_NOW + 60, UTC)
        row = _row(
            agent_pubkey=_AGENT, owner_sub="owner-1", grant_expires_at=expires, revoked_at=None,
            owner_pubkey=_OWNER_PUBKEY, owner_revoked_at=None,
        )
        connection = _ScriptedConnection({agent_sql.GRANT_SQL: row})

        assert await _store(connection).grant("cc" * 32) == StoredGrant(
            agent_pubkey=_AGENT, owner_sub="owner-1", owner_pubkey=_OWNER_PUBKEY,
            expires_at=_NOW + 60, revoked=False, owner_revoked=False,
        )
        assert await _store(_ScriptedConnection({})).grant("cc" * 32) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("revoked, owned, outcome", [
        (_AGENT, None, Revocation.REVOKED),
        (None, _row(revoked_at=datetime.now(UTC)), Revocation.ALREADY_REVOKED),
        (None, None, Revocation.NOT_FOUND),
    ])
    async def test_revokes(self, revoked, owned, outcome):
        connection = _ScriptedConnection({agent_sql.REVOKE_SQL: revoked, agent_sql.OWNED_AGENT_SQL: owned})

        assert await _store(connection).revoke("owner-1", _AGENT) is outcome
        assert connection.statements[0] == (agent_sql.REVOKE_SQL, (_AGENT, "owner-1"))
        assert "revoked_at IS NULL" in agent_sql.REVOKE_SQL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [asyncpg.PostgresError(), OSError(), TimeoutError()])
    async def test_database_errors_are_unavailable(self, error):
        store = _store(_ScriptedConnection({}, error=error))
        for operation in (store.enroll(_ENROLL), store.grant("cc" * 32), store.revoke("owner-1", _AGENT)):
            with pytest.raises(AgentStoreUnavailable):
                await operation

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [OSError("no route"), IdentityStoreUnavailable()])
    async def test_an_unreachable_pool_is_unavailable(self, error):
        async def pool_factory():
            raise error

        with pytest.raises(AgentStoreUnavailable):
            await LaunchpadAgentStore(pool_factory).grant("cc" * 32)


def _grant(**overrides) -> StoredGrant:
    values = dict(
        agent_pubkey=_AGENT, owner_sub="owner-1", owner_pubkey=_OWNER_PUBKEY,
        expires_at=_NOW + 60, revoked=False, owner_revoked=False,
    )
    values.update(overrides)
    return StoredGrant(**values)


class TestGrantUsability:
    @pytest.mark.parametrize("grant, reason", [
        (None, "unknown_grant"),
        (_grant(revoked=True, expires_at=None), "agent_revoked"),
        (_grant(owner_revoked=True), "owner_revoked"),
        (_grant(expires_at=_NOW), "grant_expired"),
        (_grant(expires_at=None), "grant_expired"),
        (_grant(), None),
    ])
    def test_refusal_reasons(self, grant, reason):
        assert grant_refusal_reason(grant, _NOW) == reason


def test_disconnector_runs_relays_concurrently():
    started: list[str] = []
    release = asyncio.Event()

    async def run():
        async def handler(request):
            started.append(request.url.host)
            if len(started) == len(_RELAYS):
                release.set()
            await release.wait()
            return httpx.Response(200, json={"disconnected": True})

        def client():
            return httpx.AsyncClient(transport=httpx.MockTransport(handler))

        disconnector = RelayDisconnector(_RELAYS, _ISSUER, 300, lambda: float(_NOW), client)
        return await asyncio.wait_for(disconnector.disconnect(_TARGET), timeout=5)

    assert asyncio.run(run()).complete
