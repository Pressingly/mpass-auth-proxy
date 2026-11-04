import hashlib
import hmac
import logging
from datetime import datetime

import asyncpg
import httpx
import pytest
from coincurve import PrivateKey

import main as m
from nip_fa import identity_keys
from nip_fa.identities import (
    IdentityKeyService,
    IdentityStoreUnavailable,
    LaunchpadIdentityStore,
    StoredIdentity,
)
from nip_fa.identity_keys import (
    SECP256K1_ORDER,
    KeyDerivationError,
    NostrKeypair,
    derive_keypair,
    is_valid_scalar,
    xonly_pubkey_hex,
)
from nip_fa.sessions import REVALIDATION_INTERVAL_SECONDS
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)
from tests.test_nip_fa_login import (  # noqa: F401  (fixtures apply by import)
    _MPASS_ID,
    _idp_refresh_response,
    _is_test_client_request_line,
    _signed_in,
    client,
    clock,
    redis_store,
)

_VECTOR_MASTER = bytes.fromhex("11" * 32)
_VECTOR_SALT = bytes.fromhex("22" * 16)
_VECTOR_MPASS_ID = "mpass-id-1234"
_VECTOR_SECRET_HEX = "26a7e427e794f0c376860988503785ad6cf7a526e7ae2930db91ccbf4bc142af"
_VECTOR_PUBKEY_HEX = "357e48fe2f74a2cdcc3adfd26051d0411cca6668562973c5370869ac538c420e"


def _rfc5869_hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


class TestKeyDerivation:
    def test_pinned_vector(self):
        keypair = derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)
        assert keypair == NostrKeypair(_VECTOR_SECRET_HEX, _VECTOR_PUBKEY_HEX)

    def test_follows_the_documented_formula(self):
        expected = _rfc5869_hkdf_sha256(
            _VECTOR_MASTER, _VECTOR_SALT, b"moneta-buzz/nostr-key/v1|" + _VECTOR_MPASS_ID.encode()
        )
        assert derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID).secret_key_hex == expected.hex()

    def test_pubkey_is_the_bip340_xonly_key(self):
        assert xonly_pubkey_hex((3).to_bytes(32, "big")) == (
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        )
        keypair = derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)
        assert PrivateKey(bytes.fromhex(keypair.secret_key_hex)).public_key_xonly.format().hex() == keypair.pubkey_hex
        assert len(keypair.pubkey_hex) == 64 and keypair.pubkey_hex == keypair.pubkey_hex.lower()

    def test_every_input_changes_the_key(self):
        baseline = derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID).pubkey_hex
        assert derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, "mpass-id-1235").pubkey_hex != baseline
        assert derive_keypair(_VECTOR_MASTER, bytes.fromhex("23" * 16), _VECTOR_MPASS_ID).pubkey_hex != baseline
        assert derive_keypair(bytes.fromhex("12" * 32), _VECTOR_SALT, _VECTOR_MPASS_ID).pubkey_hex != baseline

    @pytest.mark.parametrize("scalar, valid", [
        (0, False), (1, True), (SECP256K1_ORDER - 1, True), (SECP256K1_ORDER, False), (2**256 - 1, False),
    ])
    def test_scalar_range(self, scalar, valid):
        assert is_valid_scalar(scalar.to_bytes(32, "big")) is valid

    def test_invalid_scalar_rederives_with_a_counter_byte(self, monkeypatch):
        real = identity_keys.hkdf_candidate
        invalid = {0: bytes(32), 1: SECP256K1_ORDER.to_bytes(32, "big")}
        attempts = []

        def candidate(master, salt, mpass_id, attempt):
            attempts.append(attempt)
            return invalid.get(attempt) or real(master, salt, mpass_id, attempt)

        monkeypatch.setattr(identity_keys, "hkdf_candidate", candidate)

        keypair = derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)

        assert attempts == [0, 1, 2]
        expected = _rfc5869_hkdf_sha256(
            _VECTOR_MASTER, _VECTOR_SALT, b"moneta-buzz/nostr-key/v1|" + _VECTOR_MPASS_ID.encode() + b"\x02"
        )
        assert keypair.secret_key_hex == expected.hex()
        assert keypair == derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)

    def test_gives_up_rather_than_return_an_invalid_scalar(self, monkeypatch):
        monkeypatch.setattr(identity_keys, "hkdf_candidate", lambda *args: bytes(32))
        with pytest.raises(KeyDerivationError):
            derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)

    def test_repr_hides_the_secret(self):
        keypair = derive_keypair(_VECTOR_MASTER, _VECTOR_SALT, _VECTOR_MPASS_ID)
        assert _VECTOR_SECRET_HEX not in repr(keypair)
        assert _VECTOR_SECRET_HEX not in str(keypair)
        assert _VECTOR_PUBKEY_HEX in repr(keypair)


class _FakeIdentityStore:
    def __init__(self):
        self.rows: dict[str, StoredIdentity] = {}
        self.calls: list[tuple] = []
        self.failure: Exception | None = None

    async def ensure_identity(self, sub, pubkey_hex, email):
        self.calls.append((sub, pubkey_hex, email))
        if self.failure is not None:
            raise self.failure
        if any(row.pubkey_hex == pubkey_hex for key, row in self.rows.items() if key != sub):
            return None
        return self.rows.setdefault(sub, StoredIdentity(pubkey_hex=pubkey_hex, revoked=False))


@pytest.fixture()
def identity_store(monkeypatch):
    store = _FakeIdentityStore()
    config = m._BUZZ_ADAPTER_CONFIG
    service = IdentityKeyService(config.identity_master_secret, config.identity_salt, store)
    monkeypatch.setattr(m._buzz_adapter, "identity_keys", service)
    return store


def _expected_keypair() -> NostrKeypair:
    config = m._BUZZ_ADAPTER_CONFIG
    return derive_keypair(config.identity_master_secret, config.identity_salt, _MPASS_ID)


def _identity_key(token, **headers):
    return client.get("/nip-fa/v1/identity/key", headers={"Authorization": f"Bearer {token}", **headers})


class TestIdentityKeyEndpoint:
    def test_issues_the_derived_key_and_binds_it(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)

        response = _identity_key(token)

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert set(body) == {"nostr_pubkey", "secret_key"}
        expected = _expected_keypair()
        assert body == {"nostr_pubkey": expected.pubkey_hex, "secret_key": expected.secret_key_hex}
        assert xonly_pubkey_hex(bytes.fromhex(body["secret_key"])) == body["nostr_pubkey"]
        assert identity_store.calls == [(_MPASS_ID, expected.pubkey_hex, "jane.doe@corp.example")]

    def test_same_key_on_every_device(self, redis_store, clock, identity_store):
        first_device = _signed_in(redis_store, clock)
        second_device = _signed_in(redis_store, clock)

        assert _identity_key(first_device).json() == _identity_key(second_device).json()

    def test_revoked_identity_is_denied(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows[_MPASS_ID] = StoredIdentity(_expected_keypair().pubkey_hex, revoked=True)

        response = _identity_key(token)

        assert response.status_code == 403
        assert response.json() == {"error": "authorization_denied"}
        assert response.headers["cache-control"] == "no-store"

    def test_stored_key_that_differs_from_the_derived_one_fails_closed(
        self, redis_store, clock, identity_store, caplog
    ):
        token = _signed_in(redis_store, clock)
        stale_pubkey = "ab" * 32
        identity_store.rows[_MPASS_ID] = StoredIdentity(stale_pubkey, revoked=False)

        with caplog.at_level(logging.INFO):
            response = _identity_key(token)

        assert response.status_code == 403
        assert response.json() == {"error": "binding_mismatch"}
        errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.getMessage().startswith("nip-fa:")]
        assert len(errors) == 1
        assert f"mpass_id={_MPASS_ID} reason=binding_mismatch" in errors[0].getMessage()
        assert stale_pubkey not in errors[0].getMessage()
        assert _expected_keypair().pubkey_hex not in errors[0].getMessage()

    def test_mismatch_wins_over_revocation(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows[_MPASS_ID] = StoredIdentity("ab" * 32, revoked=True)

        assert _identity_key(token).json() == {"error": "binding_mismatch"}

    def test_key_bound_to_someone_else_fails_closed(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.rows["another-mpass-id"] = StoredIdentity(_expected_keypair().pubkey_hex, revoked=False)

        assert _identity_key(token).json() == {"error": "binding_mismatch"}

    def test_store_outage_is_issuance_unavailable(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        identity_store.failure = IdentityStoreUnavailable()

        response = _identity_key(token)

        assert response.status_code == 503
        assert response.json() == {"error": "issuance_unavailable"}
        assert "secret_key" not in response.text

    def test_missing_session_is_session_required(self, redis_store, identity_store):
        response = client.get("/nip-fa/v1/identity/key")
        assert response.status_code == 401
        assert response.json() == {"error": "session_required"}
        assert _identity_key("not-a-session").json() == {"error": "session_required"}
        assert identity_store.calls == []

    def test_repeated_authorization_is_invalid_request(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        response = client.get(
            "/nip-fa/v1/identity/key",
            headers=[("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_request"}
        assert identity_store.calls == []

    def test_expired_session_is_session_expired(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        clock.now += m._BUZZ_ADAPTER_CONFIG.session_ttl_seconds

        assert _identity_key(token).json() == {"error": "session_expired"}
        assert identity_store.calls == []

    def test_session_ended_on_revalidation_gets_no_key(
        self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(400, {"error": "invalid_grant"}))
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _identity_key(token)

        assert response.status_code == 401
        assert response.json() == {"error": "session_expired"}
        assert identity_store.calls == []

    def test_unreachable_idp_at_revalidation_gets_no_key(
        self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response(500, {}))
        clock.now += REVALIDATION_INTERVAL_SECONDS

        response = _identity_key(token)

        assert response.status_code == 503
        assert response.json() == {"error": "issuance_unavailable"}
        assert identity_store.calls == []
        assert client.get("/nip-fa/v1/session", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    def test_revalidated_session_gets_the_key(
        self, redis_store, clock, identity_store, monkeypatch, fake_token_endpoint
    ):
        token = _signed_in(redis_store, clock)
        monkeypatch.setattr(httpx.AsyncClient, "post", _idp_refresh_response())
        clock.now += REVALIDATION_INTERVAL_SECONDS

        assert _identity_key(token).status_code == 200

    def test_only_get_is_routed(self, redis_store, clock, identity_store):
        token = _signed_in(redis_store, clock)
        response = client.post("/nip-fa/v1/identity/key", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 405


class TestIssuanceLogging:
    def test_one_audit_line_and_no_secret_in_the_logs(self, redis_store, clock, identity_store, caplog):
        with caplog.at_level(logging.DEBUG):
            token = _signed_in(redis_store, clock)
            response = _identity_key(token)
            identity_store.rows[_MPASS_ID] = StoredIdentity(_expected_keypair().pubkey_hex, revoked=True)
            assert _identity_key(token).status_code == 403

        body = response.json()
        lines = [
            record.getMessage() + (record.exc_text or "")
            for record in caplog.records
            if not _is_test_client_request_line(record)
        ]
        issued = [line for line in lines if "identity key issued" in line]
        assert issued == [f"nip-fa: identity key issued mpass_id={_MPASS_ID} pubkey={body['nostr_pubkey']}"]
        logged = "\n".join(lines)
        assert body["secret_key"] not in logged
        assert token not in logged


class _FakeConnection:
    def __init__(self, row=None, execute_error=None, fetch_error=None):
        self.row = row
        self.execute_error = execute_error
        self.fetch_error = fetch_error
        self.statements: list[tuple] = []

    async def execute(self, sql, *args):
        self.statements.append((sql, args))
        if self.execute_error is not None:
            raise self.execute_error

    async def fetchrow(self, sql, *args):
        self.statements.append((sql, args))
        if self.fetch_error is not None:
            raise self.fetch_error
        return self.row


class _FakePool:
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


def _store_over(connection) -> LaunchpadIdentityStore:
    async def pool_factory():
        return _FakePool(connection)

    return LaunchpadIdentityStore(pool_factory)


class TestLaunchpadIdentityStore:
    @pytest.mark.asyncio
    async def test_binds_then_reads_back(self):
        connection = _FakeConnection(row={"pubkey_hex": "ab" * 32, "revoked_at": None})

        stored = await _store_over(connection).ensure_identity("sub-1", "ab" * 32, "jane@corp.example")

        assert stored == StoredIdentity(pubkey_hex="ab" * 32, revoked=False)
        assert connection.statements == [
            (
                "INSERT INTO buzz_identities (sub, pubkey_hex, email) VALUES ($1, $2, $3) "
                "ON CONFLICT (sub) DO NOTHING",
                ("sub-1", "ab" * 32, "jane@corp.example"),
            ),
            ("SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1", ("sub-1",)),
        ]

    @pytest.mark.asyncio
    async def test_revoked_at_marks_the_identity_revoked(self):
        connection = _FakeConnection(row={"pubkey_hex": "ab" * 32, "revoked_at": datetime(2026, 11, 4)})
        stored = await _store_over(connection).ensure_identity("sub-1", "ab" * 32, None)
        assert stored.revoked is True

    @pytest.mark.asyncio
    async def test_key_owned_by_another_sub_reads_back_as_no_binding(self):
        connection = _FakeConnection(row=None, execute_error=asyncpg.UniqueViolationError("pubkey taken"))
        assert await _store_over(connection).ensure_identity("sub-1", "ab" * 32, None) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [
        asyncpg.UndefinedTableError("no buzz_identities"),
        asyncpg.InsufficientPrivilegeError("no grant"),
        ConnectionResetError(),
        TimeoutError(),
    ])
    async def test_database_failures_are_unavailable(self, error):
        with pytest.raises(IdentityStoreUnavailable):
            await _store_over(_FakeConnection(fetch_error=error)).ensure_identity("sub-1", "ab" * 32, None)

    @pytest.mark.asyncio
    async def test_unexpected_errors_are_not_swallowed(self):
        with pytest.raises(KeyError):
            await _store_over(_FakeConnection(fetch_error=KeyError("bug"))).ensure_identity("sub-1", "ab" * 32, None)

    @pytest.mark.asyncio
    async def test_pool_outage_from_the_gateway_is_unavailable(self, monkeypatch):
        async def no_pool():
            raise m.EmailOverlayUnavailable("launchpad pool unavailable")

        monkeypatch.setattr(m, "_get_launchpad_pool", no_pool)
        store = LaunchpadIdentityStore(m._PlatformGateway().launchpad_pool)

        with pytest.raises(IdentityStoreUnavailable):
            await store.ensure_identity("sub-1", "ab" * 32, None)
