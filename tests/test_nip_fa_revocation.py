import asyncio
import json
import logging
from datetime import UTC, datetime

import asyncpg
import httpx
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

import main as m
from nip_fa import revocation as revocation_sql
from nip_fa.admin_routes import INTERNAL_PREFIX
from nip_fa.identities import IdentityStoreUnavailable, StoredIdentity
from nip_fa.relay_commands import DisconnectReport, RelayDisconnector
from nip_fa.revocation import (
    BoundIdentity,
    DenyRepusher,
    LaunchpadRevocationStore,
    OwnerRevocation,
    RecentRevocation,
    RevocationOutcome,
    RevocationStoreUnavailable,
    RevokedSubjects,
    StoredRevocation,
    SubjectMarksUnavailable,
    subject_mark_key,
)
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)
from tests.test_nip_fa_agent_units import (
    _ISSUER,
    _NOW,
    _RELAYS,
    _accepting,
    _command,
    _Pool,
    _ScriptedConnection,
)
from tests.test_nip_fa_agents import _AgentRedis
from tests.test_nip_fa_identity_key import identity_store  # noqa: F401
from tests.test_nip_fa_login import (  # noqa: F401  (fixtures apply by import)
    _MPASS_ID,
    _T0,
    _exchange,
    _login_code,
    _signed_in,
    client,
    clock,
)

_REVOKE_ROUTE = INTERNAL_PREFIX + "/v1/identity/revoke"
_PUBKEY_ROUTE = INTERNAL_PREFIX + "/v1/identity/pubkey"
_OWNER = "aa" * 32
_AGENT = "bb" * 32
_REVOKED_AT = datetime.fromtimestamp(_NOW - 100, UTC)
_TTL = 300


def _admin_token() -> str:
    return m._BUZZ_ADAPTER_CONFIG.revocation.admin_token


def _store_over(connection) -> LaunchpadRevocationStore:
    async def pool_factory():
        return _Pool(connection)

    return LaunchpadRevocationStore(pool_factory)


class _FetchConnection(_ScriptedConnection):
    async def fetch(self, sql, *args):
        return await self._answer(sql, args)


class TestLaunchpadRevocationStore:
    @pytest.mark.asyncio
    async def test_revokes_once(self):
        connection = _ScriptedConnection(
            {revocation_sql.REVOKE_IDENTITY_SQL: {"pubkey_hex": _OWNER, "revoked_at": _REVOKED_AT}}
        )
        assert await _store_over(connection).revoke("sub-1") == StoredRevocation(_OWNER, _NOW - 100, True)
        assert connection.statements == [(revocation_sql.REVOKE_IDENTITY_SQL, ("sub-1",))]
        assert "revoked_at IS NULL" in revocation_sql.REVOKE_IDENTITY_SQL

    @pytest.mark.asyncio
    async def test_revocation_time_rounds_up_and_uses_the_statement_clock(self):
        fractional = datetime.fromtimestamp(_NOW + 0.2, UTC)
        connection = _ScriptedConnection(
            {revocation_sql.REVOKE_IDENTITY_SQL: {"pubkey_hex": _OWNER, "revoked_at": fractional}}
        )
        assert (await _store_over(connection).revoke("sub-1")).revoked_at == _NOW + 1
        assert "clock_timestamp()" in revocation_sql.REVOKE_IDENTITY_SQL

    @pytest.mark.asyncio
    async def test_an_already_revoked_identity_keeps_its_first_revocation_time(self):
        connection = _ScriptedConnection(
            {revocation_sql.IDENTITY_SQL: {"pubkey_hex": _OWNER, "revoked_at": _REVOKED_AT}}
        )
        assert await _store_over(connection).revoke("sub-1") == StoredRevocation(_OWNER, _NOW - 100, False)

    @pytest.mark.asyncio
    async def test_an_unbound_subject_is_none(self):
        assert await _store_over(_ScriptedConnection({})).revoke("sub-1") is None

    @pytest.mark.asyncio
    async def test_reads_an_identity(self):
        connection = _ScriptedConnection({revocation_sql.IDENTITY_SQL: {"pubkey_hex": _OWNER, "revoked_at": None}})
        assert await _store_over(connection).identity("sub-1") == BoundIdentity(_OWNER, revoked=False)
        assert await _store_over(_ScriptedConnection({})).identity("sub-1") is None

    @pytest.mark.asyncio
    async def test_lists_recent_owner_and_agent_revocations(self):
        rows = [{"pubkey": _OWNER, "revoked_at": _REVOKED_AT}, {"pubkey": _AGENT, "revoked_at": _REVOKED_AT}]
        connection = _FetchConnection({revocation_sql.RECENT_REVOCATIONS_SQL: rows})
        assert await _store_over(connection).recent(_TTL) == [
            RecentRevocation(_OWNER, _NOW - 100), RecentRevocation(_AGENT, _NOW - 100),
        ]
        assert connection.statements == [(revocation_sql.RECENT_REVOCATIONS_SQL, (float(_TTL),))]
        assert "buzz_identities" in revocation_sql.RECENT_REVOCATIONS_SQL
        assert "buzz_agents" in revocation_sql.RECENT_REVOCATIONS_SQL

    @pytest.mark.asyncio
    @pytest.mark.parametrize("error", [asyncpg.PostgresError(), OSError(), IdentityStoreUnavailable()])
    async def test_failures_are_unavailable(self, error):
        store = _store_over(_FetchConnection({}, error=error))
        for operation in (store.revoke("sub-1"), store.identity("sub-1"), store.recent(_TTL)):
            with pytest.raises(RevocationStoreUnavailable):
                await operation


class _SubjectRedis:
    def __init__(self, failure=None):
        self.values: dict[str, tuple[str, int]] = {}
        self.failure = failure

    async def set(self, key, value, *, ex=None):
        if self.failure:
            raise self.failure
        self.values[key] = (value, ex)

    async def exists(self, key):
        if self.failure:
            raise self.failure
        return int(key in self.values)


class TestRevokedSubjects:
    @pytest.mark.asyncio
    async def test_marks_a_hashed_subject_for_the_session_lifetime(self):
        redis = _SubjectRedis()
        subjects = RevokedSubjects(lambda: redis, ttl_seconds=2_592_000)

        await subjects.mark("mpass-1")

        assert await subjects.is_revoked("mpass-1") is True
        assert await subjects.is_revoked("mpass-2") is False
        [(key, (_, ttl))] = redis.values.items()
        assert key == subject_mark_key("mpass-1") and "mpass-1" not in key
        assert ttl == 2_592_000

    @pytest.mark.asyncio
    async def test_redis_failure_is_unavailable(self):
        subjects = RevokedSubjects(lambda: _SubjectRedis(RedisConnectionError("down")), 60)
        with pytest.raises(SubjectMarksUnavailable):
            await subjects.mark("mpass-1")
        with pytest.raises(SubjectMarksUnavailable):
            await subjects.is_revoked("mpass-1")


class _Store:
    def __init__(self, stored=None, recent=(), failure=None):
        self.stored = stored
        self.recent_items = list(recent)
        self.failure = failure
        self.revoked: list[str] = []

    async def revoke(self, sub):
        self.revoked.append(sub)
        if self.failure:
            raise self.failure
        return self.stored

    async def identity(self, sub):
        if self.failure:
            raise self.failure
        return None if self.stored is None else BoundIdentity(self.stored.pubkey, True)

    async def recent(self, window_seconds):
        if self.failure:
            raise self.failure
        return self.recent_items


class _Disconnector:
    def __init__(self, failed=()):
        self.calls: list[tuple[str, int | None]] = []
        self.failed = tuple(failed)

    async def disconnect(self, target_pubkey, until=None):
        self.calls.append((target_pubkey, until))
        return DisconnectReport(failed_relays=self.failed)


def _revocation(store, disconnector=None, redis=None, now=_NOW):
    shared = redis or _SubjectRedis()
    subjects = RevokedSubjects(lambda: shared, 60)
    revocation = OwnerRevocation(
        store, subjects, disconnector or _Disconnector(), deny_seconds=_TTL, clock=lambda: float(now)
    )
    return revocation, subjects


class TestOwnerRevocation:
    @pytest.mark.asyncio
    async def test_revokes_marks_and_disconnects_only_the_owner_key(self):
        disconnector = _Disconnector()
        revocation, subjects = _revocation(_Store(StoredRevocation(_OWNER, _NOW, True)), disconnector)

        result = await revocation.revoke("mpass-1")

        assert (result.outcome, result.pubkey) == (RevocationOutcome.REVOKED, _OWNER)
        assert await subjects.is_revoked("mpass-1")
        assert disconnector.calls == [(_OWNER, _NOW + _TTL)]

    @pytest.mark.asyncio
    async def test_the_deny_never_ends_before_the_service_clock_plus_ttl(self):
        disconnector = _Disconnector()
        revocation, _ = _revocation(_Store(StoredRevocation(_OWNER, _NOW - 1000, False)), disconnector)
        assert (await revocation.revoke("mpass-1")).outcome is RevocationOutcome.REVOKED
        assert disconnector.calls == [(_OWNER, _NOW + _TTL)]

    @pytest.mark.asyncio
    async def test_a_revocation_stored_ahead_of_the_service_clock_anchors_the_deny(self):
        disconnector = _Disconnector()
        revocation, _ = _revocation(_Store(StoredRevocation(_OWNER, _NOW + 1, True)), disconnector)
        await revocation.revoke("mpass-1")
        assert disconnector.calls == [(_OWNER, _NOW + 1 + _TTL)]

    @pytest.mark.asyncio
    async def test_the_tombstone_is_set_before_the_database_is_asked(self):
        redis = _SubjectRedis()
        revocation, subjects = _revocation(_Store(failure=RevocationStoreUnavailable()), redis=redis)
        assert (await revocation.revoke("mpass-1")).outcome is RevocationOutcome.UNAVAILABLE
        assert await subjects.is_revoked("mpass-1")

    @pytest.mark.asyncio
    async def test_an_unbound_user_still_has_sessions_ended(self):
        disconnector = _Disconnector()
        revocation, subjects = _revocation(_Store(None), disconnector)
        assert (await revocation.revoke("mpass-1")).outcome is RevocationOutcome.NOT_BOUND
        assert await subjects.is_revoked("mpass-1")
        assert disconnector.calls == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("store, redis", [
        (_Store(failure=RevocationStoreUnavailable()), None),
        (_Store(StoredRevocation(_OWNER, _NOW, True)), _SubjectRedis(RedisConnectionError("down"))),
    ])
    async def test_store_or_marks_unavailable(self, store, redis):
        disconnector = _Disconnector()
        revocation, _ = _revocation(store, disconnector, redis)
        assert (await revocation.revoke("mpass-1")).outcome is RevocationOutcome.UNAVAILABLE
        assert disconnector.calls == []

    @pytest.mark.asyncio
    async def test_incomplete_disconnect(self):
        disconnector = _Disconnector(failed=("wss://a.example.com",))
        revocation, _ = _revocation(_Store(StoredRevocation(_OWNER, _NOW, True)), disconnector)
        assert (await revocation.revoke("mpass-1")).outcome is RevocationOutcome.DISCONNECT_INCOMPLETE


class TestDenyRepusher:
    @pytest.mark.asyncio
    async def test_re_pushes_live_denies_with_their_original_until(self):
        disconnector = _Disconnector()
        recent = [
            RecentRevocation(_OWNER, _NOW - 100),
            RecentRevocation(_AGENT, _NOW - 299),
            RecentRevocation("cc" * 32, _NOW - 300),
        ]
        repusher = DenyRepusher(_Store(recent=recent), disconnector, _TTL, clock=lambda: float(_NOW))

        assert await repusher.push_once() == 2

        assert disconnector.calls == [(_OWNER, _NOW + 200), (_AGENT, _NOW + 1)]

    @pytest.mark.asyncio
    async def test_keys_are_pushed_concurrently(self):
        in_flight, peak = 0, 0
        release = asyncio.Event()

        class _Slow(_Disconnector):
            async def disconnect(self, target_pubkey, until=None):
                nonlocal in_flight, peak
                in_flight += 1
                peak = max(peak, in_flight)
                if peak >= revocation_sql.DENY_REPUSH_CONCURRENCY:
                    release.set()
                await release.wait()
                in_flight -= 1
                return await super().disconnect(target_pubkey, until)

        recent = [RecentRevocation(f"{index:064x}", _NOW) for index in range(20)]
        repusher = DenyRepusher(_Store(recent=recent), _Slow(), _TTL, clock=lambda: float(_NOW))

        assert await asyncio.wait_for(repusher.push_once(), timeout=5) == 20
        assert peak == revocation_sql.DENY_REPUSH_CONCURRENCY

    @pytest.mark.asyncio
    async def test_store_outage_skips_the_tick(self):
        repusher = DenyRepusher(
            _Store(failure=RevocationStoreUnavailable()), _Disconnector(), _TTL, clock=lambda: float(_NOW)
        )
        assert await repusher.push_once() == 0

    @pytest.mark.asyncio
    async def test_a_failing_tick_does_not_end_the_loop(self, monkeypatch, caplog):
        ticks = []

        class _Exploding(_Store):
            async def recent(self, window_seconds):
                ticks.append(window_seconds)
                raise RuntimeError("boom")

        async def fake_sleep(seconds):
            if len(ticks) >= 2:
                raise asyncio.CancelledError()

        monkeypatch.setattr(revocation_sql.asyncio, "sleep", fake_sleep)
        repusher = DenyRepusher(_Exploding(), _Disconnector(), _TTL, clock=lambda: float(_NOW))
        with caplog.at_level(logging.ERROR), pytest.raises(asyncio.CancelledError):
            await repusher.run_forever()
        assert len(ticks) == 2
        assert any("deny re-push failed: RuntimeError" in record.getMessage() for record in caplog.records)


class TestDisconnectUntil:
    @pytest.mark.asyncio
    async def test_an_explicit_until_is_sent_as_is(self):
        requests: list[httpx.Request] = []

        def client():
            return httpx.AsyncClient(transport=httpx.MockTransport(_accepting(requests)))

        disconnector = RelayDisconnector(_RELAYS, _ISSUER, 300, lambda: float(_NOW), client)
        await disconnector.disconnect(_OWNER, until=_NOW + 17)

        assert {_command(request)[1]["until"] for request in requests} == {_NOW + 17}


class _FakeAdminStore:
    def __init__(self):
        self.identities: dict[str, dict] = {}
        self.failure: Exception | None = None

    async def revoke(self, sub):
        if self.failure:
            raise self.failure
        row = self.identities.get(sub)
        if row is None:
            return None
        newly = row["revoked_at"] is None
        if newly:
            row["revoked_at"] = _T0
        return StoredRevocation(row["pubkey"], row["revoked_at"], newly)

    async def identity(self, sub):
        if self.failure:
            raise self.failure
        row = self.identities.get(sub)
        return None if row is None else BoundIdentity(row["pubkey"], row["revoked_at"] is not None)

    async def recent(self, window_seconds):
        return []


@pytest.fixture()
def redis_store(monkeypatch):
    store = _AgentRedis()
    monkeypatch.setattr(m, "redis_client", store)
    return store


@pytest.fixture()
def admin(monkeypatch):
    store = _FakeAdminStore()
    disconnector = _Disconnector()
    revocation = m._buzz_adapter.admin.revocation
    monkeypatch.setattr(revocation, "store", store)
    monkeypatch.setattr(revocation, "disconnector", disconnector)
    return store, disconnector


def _bearer(token=None):
    return {"Authorization": f"Bearer {token or _admin_token()}"}


def _revoke(mpass_id=_MPASS_ID, headers=None, body=None):
    content = body if body is not None else json.dumps({"mpass_id": mpass_id}).encode()
    return client.post(
        _REVOKE_ROUTE, content=content, headers={"Content-Type": "application/json", **(headers or _bearer())}
    )


def _session_status(token) -> tuple[int, dict]:
    response = client.get("/nip-fa/v1/session", headers={"Authorization": f"Bearer {token}"})
    return response.status_code, response.json()


class TestRevokeRoute:
    def test_revokes_ends_sessions_and_disconnects_the_owner(self, redis_store, clock, admin):
        store, disconnector = admin
        store.identities[_MPASS_ID] = {"pubkey": _OWNER, "revoked_at": None}
        session_token = _signed_in(redis_store, clock)

        response = _revoke()

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {"revoked": True, "nostr_pubkey": _OWNER}
        assert disconnector.calls == [(_OWNER, _T0 + m._BUZZ_ADAPTER_CONFIG.assertion_ttl_seconds)]
        assert _session_status(session_token) == (401, {"error": "session_expired"})

    def test_a_pending_login_code_is_refused(self, redis_store, clock, admin):
        code = _login_code()
        _revoke()
        assert _exchange(code).status_code == 400

    def test_is_idempotent(self, redis_store, clock, admin):
        store, disconnector = admin
        store.identities[_MPASS_ID] = {"pubkey": _OWNER, "revoked_at": None}
        assert _revoke().json() == {"revoked": True, "nostr_pubkey": _OWNER}
        assert _revoke().json() == {"revoked": True, "nostr_pubkey": _OWNER}
        assert [call[0] for call in disconnector.calls] == [_OWNER, _OWNER]

    def test_an_unbound_user_gets_their_sessions_ended(self, redis_store, clock, admin):
        session_token = _signed_in(redis_store, clock)
        assert _revoke().json() == {"revoked": False}
        assert _session_status(session_token) == (401, {"error": "session_expired"})
        assert admin[1].calls == []

    def test_other_users_are_untouched(self, redis_store, clock, admin):
        session_token = _signed_in(redis_store, clock)
        _revoke(mpass_id="someone-else")
        assert _session_status(session_token)[0] == 200

    def test_incomplete_disconnect_is_retryable(self, redis_store, clock, admin):
        store, disconnector = admin
        store.identities[_MPASS_ID] = {"pubkey": _OWNER, "revoked_at": None}
        disconnector.failed = ("wss://relay.local.test",)
        assert (_revoke().status_code, _revoke().json()) == (503, {"error": "unavailable"})

    def test_store_outage_is_retryable(self, redis_store, clock, admin):
        admin[0].failure = RevocationStoreUnavailable()
        assert _revoke().status_code == 503

    @pytest.mark.parametrize("headers", [
        {},
        {"Authorization": "Bearer wrong-token"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer"},
    ])
    def test_needs_the_admin_token(self, redis_store, clock, admin, headers):
        response = _revoke(headers=headers or {"X-Nothing": "1"})
        assert (response.status_code, response.json()) == (401, {"error": "unauthorized"})
        assert admin[1].calls == []

    def test_a_session_token_is_not_the_admin_token(self, redis_store, clock, admin):
        session_token = _signed_in(redis_store, clock)
        assert _revoke(headers=_bearer(session_token)).status_code == 401

    @pytest.mark.parametrize("body", [
        b"",
        b"{}",
        b'{"mpass_id": 1}',
        b'{"mpass_id": ""}',
        b'{"mpass_id": " padded "}',
        b'{"mpass_id": "a", "email": "x@y"}',
        b'{"mpass_id": "a", "mpass_id": "b"}',
        b'["a"]',
    ])
    def test_body_rules(self, redis_store, clock, admin, body):
        assert _revoke(body=body).status_code == 400

    def test_body_limit(self, redis_store, clock, admin):
        assert _revoke(body=b"x" * 4097).status_code == 413

    def test_logs_no_token(self, redis_store, clock, admin, caplog):
        with caplog.at_level(logging.DEBUG):
            _revoke()
            _revoke(headers={"Authorization": "Bearer guessed-token"})
        for record in caplog.records:
            assert _admin_token() not in record.getMessage()
            assert "guessed-token" not in record.getMessage()


class TestKeyBindRacingARevocation:
    def test_a_key_bound_after_the_tombstone_is_not_issued(self, redis_store, clock, admin):
        session_token = _signed_in(redis_store, clock)
        keys = m._buzz_adapter.identity_keys
        real_store = keys._store

        class _BindsDuringRevoke:
            async def ensure_identity(self, sub, pubkey_hex, email):
                redis_store.values[revocation_sql.subject_mark_key(sub)] = "1"
                return StoredIdentity(pubkey_hex=pubkey_hex, revoked=False)

        keys._store = _BindsDuringRevoke()
        try:
            response = client.get("/nip-fa/v1/identity/key", headers={"Authorization": f"Bearer {session_token}"})
        finally:
            keys._store = real_store
        assert (response.status_code, response.json()) == (403, {"error": "authorization_denied"})
        assert "secret_key" not in response.text


class TestPubkeyRoute:
    def _get(self, params, headers=None):
        return client.get(_PUBKEY_ROUTE, params=params, headers=headers or _bearer())

    def test_returns_the_stored_key(self, redis_store, admin):
        admin[0].identities[_MPASS_ID] = {"pubkey": _OWNER, "revoked_at": None}
        response = self._get({"mpass_id": _MPASS_ID})
        assert (response.status_code, response.json()) == (200, {"nostr_pubkey": _OWNER, "revoked": False})

    def test_an_unbound_user_is_not_found_and_nothing_is_derived(self, redis_store, admin, identity_store):
        response = self._get({"mpass_id": _MPASS_ID})
        assert (response.status_code, response.json()) == (404, {"error": "identity_not_found"})
        assert identity_store.calls == []

    @pytest.mark.parametrize("params", [
        {},
        {"mpass_id": ""},
        {"mpass_id": "a", "email": "b"},
        [("mpass_id", "a"), ("mpass_id", "b")],
    ])
    def test_query_rules(self, redis_store, admin, params):
        assert self._get(params).status_code == 400

    def test_needs_the_admin_token(self, redis_store, admin):
        assert self._get({"mpass_id": _MPASS_ID}, headers={"Authorization": "Bearer nope"}).status_code == 401

    def test_store_outage(self, redis_store, admin):
        admin[0].failure = RevocationStoreUnavailable()
        assert self._get({"mpass_id": _MPASS_ID}).status_code == 503


class TestInternalRoutesStayOffTheNipFaPrefix:
    def test_no_internal_route_is_under_nip_fa(self):
        paths = {route.path for route in m.app.routes}
        assert {_REVOKE_ROUTE, _PUBKEY_ROUTE} <= paths
        assert not any(path.startswith("/nip-fa/") and "revoke" in path and "agent" not in path for path in paths)
        assert not _REVOKE_ROUTE.startswith("/nip-fa/")


class TestBackgroundRepush:
    def test_starts_with_the_app_and_stops_with_it(self, redis_store, monkeypatch):
        started = []

        async def fake_run_forever():
            started.append(True)
            await asyncio.Event().wait()

        monkeypatch.setattr(m._buzz_adapter.repusher, "run_forever", fake_run_forever)
        from fastapi.testclient import TestClient

        with TestClient(m.app):
            assert m._buzz_adapter._background is not None
        assert started == [True]
        assert m._buzz_adapter._background is None
