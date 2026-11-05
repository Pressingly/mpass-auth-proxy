"""Owner revocation: the durable mark in launchpad's `buzz_identities`, the
Redis tombstone that ends a revoked user's adapter sessions and login codes,
and the periodic re-push of relay denies a relay restart forgets.

The relay denies an agent assertion when the issuer has denied either the
agent key or its owner (NIP-FI "Agent keys", relay `assertion_denied`), and
its disconnect closes sessions whose recorded owner is the target. So one
disconnect of the owner key covers the owner's agents; their grants also stop
at once, because a grant is usable only while its owner is not revoked."""

import asyncio
import enum
import hashlib
import logging
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

import asyncpg
from redis.exceptions import RedisError

from .identities import DATABASE_ERRORS, IdentityStoreUnavailable
from .relay_commands import RelayDisconnector

logger = logging.getLogger(__name__)

REVOKE_IDENTITY_SQL = (
    "UPDATE buzz_identities SET revoked_at = clock_timestamp() WHERE sub = $1 AND revoked_at IS NULL "
    "RETURNING pubkey_hex, revoked_at"
)
IDENTITY_SQL = "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1"
RECENT_REVOCATIONS_SQL = (
    "SELECT pubkey_hex AS pubkey, revoked_at FROM buzz_identities "
    "WHERE revoked_at > now() - make_interval(secs => $1) "
    "UNION ALL "
    "SELECT agent_pubkey AS pubkey, revoked_at FROM buzz_agents "
    "WHERE revoked_at > now() - make_interval(secs => $1)"
)
DENY_REPUSH_INTERVAL_SECONDS = 30
DENY_REPUSH_CONCURRENCY = 8


class RevocationStoreUnavailable(Exception):
    """The revocation store could not be asked."""


class SubjectMarksUnavailable(Exception):
    """The revoked-subject tombstone could not be read or written."""


@dataclass(frozen=True)
class StoredRevocation:
    pubkey: str
    revoked_at: int
    newly_revoked: bool


@dataclass(frozen=True)
class BoundIdentity:
    pubkey: str
    revoked: bool


@dataclass(frozen=True)
class RecentRevocation:
    pubkey: str
    revoked_at: int


class RevocationStore(Protocol):
    async def revoke(self, sub: str) -> StoredRevocation | None:
        """None when `sub` has no bound key. Raises RevocationStoreUnavailable."""

    async def identity(self, sub: str) -> BoundIdentity | None:
        """Raises RevocationStoreUnavailable."""

    async def recent(self, window_seconds: int) -> list[RecentRevocation]:
        """Owner and agent keys revoked within the window. Raises RevocationStoreUnavailable."""


def _epoch(row) -> int:
    """Rounded up, so a deny anchored on it never ends before an assertion
    issued in the same second the revocation was written."""
    return math.ceil(row["revoked_at"].timestamp())


class LaunchpadRevocationStore:
    def __init__(self, pool_factory: Callable[[], Awaitable[asyncpg.Pool]]):
        self._pool_factory = pool_factory

    async def _run(self, operation):
        try:
            pool = await self._pool_factory()
            async with pool.acquire() as conn:
                return await operation(conn)
        except (*DATABASE_ERRORS, IdentityStoreUnavailable) as exc:
            logger.error("nip-fa: revocation store unavailable: %s", type(exc).__name__)
            raise RevocationStoreUnavailable() from exc

    async def revoke(self, sub: str) -> StoredRevocation | None:
        async def operation(conn):
            revoked = await conn.fetchrow(REVOKE_IDENTITY_SQL, sub)
            if revoked is not None:
                return StoredRevocation(revoked["pubkey_hex"], _epoch(revoked), newly_revoked=True)
            existing = await conn.fetchrow(IDENTITY_SQL, sub)
            if existing is None:
                return None
            return StoredRevocation(existing["pubkey_hex"], _epoch(existing), newly_revoked=False)

        return await self._run(operation)

    async def identity(self, sub: str) -> BoundIdentity | None:
        row = await self._run(lambda conn: conn.fetchrow(IDENTITY_SQL, sub))
        return None if row is None else BoundIdentity(row["pubkey_hex"], revoked=row["revoked_at"] is not None)

    async def recent(self, window_seconds: int) -> list[RecentRevocation]:
        rows = await self._run(lambda conn: conn.fetch(RECENT_REVOCATIONS_SQL, float(window_seconds)))
        return [RecentRevocation(row["pubkey"], _epoch(row)) for row in rows]


def subject_mark_key(sub: str) -> str:
    return RevokedSubjects.KEY_PREFIX + hashlib.sha256(sub.encode("utf-8")).hexdigest()


class RevokedSubjects:
    """A tombstone per revoked mPass ID, kept as long as an adapter session can
    live, so every session and login code minted before the revocation is
    refused without an index of them. The database stays the authority: a
    lost tombstone still leaves key, assertion and grant issuance refused."""

    KEY_PREFIX = "nip_fa_revoked_sub:"

    def __init__(self, redis_factory, ttl_seconds: int):
        self._redis_factory = redis_factory
        self._ttl_seconds = ttl_seconds

    async def mark(self, sub: str) -> None:
        try:
            await self._redis_factory().set(subject_mark_key(sub), "1", ex=self._ttl_seconds)
        except (RedisError, OSError) as exc:
            raise SubjectMarksUnavailable() from exc

    async def is_revoked(self, sub: str) -> bool:
        try:
            return bool(await self._redis_factory().exists(subject_mark_key(sub)))
        except (RedisError, OSError) as exc:
            raise SubjectMarksUnavailable() from exc


class RevocationOutcome(enum.Enum):
    REVOKED = "revoked"
    NOT_BOUND = "not_bound"
    UNAVAILABLE = "unavailable"
    DISCONNECT_INCOMPLETE = "disconnect_incomplete"


@dataclass(frozen=True)
class RevocationResult:
    outcome: RevocationOutcome
    pubkey: str | None = None


def deny_until(revoked_at: int, deny_seconds: int) -> int:
    return revoked_at + deny_seconds


class OwnerRevocation:
    """Revokes an mPass ID: the session tombstone first, so a key bind racing
    the revocation re-checks it and fails closed; then the database (durable
    and authoritative); then a disconnect of the owner key on every relay.
    Each step is idempotent, so a caller retries the whole call on any
    incomplete outcome.

    The deny lasts until the later of the stored revocation time and this
    service's clock after the commit, plus the assertion TTL: every assertion
    issued from a read that still saw the user as active read its clock before
    that commit, so it expires by then."""

    def __init__(
        self,
        store: RevocationStore,
        subjects: RevokedSubjects,
        disconnector: RelayDisconnector,
        deny_seconds: int,
        clock,
    ):
        self.store = store
        self.subjects = subjects
        self.disconnector = disconnector
        self._deny_seconds = deny_seconds
        self._clock = clock

    async def revoke(self, sub: str) -> RevocationResult:
        try:
            await self.subjects.mark(sub)
            stored = await self.store.revoke(sub)
        except (RevocationStoreUnavailable, SubjectMarksUnavailable) as exc:
            logger.error("nip-fa: owner revoke unavailable mpass_id=%s error=%s", sub, type(exc).__name__)
            return RevocationResult(RevocationOutcome.UNAVAILABLE)
        if stored is None:
            logger.warning("nip-fa: owner revoked mpass_id=%s outcome=not_bound; sessions ended", sub)
            return RevocationResult(RevocationOutcome.NOT_BOUND)
        anchor = max(stored.revoked_at, int(self._clock()))
        report = await self.disconnector.disconnect(stored.pubkey, deny_until(anchor, self._deny_seconds))
        logger.warning(
            "nip-fa: owner revoked mpass_id=%s pubkey=%s newly=%s disconnect_complete=%s",
            sub, stored.pubkey, stored.newly_revoked, report.complete,
        )
        if not report.complete:
            return RevocationResult(RevocationOutcome.DISCONNECT_INCOMPLETE, stored.pubkey)
        return RevocationResult(RevocationOutcome.REVOKED, stored.pubkey)


class DenyRepusher:
    """Re-sends the relay deny for every owner or agent key revoked within the
    last deny window, every DENY_REPUSH_INTERVAL_SECONDS. A relay keeps its
    deny set in memory only and exposes no restart signal, so a periodic
    re-push bounds the window a restarted relay could readmit a revoked key
    with a still-valid assertion to one interval plus one tick. A re-push is
    anchored on the stored revocation time, which can end a little before the
    deny the revoking call sent; the relay keeps the later of the two while it
    holds both, and the re-push only matters once a restart dropped them."""

    def __init__(
        self,
        store: RevocationStore,
        disconnector: RelayDisconnector,
        deny_seconds: int,
        clock,
        interval_seconds: int = DENY_REPUSH_INTERVAL_SECONDS,
    ):
        self._store = store
        self._disconnector = disconnector
        self._deny_seconds = deny_seconds
        self._clock = clock
        self._interval_seconds = interval_seconds

    async def push_once(self) -> int:
        """The number of keys re-pushed."""
        try:
            revocations = await self._store.recent(self._deny_seconds)
        except RevocationStoreUnavailable:
            return 0
        now = int(self._clock())
        live = [item for item in revocations if deny_until(item.revoked_at, self._deny_seconds) > now]
        slots = asyncio.Semaphore(DENY_REPUSH_CONCURRENCY)

        async def push(item: RecentRevocation) -> None:
            async with slots:
                await self._disconnector.disconnect(item.pubkey, deny_until(item.revoked_at, self._deny_seconds))

        await asyncio.gather(*(push(item) for item in live))
        return len(live)

    async def run_forever(self) -> None:
        while True:
            try:
                await self.push_once()
            except Exception as exc:  # noqa: BLE001  a failed tick must not end the loop
                logger.error("nip-fa: deny re-push failed: %s", type(exc).__name__)
            await asyncio.sleep(self._interval_seconds)
