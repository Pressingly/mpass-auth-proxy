"""Agent enrollments in launchpad's `buzz_agents` table (schema owned by
launchpad-api): enroll an agent key under its owner, look a grant up by its
hash, and revoke. The table keeps an agent with its first owner for good and
makes revocation final; this module never relies on that alone and refuses
both cases itself."""

import enum
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import asyncpg

from .identities import DATABASE_ERRORS, IdentityStoreUnavailable

logger = logging.getLogger(__name__)

LOCK_OWNER_SQL = "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1 FOR NO KEY UPDATE"
IS_IDENTITY_KEY_SQL = "SELECT EXISTS (SELECT 1 FROM buzz_identities WHERE pubkey_hex = $1)"
EXISTING_AGENT_SQL = "SELECT owner_sub, revoked_at FROM buzz_agents WHERE agent_pubkey = $1"
OTHER_ACTIVE_AGENTS_SQL = (
    "SELECT count(*) FROM buzz_agents WHERE owner_sub = $1 AND revoked_at IS NULL AND agent_pubkey <> $2"
)
ENROLL_SQL = (
    "INSERT INTO buzz_agents (agent_pubkey, owner_sub, grant_hash, grant_expires_at) "
    "VALUES ($1, $2, $3, $4) "
    "ON CONFLICT (agent_pubkey) DO UPDATE "
    "SET grant_hash = EXCLUDED.grant_hash, grant_expires_at = EXCLUDED.grant_expires_at "
    "WHERE buzz_agents.owner_sub = EXCLUDED.owner_sub AND buzz_agents.revoked_at IS NULL "
    "RETURNING agent_pubkey"
)
GRANT_SQL = (
    "SELECT a.agent_pubkey, a.owner_sub, a.grant_expires_at, a.revoked_at, "
    "i.pubkey_hex AS owner_pubkey, i.revoked_at AS owner_revoked_at "
    "FROM buzz_agents a JOIN buzz_identities i ON i.sub = a.owner_sub "
    "WHERE a.grant_hash = $1"
)
REVOKE_SQL = (
    "UPDATE buzz_agents SET revoked_at = now(), grant_hash = NULL, grant_expires_at = NULL "
    "WHERE agent_pubkey = $1 AND owner_sub = $2 AND revoked_at IS NULL "
    "RETURNING agent_pubkey"
)
OWNED_AGENT_SQL = "SELECT revoked_at FROM buzz_agents WHERE agent_pubkey = $1 AND owner_sub = $2"


class AgentStoreUnavailable(Exception):
    """The agent store could not be asked."""


class EnrollmentRaced(AgentStoreUnavailable):
    """The agent was enrolled between the revoke and its read-back; the
    caller retries rather than report a live agent as revoked."""


class Enrollment(enum.Enum):
    ENROLLED = "enrolled"
    OWNER_REFUSED = "owner_refused"
    AGENT_REFUSED = "agent_refused"
    CAP_REACHED = "cap_reached"


class Revocation(enum.Enum):
    REVOKED = "revoked"
    ALREADY_REVOKED = "already_revoked"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class EnrollmentRequest:
    owner_sub: str
    owner_pubkey: str
    agent_pubkey: str
    grant_hash: str
    expires_at: int
    max_agents: int

    def __repr__(self) -> str:
        return f"EnrollmentRequest(owner_sub={self.owner_sub!r}, agent_pubkey={self.agent_pubkey!r})"


@dataclass(frozen=True)
class StoredGrant:
    agent_pubkey: str
    owner_sub: str
    owner_pubkey: str
    expires_at: int | None
    revoked: bool
    owner_revoked: bool

    def usable_at(self, now: int) -> bool:
        """NIP-FA: issue only while the grant and its owner's authorization
        are valid. An owner revocation ends every grant they authorized."""
        return (
            not self.revoked
            and not self.owner_revoked
            and self.expires_at is not None
            and now < self.expires_at
        )


class AgentStore(Protocol):
    async def enroll(self, request: EnrollmentRequest) -> Enrollment:
        """Raises AgentStoreUnavailable."""

    async def grant(self, grant_hash: str) -> StoredGrant | None:
        """Raises AgentStoreUnavailable."""

    async def revoke(self, owner_sub: str, agent_pubkey: str) -> Revocation:
        """Raises AgentStoreUnavailable."""


def _epoch(moment: datetime | None) -> int | None:
    return None if moment is None else int(moment.timestamp())


def _stored_grant(row) -> StoredGrant:
    return StoredGrant(
        agent_pubkey=row["agent_pubkey"],
        owner_sub=row["owner_sub"],
        owner_pubkey=row["owner_pubkey"],
        expires_at=_epoch(row["grant_expires_at"]),
        revoked=row["revoked_at"] is not None,
        owner_revoked=row["owner_revoked_at"] is not None,
    )


def owner_refusal(owner_row, owner_pubkey: str) -> bool:
    return owner_row is None or owner_row["revoked_at"] is not None or owner_row["pubkey_hex"] != owner_pubkey


def agent_refusal(existing_row, owner_sub: str) -> bool:
    """An agent key enrolled under another owner, or revoked, never enrolls again."""
    return existing_row is not None and (
        existing_row["owner_sub"] != owner_sub or existing_row["revoked_at"] is not None
    )


async def _enroll_locked(conn, request: EnrollmentRequest) -> Enrollment:
    owner = await conn.fetchrow(LOCK_OWNER_SQL, request.owner_sub)
    if owner_refusal(owner, request.owner_pubkey):
        return Enrollment.OWNER_REFUSED
    if await conn.fetchval(IS_IDENTITY_KEY_SQL, request.agent_pubkey):
        return Enrollment.AGENT_REFUSED
    if agent_refusal(await conn.fetchrow(EXISTING_AGENT_SQL, request.agent_pubkey), request.owner_sub):
        return Enrollment.AGENT_REFUSED
    if await conn.fetchval(OTHER_ACTIVE_AGENTS_SQL, request.owner_sub, request.agent_pubkey) >= request.max_agents:
        return Enrollment.CAP_REACHED
    expires_at = datetime.fromtimestamp(request.expires_at, UTC)
    enrolled = await conn.fetchval(
        ENROLL_SQL, request.agent_pubkey, request.owner_sub, request.grant_hash, expires_at
    )
    return Enrollment.ENROLLED if enrolled else Enrollment.AGENT_REFUSED


class LaunchpadAgentStore:
    """Enrollment runs in one transaction holding the owner's
    `buzz_identities` row, so an owner's enrollments are counted one at a
    time and none can commit after a concurrent revocation of the owner."""

    def __init__(self, pool_factory: Callable[[], Awaitable[asyncpg.Pool]]):
        self._pool_factory = pool_factory

    async def _run(self, operation):
        try:
            pool = await self._pool_factory()
            async with pool.acquire() as conn:
                return await operation(conn)
        except (*DATABASE_ERRORS, IdentityStoreUnavailable) as exc:
            logger.error("nip-fa: agent store unavailable: %s", type(exc).__name__)
            raise AgentStoreUnavailable() from exc

    async def enroll(self, request: EnrollmentRequest) -> Enrollment:
        async def operation(conn):
            async with conn.transaction():
                return await _enroll_locked(conn, request)

        return await self._run(operation)

    async def grant(self, grant_hash: str) -> StoredGrant | None:
        row = await self._run(lambda conn: conn.fetchrow(GRANT_SQL, grant_hash))
        return None if row is None else _stored_grant(row)

    async def revoke(self, owner_sub: str, agent_pubkey: str) -> Revocation:
        async def operation(conn):
            if await conn.fetchval(REVOKE_SQL, agent_pubkey, owner_sub):
                return Revocation.REVOKED
            owned = await conn.fetchrow(OWNED_AGENT_SQL, agent_pubkey, owner_sub)
            if owned is None:
                return Revocation.NOT_FOUND
            if owned["revoked_at"] is None:
                logger.warning("nip-fa: agent revoke raced an enrollment mpass_id=%s agent=%s", owner_sub, agent_pubkey)
                raise EnrollmentRaced()
            return Revocation.ALREADY_REVOKED

        return await self._run(operation)
