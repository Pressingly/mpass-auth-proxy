"""Binding each mPass ID to its custodial Nostr key, and issuing that key.

The binding lives in launchpad's `buzz_identities` table (schema owned by
launchpad-api). The first issuance records the derived public key; every later
one must derive the same key, so a rotated master secret or salt refuses
issuance instead of silently handing a person a new identity."""

import enum
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

import asyncpg

from .identity_keys import NostrKeypair, derive_keypair
from .sessions import Identity

logger = logging.getLogger(__name__)

_BIND_SQL = (
    "INSERT INTO buzz_identities (sub, pubkey_hex, email) VALUES ($1, $2, $3) "
    "ON CONFLICT (sub) DO NOTHING"
)
_READ_SQL = "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1"
DATABASE_ERRORS = (
    asyncpg.PostgresError,
    asyncpg.InterfaceError,
    asyncpg.InternalClientError,
    OSError,
    TimeoutError,
)


class IdentityStoreUnavailable(Exception):
    """The identity store could not be asked."""


@dataclass(frozen=True)
class StoredIdentity:
    pubkey_hex: str
    revoked: bool


class IdentityStore(Protocol):
    async def ensure_identity(self, sub: str, pubkey_hex: str, email: str | None) -> StoredIdentity | None:
        """The binding stored for `sub` after binding `pubkey_hex` to it if it
        had none, or None when that key is already bound to someone else.
        Raises IdentityStoreUnavailable."""


class LaunchpadIdentityStore:
    def __init__(self, pool_factory: Callable[[], Awaitable[asyncpg.Pool]]):
        self._pool_factory = pool_factory

    async def ensure_identity(self, sub: str, pubkey_hex: str, email: str | None) -> StoredIdentity | None:
        try:
            pool = await self._pool_factory()
            async with pool.acquire() as conn:
                await _bind(conn, sub, pubkey_hex, email)
                row = await conn.fetchrow(_READ_SQL, sub)
        except DATABASE_ERRORS as exc:
            logger.error("nip-fa: identity store unavailable: %s", type(exc).__name__)
            raise IdentityStoreUnavailable() from exc
        if row is None:
            return None
        return StoredIdentity(pubkey_hex=row["pubkey_hex"], revoked=row["revoked_at"] is not None)


async def _bind(conn, sub: str, pubkey_hex: str, email: str | None) -> None:
    """Binds the key unless `sub` already has one. A key already bound to
    someone else is left for the read-back to report as no binding."""
    try:
        await conn.execute(_BIND_SQL, sub, pubkey_hex, email)
    except asyncpg.UniqueViolationError:
        pass


class KeyIssuanceStatus(enum.Enum):
    ISSUED = "issued"
    REVOKED = "revoked"
    BINDING_MISMATCH = "binding_mismatch"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class KeyIssuance:
    status: KeyIssuanceStatus
    keypair: NostrKeypair | None = None


def issuance_status(derived_pubkey_hex: str, stored: StoredIdentity | None) -> KeyIssuanceStatus:
    if stored is None or stored.pubkey_hex != derived_pubkey_hex:
        return KeyIssuanceStatus.BINDING_MISMATCH
    if stored.revoked:
        return KeyIssuanceStatus.REVOKED
    return KeyIssuanceStatus.ISSUED


class IdentityKeyService:
    """`subject_revoked`, when given, is re-checked after a bind: an owner
    revocation that found no key to revoke has already ended the user's
    sessions, so a bind racing it must not hand that user a key."""

    def __init__(
        self,
        master_secret: bytes,
        salt: bytes,
        store: IdentityStore,
        subject_revoked: Callable[[str], Awaitable[bool]] | None = None,
    ):
        self._master_secret = master_secret
        self._salt = salt
        self._store = store
        self._subject_revoked = subject_revoked

    def __repr__(self) -> str:
        return "IdentityKeyService(<redacted>)"

    async def bind(self, identity: Identity) -> KeyIssuance:
        """The user's bound custodial keypair, binding it on first use. Logs
        refusals; the caller logs what it does with an issued keypair."""
        keypair = derive_keypair(self._master_secret, self._salt, identity.sub)
        try:
            stored = await self._store.ensure_identity(identity.sub, keypair.pubkey_hex, identity.email)
        except IdentityStoreUnavailable:
            logger.warning("nip-fa: identity key unavailable for mpass_id=%s", identity.sub)
            return KeyIssuance(KeyIssuanceStatus.UNAVAILABLE)
        status = issuance_status(keypair.pubkey_hex, stored)
        if status is not KeyIssuanceStatus.ISSUED:
            _log_refusal(identity.sub, status, stored)
            return KeyIssuance(status)
        return await self._unless_subject_revoked(identity.sub, KeyIssuance(status, keypair))

    async def _unless_subject_revoked(self, sub: str, issuance: KeyIssuance) -> KeyIssuance:
        if self._subject_revoked is None:
            return issuance
        try:
            revoked = await self._subject_revoked(sub)
        except Exception as exc:  # noqa: BLE001  any tombstone read failure fails closed
            logger.warning("nip-fa: identity key unavailable for mpass_id=%s error=%s", sub, type(exc).__name__)
            return KeyIssuance(KeyIssuanceStatus.UNAVAILABLE)
        if revoked:
            logger.warning("nip-fa: identity key refused mpass_id=%s reason=subject_revoked", sub)
            return KeyIssuance(KeyIssuanceStatus.REVOKED)
        return issuance

    async def issue(self, identity: Identity) -> KeyIssuance:
        issuance = await self.bind(identity)
        if issuance.status is KeyIssuanceStatus.ISSUED:
            logger.info(
                "nip-fa: identity key issued mpass_id=%s pubkey=%s", identity.sub, issuance.keypair.pubkey_hex
            )
        return issuance


def _log_refusal(mpass_id: str, status: KeyIssuanceStatus, stored: StoredIdentity | None) -> None:
    if status is KeyIssuanceStatus.REVOKED:
        logger.warning("nip-fa: identity key refused mpass_id=%s reason=revoked", mpass_id)
    elif stored is None:
        logger.error(
            "nip-fa: identity key refused mpass_id=%s reason=pubkey_bound_to_other_sub; the derived "
            "key is already bound to another mPass ID in buzz_identities",
            mpass_id,
        )
    else:
        logger.error(
            "nip-fa: identity key refused mpass_id=%s reason=binding_mismatch; the stored key "
            "differs from the derived one (BUZZ_IDENTITY_MASTER_SECRET or BUZZ_IDENTITY_SALT changed?)",
            mpass_id,
        )
