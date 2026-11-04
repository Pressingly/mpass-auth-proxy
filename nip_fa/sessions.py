"""Adapter sessions: storage keyed by token hash, and D6 revalidation."""

import enum
import hashlib
import json
import logging
import secrets
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import Protocol

import httpx
import jwt

from .sealing import SESSION_REFRESH_TOKEN, seal, unseal

logger = logging.getLogger(__name__)

REVALIDATION_INTERVAL_SECONDS = 3600
_SESSION_KEY_PREFIX = "nip_fa_session:"


@dataclass(frozen=True)
class Identity:
    """`sub` is the mPass ID (Cognito `cognito:username`), the stable subject
    the adapter keys everything on. `cognito_sub` is for log correlation only."""

    sub: str
    cognito_sub: str
    email: str | None


@dataclass(frozen=True)
class Session:
    identity: Identity
    refresh_token: str
    expires_at: int
    revalidated_at: int

    def __repr__(self) -> str:
        return f"Session(sub={self.identity.sub!r}, expires_at={self.expires_at})"

    def expired_at(self, now: int) -> bool:
        return now >= self.expires_at

    def due_for_revalidation(self, now: int) -> bool:
        return now - self.revalidated_at >= REVALIDATION_INTERVAL_SECONDS


class Revalidation(enum.Enum):
    VALID = "valid"
    ENDED = "ended"
    UNAVAILABLE = "unavailable"


class LookupStatus(enum.Enum):
    FOUND = "found"
    MISSING = "missing"
    ENDED = "ended"


@dataclass(frozen=True)
class SessionLookup:
    status: LookupStatus
    session: Session | None = None
    revalidation: Revalidation | None = None


class IdpUnavailable(Exception):
    """The IdP could not be asked, for a reason other than an HTTP transport error."""


class IdentityProvider(Protocol):
    async def refresh_grant(self, refresh_token: str) -> httpx.Response:
        """Raises httpx.HTTPError or IdpUnavailable when the IdP cannot be asked."""

    async def corporate_id_allowed(self, access_token: str) -> bool: ...


def rfc3339(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def session_key(session_token: str) -> str:
    return _SESSION_KEY_PREFIX + hashlib.sha256(session_token.encode("utf-8")).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def encode_record(session_token: str, session: Session) -> str:
    return json.dumps({
        "identity": asdict(session.identity),
        "sealed_refresh_token": seal(session_token, session.refresh_token, SESSION_REFRESH_TOKEN),
        "expires_at": session.expires_at,
        "revalidated_at": session.revalidated_at,
    })


def decode_record(session_token: str, raw: str) -> Session | None:
    """The session, or None when the record cannot be trusted for this token."""
    data = json.loads(raw)
    refresh_token = unseal(session_token, data["sealed_refresh_token"], SESSION_REFRESH_TOKEN)
    if refresh_token is None:
        return None
    return Session(
        identity=Identity(**data["identity"]),
        refresh_token=refresh_token,
        expires_at=data["expires_at"],
        revalidated_at=data["revalidated_at"],
    )


class SessionStore:
    def __init__(self, redis_factory):
        self._redis_factory = redis_factory

    async def put(self, session_token: str, session: Session, now: int) -> None:
        await self._redis_factory().setex(
            session_key(session_token), session.expires_at - now, encode_record(session_token, session)
        )

    async def replace_existing(self, session_token: str, session: Session) -> bool:
        """Overwrite the record only while it still exists, keeping its TTL, so
        a session deleted mid-revalidation stays deleted."""
        written = await self._redis_factory().set(
            session_key(session_token), encode_record(session_token, session), xx=True, keepttl=True
        )
        return bool(written)

    async def load(self, session_token: str) -> Session | None:
        raw = await self._redis_factory().get(session_key(session_token))
        if not raw:
            return None
        session = decode_record(session_token, raw)
        if session is None:
            logger.warning("nip-fa: session record failed to unseal; treating as no session")
        return session

    async def delete(self, session_token: str) -> None:
        await self._redis_factory().delete(session_key(session_token))


class SessionService:
    """Looks up an adapter session and revalidates it against the IdP (D6):
    at most hourly, the stored Cognito refresh token is exchanged and the
    corporate-id gate re-run. A refusal ends the session; an outage leaves it
    in place for the caller to decide how to answer."""

    def __init__(self, store: SessionStore, idp: IdentityProvider, clock):
        self._store = store
        self._idp = idp
        self._clock = clock

    def now(self) -> int:
        return int(self._clock())

    async def open(self, identity: Identity, refresh_token: str, ttl_seconds: int) -> tuple[str, Session]:
        now = self.now()
        session = Session(
            identity=identity,
            refresh_token=refresh_token,
            expires_at=now + ttl_seconds,
            revalidated_at=now,
        )
        session_token = new_session_token()
        await self._store.put(session_token, session, now)
        return session_token, session

    async def lookup(self, session_token: str) -> SessionLookup:
        session = await self._store.load(session_token)
        if session is None:
            return SessionLookup(LookupStatus.MISSING)
        now = self.now()
        if session.expired_at(now):
            await self._store.delete(session_token)
            return SessionLookup(LookupStatus.ENDED)
        if not session.due_for_revalidation(now):
            return SessionLookup(LookupStatus.FOUND, session, Revalidation.VALID)
        return await self._revalidate(session_token, session, now)

    async def _revalidate(self, session_token: str, session: Session, now: int) -> SessionLookup:
        outcome, rotated_refresh_token = await self._ask_idp(session)
        sub = session.identity.sub
        if outcome is Revalidation.ENDED:
            await self._store.delete(session_token)
            logger.warning("nip-fa: session ended on revalidation for mpass_id=%s", sub)
            return SessionLookup(LookupStatus.ENDED)
        if outcome is Revalidation.UNAVAILABLE:
            logger.warning("nip-fa: revalidation unavailable for mpass_id=%s; session kept", sub)
            return SessionLookup(LookupStatus.FOUND, session, outcome)
        renewed = replace(
            session,
            refresh_token=rotated_refresh_token or session.refresh_token,
            revalidated_at=now,
        )
        if not await self._store.replace_existing(session_token, renewed):
            logger.warning("nip-fa: session deleted during revalidation for mpass_id=%s", sub)
            return SessionLookup(LookupStatus.ENDED)
        logger.info("nip-fa: session revalidated for mpass_id=%s", sub)
        return SessionLookup(LookupStatus.FOUND, renewed, outcome)

    async def _ask_idp(self, session: Session) -> tuple[Revalidation, str | None]:
        try:
            response = await self._idp.refresh_grant(session.refresh_token)
        except (httpx.HTTPError, IdpUnavailable) as exc:
            logger.warning("nip-fa: refresh grant failed: %s", type(exc).__name__)
            return Revalidation.UNAVAILABLE, None
        if response.status_code != 200:
            return _classify_refusal(response), None
        body = _json_object(response)
        access_token = body.get("access_token")
        if not access_token:
            return Revalidation.UNAVAILABLE, None
        try:
            allowed = await self._idp.corporate_id_allowed(access_token)
        except (httpx.HTTPError, jwt.PyJWTError) as exc:
            logger.warning("nip-fa: corporate-id check failed: %s", type(exc).__name__)
            return Revalidation.UNAVAILABLE, None
        if not allowed:
            return Revalidation.ENDED, None
        return Revalidation.VALID, body.get("refresh_token")


def _classify_refusal(response: httpx.Response) -> Revalidation:
    if response.status_code in (400, 401) and _json_object(response).get("error") == "invalid_grant":
        return Revalidation.ENDED
    return Revalidation.UNAVAILABLE


def _json_object(response: httpx.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
