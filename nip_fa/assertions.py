"""NIP-FI relay assertions: the request body, the claims, the signature, and
the per-session issuance rate limit."""

import re
import unicodedata
from dataclasses import dataclass

import jwt
from redis.exceptions import RedisError

from .bodies import strict_json_loads
from .urls import relay_audience

ASSERTION_TYP = "nip-fi+jwt"
ASSERTION_ALGORITHM = "RS256"
ASSERTION_FIELDS = frozenset({"relay_url", "nostr_pubkey"})
MAX_ASSERTION_BODY_BYTES = 4096

_PUBKEY_PATTERN = re.compile(r"[0-9a-f]{64}")
_USERNAME_PATTERN = re.compile(r"[a-z0-9._-]{1,64}")
_MAX_DISPLAY_NAME_CHARS = 64
_FORBIDDEN_DISPLAY_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


@dataclass(frozen=True)
class AssertionRequest:
    relay_url: str
    nostr_pubkey: str


def parse_assertion_body(raw: bytes) -> AssertionRequest | None:
    try:
        body = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(body, dict) or set(body) != ASSERTION_FIELDS:
        return None
    relay_url, pubkey = body["relay_url"], body["nostr_pubkey"]
    if not isinstance(relay_url, str) or not isinstance(pubkey, str) or not _PUBKEY_PATTERN.fullmatch(pubkey):
        return None
    return AssertionRequest(relay_url=relay_url, nostr_pubkey=pubkey)



def is_publishable_profile(profile: dict | None) -> bool:
    """The relay's `nostr_public_profile` rules (buzz-auth public_profile.rs):
    anything else is dropped relay-side, so it is not sent at all."""
    return (
        profile is not None
        and bool(_USERNAME_PATTERN.fullmatch(profile["username"]))
        and _is_display_name(profile["display_name"])
    )


def _is_display_name(value: str) -> bool:
    return (
        0 < len(value) <= _MAX_DISPLAY_NAME_CHARS
        and value.strip() == value
        and unicodedata.is_normalized("NFC", value)
        and not any(unicodedata.category(char) in _FORBIDDEN_DISPLAY_CATEGORIES for char in value)
    )


def assertion_claims(
    issuer: str,
    sub: str,
    relay_url: str,
    nostr_pubkey: str,
    issued_at: int,
    expires_at: int,
    profile: dict | None,
) -> dict:
    claims = {
        "iss": issuer,
        "sub": sub,
        "aud": relay_audience(relay_url),
        "iat": issued_at,
        "exp": expires_at,
        "nostr_pubkey": nostr_pubkey,
    }
    if is_publishable_profile(profile):
        claims["nostr_public_profile"] = {
            "display_name": profile["display_name"],
            "username": profile["username"],
        }
    return claims


def assertion_expiry(issued_at: int, ttl_seconds: int, session_expires_at: int) -> int:
    """NIP-FA: never later than the adapter session's expiry."""
    return min(issued_at + ttl_seconds, session_expires_at)


@dataclass(frozen=True)
class SigningKey:
    private_key: object
    kid: str

    def __repr__(self) -> str:
        return f"SigningKey(kid={self.kid!r}, private_key=<redacted>)"


def sign_assertion(claims: dict, signing_key: SigningKey) -> str:
    return jwt.encode(
        claims,
        signing_key.private_key,
        algorithm=ASSERTION_ALGORITHM,
        headers={"typ": ASSERTION_TYP, "kid": signing_key.kid},
    )


class RateLimiterUnavailable(Exception):
    """The rate-limit counter could not be read or written."""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: int = 0


class AssertionRateLimiter:
    """A fixed window per adapter session, counted in Redis under the session
    record's key (a token hash), never the token itself."""

    KEY_PREFIX = "nip_fa_assertion_rate:"

    def __init__(self, redis_factory, limit: int, window_seconds: int):
        self._redis_factory = redis_factory
        self._limit = limit
        self._window_seconds = window_seconds

    async def check(self, session_record_key: str) -> RateDecision:
        key = self.KEY_PREFIX + session_record_key
        try:
            count, ttl = await self._count(key)
        except (RedisError, OSError) as exc:
            raise RateLimiterUnavailable() from exc
        if count <= self._limit:
            return RateDecision(allowed=True)
        return RateDecision(allowed=False, retry_after_seconds=max(ttl, 1))

    async def _count(self, key: str) -> tuple[int, int]:
        async with self._redis_factory().pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, self._window_seconds, nx=True)
            pipe.ttl(key)
            count, _, ttl = await pipe.execute()
        return int(count), int(ttl)
