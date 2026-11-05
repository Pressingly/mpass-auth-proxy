"""NIP-FI "Admin disconnect API": the issuer tells each relay to close a key's
live connections and deny it until `until`.

    POST {internal_url}/api/nip-fi/disconnect
    Nostr-Federated-Identity: Bearer <command JWT, typ nip-fi-command+jwt>
    {"pubkey": "<target>"}

The relay keeps its deny set in memory only, so a restarted relay forgets it;
sending the same disconnect again is always safe (an accepted disconnect never
shortens an active deny). Used by agent revocation, and meant for owner
revocation too."""

import asyncio
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass

import httpx
import jwt

from .assertions import ASSERTION_ALGORITHM, SigningKey
from .config import RelayEndpoint

logger = logging.getLogger(__name__)

COMMAND_TYP = "nip-fi-command+jwt"
DISCONNECT_PATH = "/api/nip-fi/disconnect"
DISCONNECT_METHOD = "POST"
DISCONNECT_COMMAND = "disconnect"
COMMAND_HEADER = "Nostr-Federated-Identity"
COMMAND_TTL_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class CommandIssuer:
    issuer: str
    principal: str
    signing_key: Callable[[], SigningKey]


def disconnect_claims(
    issuer: CommandIssuer, audience: str, target_pubkey: str, now: int, until: int, jti: str
) -> dict:
    return {
        "iss": issuer.issuer,
        "sub": issuer.principal,
        "aud": audience,
        "iat": now,
        "exp": now + COMMAND_TTL_SECONDS,
        "jti": jti,
        "method": DISCONNECT_METHOD,
        "path": DISCONNECT_PATH,
        "cmd": DISCONNECT_COMMAND,
        "target_pubkey": target_pubkey,
        "until": until,
    }


def sign_command(claims: dict, signing_key: SigningKey) -> str:
    return jwt.encode(
        claims,
        signing_key.private_key,
        algorithm=ASSERTION_ALGORITHM,
        headers={"typ": COMMAND_TYP, "kid": signing_key.kid},
    )


def is_disconnected(response: httpx.Response) -> bool:
    if response.status_code != 200:
        return False
    try:
        return response.json() == {"disconnected": True}
    except ValueError:
        return False


def default_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False)


@dataclass(frozen=True)
class DisconnectReport:
    failed_relays: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.failed_relays


def _succeeded(relay: RelayEndpoint, target_pubkey: str, result: bool | BaseException) -> bool:
    """A disconnect that raised (a bad URL, a signing error) fails that relay
    only, so the caller still answers and logs an incomplete disconnect."""
    if isinstance(result, BaseException):
        logger.error(
            "nip-fa: relay disconnect errored relay=%s pubkey=%s error=%s",
            relay.relay_url, target_pubkey, type(result).__name__,
        )
        return False
    return result


class RelayDisconnector:
    """Disconnects a key on every configured relay. `deny_seconds` should
    outlast every assertion already issued for the key, so it is the
    assertion TTL. The relay refuses an `until` past its own
    `now + skew + maximum_assertion_age`, so those must exceed the TTL by the
    clock drift between the two hosts."""

    def __init__(
        self,
        relays: tuple[RelayEndpoint, ...],
        issuer: CommandIssuer,
        deny_seconds: int,
        clock,
        http_client: Callable[[], httpx.AsyncClient] = default_http_client,
    ):
        self._relays = relays
        self._issuer = issuer
        self._deny_seconds = deny_seconds
        self._clock = clock
        self._http_client = http_client

    async def disconnect(self, target_pubkey: str, until: int | None = None) -> DisconnectReport:
        """`until` defaults to now plus the deny window. Owner revocation and
        the re-push pass one anchored on the stored revocation time instead."""
        async with self._http_client() as client:
            results = await asyncio.gather(
                *(self._disconnect_on(client, relay, target_pubkey, until) for relay in self._relays),
                return_exceptions=True,
            )
        return DisconnectReport(
            failed_relays=tuple(
                relay.relay_url
                for relay, result in zip(self._relays, results)
                if not _succeeded(relay, target_pubkey, result)
            )
        )

    async def _disconnect_on(
        self, client: httpx.AsyncClient, relay: RelayEndpoint, target_pubkey: str, until: int | None
    ) -> bool:
        now = int(self._clock())
        claims = disconnect_claims(
            self._issuer, relay.command_audience, target_pubkey, now,
            now + self._deny_seconds if until is None else until,
            secrets.token_urlsafe(24),
        )
        command = sign_command(claims, self._issuer.signing_key())
        try:
            response = await client.post(
                relay.internal_url + DISCONNECT_PATH,
                json={"pubkey": target_pubkey},
                headers={COMMAND_HEADER: f"Bearer {command}"},
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "nip-fa: relay disconnect failed relay=%s pubkey=%s error=%s",
                relay.relay_url, target_pubkey, type(exc).__name__,
            )
            return False
        if not is_disconnected(response):
            logger.warning(
                "nip-fa: relay disconnect refused relay=%s pubkey=%s status=%d",
                relay.relay_url, target_pubkey, response.status_code,
            )
            return False
        logger.info("nip-fa: relay disconnect accepted relay=%s pubkey=%s", relay.relay_url, target_pubkey)
        return True
