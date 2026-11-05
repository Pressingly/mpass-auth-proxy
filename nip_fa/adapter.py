"""NIP-FA browser login, code exchange, session check, identity key and relay
assertion. The agent routes live in agent_routes.py."""

import asyncio
import contextlib
import hashlib
import logging
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Protocol

import asyncpg
from fastapi import APIRouter
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response

from .admin_routes import AdminRoutes
from .agent_routes import AgentRoutes
from .agents import AgentStore, LaunchpadAgentStore
from .assertions import (
    MAX_ASSERTION_BODY_BYTES,
    AssertionRateLimiter,
    AssertionRequest,
    RateLimiterUnavailable,
    SigningKey,
    assertion_claims,
    assertion_expiry,
    parse_assertion_body,
    sign_assertion,
)
from .bodies import RequestTooLarge, read_body_within
from .config import AdapterConfig
from .identities import (
    IdentityKeyService,
    IdentityStore,
    KeyIssuance,
    KeyIssuanceStatus,
    LaunchpadIdentityStore,
)
from .nip98 import ExpectedRequest, ProofFailure, verify_http_auth
from .relay_commands import CommandIssuer, RelayDisconnector
from .responses import (
    adapter_json,
    adapter_redirect,
    authorization_denied,
    binding_mismatch,
    invalid_proof,
    invalid_request,
    issuance_unavailable,
    rate_limited,
    request_too_large,
    session_expired,
    session_required,
)
from .revocation import (
    DenyRepusher,
    LaunchpadRevocationStore,
    OwnerRevocation,
    RevocationStore,
    RevokedSubjects,
)
from .routes import (
    AGENT_ASSERTION_ROUTE,
    AGENT_GRANT_ROUTE,
    AGENT_REVOKE_ROUTE,
    ASSERTIONS_ROUTE,
    ROUTE_PREFIX,
)
from .sealing import LOGIN_CODE_RECORD, RecordSealer
from .sessions import (
    Identity,
    IdentityProvider,
    LookupStatus,
    Revalidation,
    Session,
    SessionLookup,
    SessionService,
    SessionStore,
    rfc3339,
)
from .urls import relay_authority
from .validation import challenge_matches, parse_exchange_body, parse_login_start, with_query_params

logger = logging.getLogger(__name__)

FLOW_TAG = "nip-fa"
CODE_TTL_SECONDS = 120
MAX_EXCHANGE_BODY_BYTES = 4096
ASSERTION_RATE_LIMIT = 30
ASSERTION_RATE_WINDOW_SECONDS = 60
_CODE_KEY_PREFIX = "nip_fa_code:"


class IdentityUnavailable(Exception):
    """The platform could not resolve the user's email right now."""


class EmailVerificationRequired(Exception):
    """The platform requires a verified email and this user has none yet."""


class PlatformGateway(IdentityProvider, Protocol):
    """What the adapter needs from the host service. main.py implements it, so
    the Moneta, Cognito and launchpad logic stays in one place."""

    def redis(self): ...

    async def begin_moneta_login(self, state: str, bridge_data: dict) -> Response: ...

    async def resolve_email(self, claims: dict) -> str | None:
        """Raises IdentityUnavailable, or EmailVerificationRequired when the
        platform requires a verified email and the user has none."""

    async def launchpad_pool(self) -> asyncpg.Pool:
        """Raises IdentityStoreUnavailable when the launchpad database cannot be reached."""

    def signing_key(self) -> SigningKey:
        """The key that signs NIP-FI assertions, published at /.well-known/jwks.json."""


def _code_key(code: str) -> str:
    return _CODE_KEY_PREFIX + hashlib.sha256(code.encode("utf-8")).hexdigest()


def _usable_email(email: str | None) -> str | None:
    if not email:
        return None
    local, at, domain = email.partition("@")
    return email if local and at and domain else None


def _profile_projection(email: str | None) -> dict | None:
    if not email:
        return None
    local_part = email.partition("@")[0]
    return {"username": local_part, "display_name": local_part}


def session_view(session: Session) -> dict:
    view: dict = {"expires_at": rfc3339(session.expires_at)}
    if session.identity.email:
        view["email"] = session.identity.email
    view["profile_projection"] = _profile_projection(session.identity.email)
    return view


_KEY_REFUSALS = {
    KeyIssuanceStatus.REVOKED: authorization_denied,
    KeyIssuanceStatus.BINDING_MISMATCH: binding_mismatch,
    KeyIssuanceStatus.UNAVAILABLE: issuance_unavailable,
}


def _key_refusal(status: KeyIssuanceStatus) -> Response | None:
    refusal = _KEY_REFUSALS.get(status)
    return refusal() if refusal is not None else None


def _issuance_response(issuance: KeyIssuance) -> Response:
    refusal = _key_refusal(issuance.status)
    if refusal is not None:
        return refusal
    keypair = issuance.keypair
    return adapter_json({"nostr_pubkey": keypair.pubkey_hex, "secret_key": keypair.secret_key_hex})


@dataclass(frozen=True)
class _AssertionInput:
    proof: str
    raw_body: bytes
    body: AssertionRequest

    def __repr__(self) -> str:
        return "_AssertionInput(<redacted>)"


async def _read_assertion_input(request: Request) -> _AssertionInput | Response:
    proofs = request.headers.getlist("nostr-authorization")
    if len(proofs) != 1 or "content-encoding" in request.headers:
        return invalid_request()
    try:
        raw = await read_body_within(request, MAX_ASSERTION_BODY_BYTES)
    except RequestTooLarge:
        return request_too_large()
    body = parse_assertion_body(raw)
    if body is None:
        return invalid_request()
    return _AssertionInput(proof=proofs[0], raw_body=raw, body=body)


def _single_bearer_token(headers: Headers) -> tuple[str | None, Response | None]:
    values = headers.getlist("authorization")
    if not values:
        return None, session_required()
    if len(values) > 1:
        return None, invalid_request()
    scheme, _, token = values[0].partition(" ")
    if scheme.lower() != "bearer":
        return None, invalid_request()
    token = token.strip()
    if not token:
        return None, session_required()
    return token, None


def _relay_disconnector(config: AdapterConfig, gateway: PlatformGateway, clock) -> RelayDisconnector | None:
    if config.revocation is None:
        return None
    issuer = CommandIssuer(
        issuer=config.nip_fi_issuer,
        principal=config.revocation.command_principal,
        signing_key=gateway.signing_key,
    )
    return RelayDisconnector(config.revocation.relays, issuer, config.assertion_ttl_seconds, clock)


def _revocation_parts(
    config: AdapterConfig,
    store: RevocationStore,
    subjects: RevokedSubjects | None,
    disconnector: RelayDisconnector | None,
    clock,
) -> tuple[AdminRoutes | None, DenyRepusher | None]:
    if config.revocation is None:
        return None, None
    deny_seconds = config.assertion_ttl_seconds
    revocation = OwnerRevocation(store, subjects, disconnector, deny_seconds, clock)
    return (
        AdminRoutes(config.revocation.admin_token, revocation),
        DenyRepusher(store, disconnector, deny_seconds, clock),
    )


class NipFaAdapter:
    def __init__(
        self,
        config: AdapterConfig,
        gateway: PlatformGateway,
        clock=time.time,
        identity_store: IdentityStore | None = None,
        agent_store: AgentStore | None = None,
        disconnector: RelayDisconnector | None = None,
        revocation_store: RevocationStore | None = None,
    ):
        self._config = config
        self._gateway = gateway
        self.sealer = RecordSealer(config.identity_master_secret)
        disconnector = disconnector or _relay_disconnector(config, gateway, clock)
        subjects = RevokedSubjects(gateway.redis, config.session_ttl_seconds) if config.revocation else None
        self.sessions = SessionService(SessionStore(gateway.redis, self.sealer), gateway, clock, subjects)
        self.identity_keys = IdentityKeyService(
            config.identity_master_secret,
            config.identity_salt,
            identity_store or LaunchpadIdentityStore(gateway.launchpad_pool),
            self.sessions.subject_revoked if subjects is not None else None,
        )
        self.assertion_rate_limiter = AssertionRateLimiter(
            gateway.redis, ASSERTION_RATE_LIMIT, ASSERTION_RATE_WINDOW_SECONDS
        )
        self.agents = AgentRoutes(
            config=config,
            sessions=self.sessions,
            authenticate=self.authenticate,
            identity_keys=self.identity_keys,
            store=agent_store or LaunchpadAgentStore(gateway.launchpad_pool),
            disconnector=disconnector,
            redis_factory=gateway.redis,
            signing_key=gateway.signing_key,
        )
        self.admin, self.repusher = _revocation_parts(
            config, revocation_store or LaunchpadRevocationStore(gateway.launchpad_pool), subjects, disconnector, clock
        )
        self._background: asyncio.Task | None = None
        self.router = self._build_router()

    def _build_router(self) -> APIRouter:
        router = APIRouter()
        router.include_router(self._public_router())
        if self.admin is not None:
            router.include_router(self.admin.router)
        return router

    def start_background(self) -> None:
        """Starts the relay deny re-push when owner revocation is on."""
        if self.repusher is not None and self._background is None:
            self._background = asyncio.get_running_loop().create_task(self.repusher.run_forever())

    async def stop_background(self) -> None:
        if self._background is None:
            return
        self._background.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._background
        self._background = None

    def _public_router(self) -> APIRouter:
        router = APIRouter(prefix=ROUTE_PREFIX)
        router.add_api_route("/v1/login/start", self.start_login, methods=["GET"])
        router.add_api_route("/v1/login/exchange", self.exchange_code, methods=["POST"])
        router.add_api_route("/v1/session", self.check_session, methods=["GET"])
        router.add_api_route("/v1/identity/key", self.issue_identity_key, methods=["GET"])
        router.add_api_route(ASSERTIONS_ROUTE, self.issue_assertion, methods=["POST"])
        router.add_api_route(AGENT_GRANT_ROUTE, self.agents.issue_grant, methods=["POST"])
        router.add_api_route(AGENT_ASSERTION_ROUTE, self.agents.issue_assertion, methods=["POST"])
        router.add_api_route(AGENT_REVOKE_ROUTE, self.agents.revoke, methods=["POST"])
        return router

    def owns(self, bridge_data: dict) -> bool:
        return bridge_data.get("flow") == FLOW_TAG

    async def start_login(self, request: Request) -> Response:
        login = parse_login_start(request.query_params.multi_items())
        if login is None:
            return invalid_request()
        bridge_data = {
            "flow": FLOW_TAG,
            "return_to": login.return_to,
            "handoff_challenge": login.handoff_challenge,
        }
        response = await self._gateway.begin_moneta_login(secrets.token_urlsafe(32), bridge_data)
        response.headers.update({"Cache-Control": "no-store"})
        return response

    def deny_login(
        self, bridge_data: dict, error: str = "access_denied", description: str | None = None
    ) -> Response:
        params = {"error": error, **({"error_description": description} if description else {})}
        return adapter_redirect(with_query_params(bridge_data["return_to"], params))

    async def complete_login(self, bridge_data: dict, claims: dict, refresh_token: str) -> Response:
        """Called by /mpass-callback once the id_token is verified and the
        corporate-id gate has passed. Fails closed without a stable subject."""
        mpass_id = claims.get("cognito:username")
        if not mpass_id:
            logger.error("nip-fa: verified id_token has no cognito:username; refusing login")
            return self.deny_login(bridge_data, "server_error")
        if not refresh_token:
            logger.error("nip-fa: no refresh_token for mpass_id=%s; refusing login", mpass_id)
            return self.deny_login(bridge_data, "server_error")
        try:
            email = await self._gateway.resolve_email(claims)
        except IdentityUnavailable:
            logger.error("nip-fa: email unavailable for mpass_id=%s; refusing login", mpass_id)
            return self.deny_login(bridge_data, "temporarily_unavailable")
        except EmailVerificationRequired:
            logger.warning(
                "nip-fa: login refused for mpass_id=%s reason=email_verification_required", mpass_id
            )
            return self.deny_login(bridge_data, "access_denied", "email_verification_required")

        identity = Identity(
            sub=mpass_id,
            cognito_sub=str(claims.get("sub", "")),
            email=_usable_email(email),
        )
        code = secrets.token_urlsafe(32)
        record = {
            "handoff_challenge": bridge_data["handoff_challenge"],
            "identity": asdict(identity),
            "refresh_token": refresh_token,
        }
        sealed = self.sealer.seal(code, record, LOGIN_CODE_RECORD)
        await self._gateway.redis().setex(_code_key(code), CODE_TTL_SECONDS, sealed)
        logger.info("nip-fa: login code issued for mpass_id=%s", mpass_id)
        return adapter_redirect(with_query_params(bridge_data["return_to"], {"code": code}))

    async def exchange_code(self, request: Request) -> Response:
        if request.headers.get("content-encoding"):
            return invalid_request()
        try:
            raw = await read_body_within(request, MAX_EXCHANGE_BODY_BYTES)
        except RequestTooLarge:
            return request_too_large()
        exchange = parse_exchange_body(raw)
        if exchange is None:
            return invalid_request()

        stored = await self._gateway.redis().getdel(_code_key(exchange.code))
        if not stored:
            logger.warning("nip-fa: exchange with unknown or expired code")
            return invalid_request()
        record = self.sealer.unseal(exchange.code, stored, LOGIN_CODE_RECORD)
        if record is None:
            logger.error("nip-fa: login code record failed to unseal; code burned")
            return invalid_request()
        identity = Identity(**record["identity"])
        if await self.sessions.subject_revoked(identity.sub):
            logger.warning("nip-fa: exchange refused for revoked mpass_id=%s; code burned", identity.sub)
            return invalid_request()
        if not challenge_matches(exchange.handoff_secret, record["handoff_challenge"]):
            logger.warning("nip-fa: handoff secret mismatch for mpass_id=%s; code burned", identity.sub)
            return invalid_request()

        session_token, session = await self.sessions.open(
            identity, record["refresh_token"], self._config.session_ttl_seconds
        )
        logger.info("nip-fa: session opened for mpass_id=%s", identity.sub)
        return adapter_json({"session_token": session_token, **session_view(session)})

    async def authenticate(self, headers: Headers) -> tuple[SessionLookup | None, Response | None]:
        """Shared session gate for every Bearer-authenticated adapter route.
        Returns the lookup, or the denial to send when there is no usable session."""
        token, denial = _single_bearer_token(headers)
        if denial is not None:
            return None, denial
        lookup = await self.sessions.lookup(token)
        if lookup.status is LookupStatus.MISSING:
            return None, session_required()
        if lookup.status is LookupStatus.ENDED:
            return None, session_expired()
        return lookup, None

    async def check_session(self, request: Request) -> Response:
        lookup, denial = await self.authenticate(request.headers)
        if denial is not None:
            return denial
        return adapter_json(session_view(lookup.session))

    async def issue_identity_key(self, request: Request) -> Response:
        """Our custodial extension to NIP-FA: the platform-held Nostr key for the
        session's mPass ID. Stricter than the session check: a session whose
        hourly revalidation could not reach the IdP gets no key."""
        lookup, denial = await self.authenticate(request.headers)
        if denial is not None:
            return denial
        if lookup.revalidation is Revalidation.UNAVAILABLE:
            return issuance_unavailable()
        return _issuance_response(await self.identity_keys.issue(lookup.session.identity))

    async def issue_assertion(self, request: Request) -> Response:
        """NIP-FA "Relay assertion". Authenticate (session, then NIP-98 proof of
        the key) before authorizing (relay allowlist, then identity binding):
        the proof's `payload` tag is what authenticates `relay_url`, so no
        authorization decision is made on a body the key holder did not sign."""
        lookup, denial = await self.authenticate(request.headers)
        if denial is not None:
            return denial
        if lookup.revalidation is Revalidation.UNAVAILABLE:
            return issuance_unavailable()
        denial = await self._rate_limit_denial(lookup)
        if denial is not None:
            return denial
        inputs = await _read_assertion_input(request)
        if isinstance(inputs, Response):
            return inputs
        identity = lookup.session.identity
        now = self.sessions.now()
        if lookup.session.expired_at(now):
            return session_expired()
        denial = self._proof_denial(identity, inputs, now)
        if denial is not None:
            return denial
        denial = self._relay_denial(identity, inputs.body)
        if denial is not None:
            return denial
        denial = await self._binding_denial(identity, inputs.body.nostr_pubkey)
        if denial is not None:
            return denial
        return self._assertion_response(lookup.session, inputs.body, now)

    async def _rate_limit_denial(self, lookup: SessionLookup) -> Response | None:
        try:
            decision = await self.assertion_rate_limiter.check(lookup.record_key)
        except RateLimiterUnavailable:
            logger.error("nip-fa: assertion rate limiter unavailable mpass_id=%s", lookup.session.identity.sub)
            return issuance_unavailable()
        if decision.allowed:
            return None
        logger.warning("nip-fa: assertion refused mpass_id=%s reason=rate_limited", lookup.session.identity.sub)
        return rate_limited(decision.retry_after_seconds)

    def _proof_denial(self, identity: Identity, inputs: _AssertionInput, now: int) -> Response | None:
        expected = ExpectedRequest(url=self._config.assertions_url, method="POST", body=inputs.raw_body)
        result = verify_http_auth(inputs.proof, expected, now)
        if isinstance(result, ProofFailure):
            reason = result.value
        elif result.pubkey != inputs.body.nostr_pubkey:
            reason = "signer_is_not_nostr_pubkey"
        else:
            return None
        logger.warning("nip-fa: assertion refused mpass_id=%s reason=invalid_proof detail=%s", identity.sub, reason)
        return invalid_proof()

    def _relay_denial(self, identity: Identity, body: AssertionRequest) -> Response | None:
        if body.relay_url in self._config.relay_urls:
            return None
        logger.warning("nip-fa: assertion refused mpass_id=%s reason=unknown_relay", identity.sub)
        return authorization_denied()

    async def _binding_denial(self, identity: Identity, nostr_pubkey: str) -> Response | None:
        issuance = await self.identity_keys.bind(identity)
        refusal = _key_refusal(issuance.status)
        if refusal is not None:
            return refusal
        if issuance.keypair.pubkey_hex == nostr_pubkey:
            return None
        logger.warning(
            "nip-fa: assertion refused mpass_id=%s reason=binding_mismatch; requested key is not the "
            "user's bound key",
            identity.sub,
        )
        return binding_mismatch()

    def _assertion_response(self, session: Session, body: AssertionRequest, now: int) -> Response:
        expires_at = assertion_expiry(now, self._config.assertion_ttl_seconds, session.expires_at)
        claims = assertion_claims(
            issuer=self._config.nip_fi_issuer,
            sub=session.identity.sub,
            relay_url=body.relay_url,
            nostr_pubkey=body.nostr_pubkey,
            issued_at=now,
            expires_at=expires_at,
            profile=_profile_projection(session.identity.email),
        )
        assertion = sign_assertion(claims, self._gateway.signing_key())
        logger.info(
            "nip-fa: assertion issued mpass_id=%s pubkey=%s relay=%s exp=%d",
            session.identity.sub, body.nostr_pubkey, relay_authority(body.relay_url), expires_at,
        )
        return adapter_json({"assertion": assertion, "nostr_pubkey": body.nostr_pubkey, "expires_at": expires_at})
