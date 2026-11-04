"""NIP-FA browser login, code exchange and session check."""

import hashlib
import json
import logging
import secrets
import time
from dataclasses import asdict
from typing import Protocol

from fastapi import APIRouter
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response

from .config import AdapterConfig
from .responses import (
    adapter_json,
    adapter_redirect,
    invalid_request,
    request_too_large,
    session_expired,
    session_required,
)
from .sessions import (
    Identity,
    IdentityProvider,
    LookupStatus,
    Session,
    SessionLookup,
    SessionService,
    SessionStore,
    rfc3339,
)
from .validation import challenge_matches, parse_exchange_body, parse_login_start, with_query_params

logger = logging.getLogger(__name__)

ROUTE_PREFIX = "/nip-fa"
FLOW_TAG = "nip-fa"
CODE_TTL_SECONDS = 120
MAX_EXCHANGE_BODY_BYTES = 4096
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


class NipFaAdapter:
    def __init__(self, config: AdapterConfig, gateway: PlatformGateway, clock=time.time):
        self._config = config
        self._gateway = gateway
        self.sessions = SessionService(SessionStore(gateway.redis), gateway, clock)
        self.router = self._build_router()

    def _build_router(self) -> APIRouter:
        router = APIRouter(prefix=ROUTE_PREFIX)
        router.add_api_route("/v1/login/start", self.start_login, methods=["GET"])
        router.add_api_route("/v1/login/exchange", self.exchange_code, methods=["POST"])
        router.add_api_route("/v1/session", self.check_session, methods=["GET"])
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
        await self._gateway.redis().setex(_code_key(code), CODE_TTL_SECONDS, json.dumps(record))
        logger.info("nip-fa: login code issued for mpass_id=%s", mpass_id)
        return adapter_redirect(with_query_params(bridge_data["return_to"], {"code": code}))

    async def exchange_code(self, request: Request) -> Response:
        if request.headers.get("content-encoding"):
            return invalid_request()
        raw = await request.body()
        if len(raw) > MAX_EXCHANGE_BODY_BYTES:
            return request_too_large()
        exchange = parse_exchange_body(raw)
        if exchange is None:
            return invalid_request()

        stored = await self._gateway.redis().getdel(_code_key(exchange.code))
        if not stored:
            logger.warning("nip-fa: exchange with unknown or expired code")
            return invalid_request()
        record = json.loads(stored)
        identity = Identity(**record["identity"])
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
