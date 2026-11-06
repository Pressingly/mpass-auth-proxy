"""Internal adapter routes for operators: owner revocation and the owner
pubkey lookup a provisioner needs for the relay's RELAY_OWNER_PUBKEY.

They live under INTERNAL_PREFIX, outside `/nip-fa/`, so the public
`PathPrefix(/nip-fa/)` rule never routes them; callers reach this service on
its internal hostname. Each request carries `Authorization: Bearer
<BUZZ_ADMIN_TOKEN>`, compared in constant time."""

import hmac
import logging

from fastapi import APIRouter
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response

from .bodies import RequestTooLarge, read_body_within, strict_json_loads
from .responses import adapter_json, denial, invalid_request, request_too_large
from .revocation import OwnerRevocation, RevocationOutcome, RevocationStoreUnavailable

logger = logging.getLogger(__name__)

INTERNAL_PREFIX = "/internal/nip-fa"
REVOKE_ROUTE = "/v1/identity/revoke"
PUBKEY_ROUTE = "/v1/identity/pubkey"
MAX_REVOKE_BODY_BYTES = 4096
MAX_MPASS_ID_CHARS = 2048


def presents_admin_token(headers: Headers, admin_token: str) -> bool:
    values = headers.getlist("authorization")
    if len(values) != 1:
        return False
    scheme, _, token = values[0].partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(token.strip().encode("utf-8"), admin_token.encode("utf-8"))


def is_mpass_id(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_MPASS_ID_CHARS and value.strip() == value


def parse_revoke_body(raw: bytes) -> str | None:
    try:
        body = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(body, dict) or set(body) != {"mpass_id"} or not is_mpass_id(body["mpass_id"]):
        return None
    return body["mpass_id"]


def unauthorized() -> Response:
    return denial(401, "unauthorized")


def unavailable() -> Response:
    return denial(503, "unavailable")


_REVOKE_RESPONSES = {
    RevocationOutcome.REVOKED: lambda result: adapter_json({"revoked": True, "nostr_pubkey": result.pubkey}),
    RevocationOutcome.NOT_BOUND: lambda result: adapter_json({"revoked": False}),
    RevocationOutcome.UNAVAILABLE: lambda result: unavailable(),
    RevocationOutcome.DISCONNECT_INCOMPLETE: lambda result: unavailable(),
}


class AdminRoutes:
    def __init__(self, admin_token: str, revocation: OwnerRevocation):
        self._admin_token = admin_token
        self.revocation = revocation
        self.router = self._build_router()

    def __repr__(self) -> str:
        return "AdminRoutes(<redacted>)"

    def _build_router(self) -> APIRouter:
        router = APIRouter(prefix=INTERNAL_PREFIX)
        router.add_api_route(REVOKE_ROUTE, self.revoke, methods=["POST"])
        router.add_api_route(PUBKEY_ROUTE, self.pubkey, methods=["GET"])
        return router

    async def revoke(self, request: Request) -> Response:
        """`{"revoked": true, "nostr_pubkey"}` once the key is revoked and every
        relay confirmed the disconnect; `{"revoked": false}` when the user never
        bound a key (their sessions still end). 503 means retry: every step is
        idempotent."""
        if not presents_admin_token(request.headers, self._admin_token):
            logger.warning("nip-fa: owner revoke refused reason=admin_token")
            return unauthorized()
        if "content-encoding" in request.headers:
            return invalid_request()
        try:
            raw = await read_body_within(request, MAX_REVOKE_BODY_BYTES)
        except RequestTooLarge:
            return request_too_large()
        mpass_id = parse_revoke_body(raw)
        if mpass_id is None:
            return invalid_request()
        result = await self.revocation.revoke(mpass_id)
        return _REVOKE_RESPONSES[result.outcome](result)

    async def pubkey(self, request: Request) -> Response:
        """The bound owner pubkey for an mPass ID, read from storage, never
        derived here: 404 until the user has signed in to Buzz once."""
        if not presents_admin_token(request.headers, self._admin_token):
            logger.warning("nip-fa: owner pubkey lookup refused reason=admin_token")
            return unauthorized()
        values = request.query_params.getlist("mpass_id")
        if len(values) != 1 or not is_mpass_id(values[0]) or set(request.query_params) != {"mpass_id"}:
            return invalid_request()
        try:
            identity = await self.revocation.store.identity(values[0])
        except RevocationStoreUnavailable:
            return unavailable()
        if identity is None:
            return denial(404, "identity_not_found")
        return adapter_json({"nostr_pubkey": identity.pubkey, "revoked": identity.revoked})
