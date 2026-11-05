"""NIP-FA "Agent keys" routes (block/buzz docs/nips/NIP-FA.md at b14899f):
agent grant, agent assertion and agent revocation.

Credentials are never logged: not the session token, the grant, the owner
attestation or any header value. mPass IDs and public keys are."""

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response

from .agent_grants import (
    FORM_CONTENT_TYPE,
    LEGACY_DIALECT,
    MAX_AGENT_GRANT_BODY_BYTES,
    MAX_AGENT_REVOKE_BODY_BYTES,
    SPEC_DIALECT,
    AgentGrantRequest,
    GrantDialect,
    grant_hash,
    grant_response,
    is_grant_token,
    new_grant_token,
    parse_agent_grant_form,
    parse_agent_revoke_form,
)
from .agents import AgentStore, AgentStoreUnavailable, Enrollment, EnrollmentRequest, Revocation, StoredGrant
from .assertions import (
    AGENT_ASSERTION_TYP,
    MAX_ASSERTION_BODY_BYTES,
    AssertionRateLimiter,
    AssertionRequest,
    RateLimiterUnavailable,
    SigningKey,
    agent_assertion_claims,
    assertion_expiry,
    parse_assertion_body,
    sign_assertion,
)
from .bodies import RequestTooLarge, read_body_within
from .config import AdapterConfig, AgentConfig
from .identities import IdentityKeyService, KeyIssuanceStatus
from .nip98 import ExpectedRequest, ProofFailure, VerifiedProof, verify_http_auth
from .owner_attestation import verified_owner
from .proof_replay import ProofReplayGuard, ReplayGuardUnavailable
from .relay_commands import RelayDisconnector
from .responses import (
    adapter_json,
    agent_not_found,
    agent_unsupported,
    authorization_denied,
    invalid_grant,
    invalid_proof,
    invalid_request,
    issuance_unavailable,
    rate_limited,
    request_too_large,
)
from .sessions import Identity, LookupStatus, Revalidation, SessionLookup, SessionService
from .urls import relay_authority

logger = logging.getLogger(__name__)

AGENT_GRANT_RATE_LIMIT = 10
AGENT_ASSERTION_RATE_LIMIT = 30
AGENT_REVOKE_RATE_LIMIT = 10
AGENT_RATE_WINDOW_SECONDS = 60

Authenticate = Callable[[Headers], Awaitable[tuple[SessionLookup | None, Response | None]]]


@dataclass(frozen=True)
class _ProvenBody:
    raw: bytes
    proof: str

    def __repr__(self) -> str:
        return "_ProvenBody(<redacted>)"


def _single_header(headers: Headers, name: str) -> str | None:
    values = headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _media_type(headers: Headers) -> str:
    return headers.get("content-type", "").partition(";")[0].strip().lower()


def _grant_header_violation(headers: Headers) -> bool:
    """NIP-FA "Agent grant": the session travels only as `subject_token`."""
    return (
        "authorization" in headers
        or "cookie" in headers
        or "content-encoding" in headers
        or _media_type(headers) != FORM_CONTENT_TYPE
    )


def _carries_both_proof_headers(headers: Headers) -> bool:
    return SPEC_DIALECT.proof_header in headers and LEGACY_DIALECT.proof_header in headers


async def _read_proven_body(
    request: Request, limit: int, proof_header: str = SPEC_DIALECT.proof_header
) -> _ProvenBody | Response:
    proof = _single_header(request.headers, proof_header)
    if proof is None or "content-encoding" in request.headers:
        return invalid_request()
    try:
        raw = await read_body_within(request, limit)
    except RequestTooLarge:
        return request_too_large()
    return _ProvenBody(raw=raw, proof=proof)


def _grant_bearer(headers: Headers) -> tuple[str | None, Response | None]:
    """The agent grant from `Authorization: Bearer`. A missing grant is 401
    `invalid_grant`; a header that is not exactly one Bearer is 400."""
    values = headers.getlist("authorization")
    if not values:
        return None, invalid_grant(401)
    scheme, _, token = values[0].partition(" ")
    if len(values) > 1 or scheme.lower() != "bearer":
        return None, invalid_request()
    token = token.strip()
    return (token, None) if token else (None, invalid_grant(401))


def _proof_signer(proof: str, url: str, raw: bytes, now: int) -> VerifiedProof | ProofFailure:
    return verify_http_auth(proof, ExpectedRequest(url=url, method="POST", body=raw), now)


def grant_refusal_reason(grant: StoredGrant | None, now: int) -> str | None:
    if grant is None:
        return "unknown_grant"
    if grant.revoked:
        return "agent_revoked"
    if grant.owner_revoked:
        return "owner_revoked"
    if not grant.usable_at(now):
        return "grant_expired"
    return None


_ENROLLMENT_REFUSALS: dict[Enrollment, Callable[[], Response]] = {
    Enrollment.OWNER_REFUSED: invalid_request,
    Enrollment.AGENT_REFUSED: lambda: invalid_grant(400),
    Enrollment.CAP_REACHED: lambda: rate_limited(None),
}


class AgentRoutes:
    def __init__(
        self,
        config: AdapterConfig,
        sessions: SessionService,
        authenticate: Authenticate,
        identity_keys: IdentityKeyService,
        store: AgentStore,
        disconnector: RelayDisconnector | None,
        redis_factory,
        signing_key: Callable[[], SigningKey],
    ):
        self._config = config
        self._agents: AgentConfig | None = config.agents
        self._sessions = sessions
        self._authenticate = authenticate
        self.identity_keys = identity_keys
        self.store = store
        self.disconnector = disconnector
        self._signing_key = signing_key
        self._grant_proofs = ProofReplayGuard(redis_factory, "agent-grant")
        self._assertion_proofs = ProofReplayGuard(redis_factory, "agent-assertion")
        self.grant_rate_limiter = AssertionRateLimiter(
            redis_factory, AGENT_GRANT_RATE_LIMIT, AGENT_RATE_WINDOW_SECONDS, "nip_fa_agent_grant_rate:"
        )
        self.assertion_rate_limiter = AssertionRateLimiter(
            redis_factory, AGENT_ASSERTION_RATE_LIMIT, AGENT_RATE_WINDOW_SECONDS, "nip_fa_agent_assertion_rate:"
        )
        self.revoke_rate_limiter = AssertionRateLimiter(
            redis_factory, AGENT_REVOKE_RATE_LIMIT, AGENT_RATE_WINDOW_SECONDS, "nip_fa_agent_revoke_rate:"
        )

    async def issue_grant(self, request: Request) -> Response:
        """Authenticate the owner (session, then the agent key's NIP-98 proof)
        before authorizing (owner key, attestation, enrollment)."""
        if self._agents is None:
            return agent_unsupported()
        if _grant_header_violation(request.headers):
            return invalid_request()
        dialect = self._grant_dialect(request.headers)
        if dialect is None:
            return invalid_request()
        body = await _read_proven_body(request, MAX_AGENT_GRANT_BODY_BYTES, dialect.proof_header)
        if isinstance(body, Response):
            return body
        form = parse_agent_grant_form(body.raw, dialect)
        if form is None:
            return invalid_request()
        session_or_denial = await self._owner_session(form.subject_token)
        if isinstance(session_or_denial, Response):
            return session_or_denial
        identity, now = session_or_denial
        denial = await self._proof_denial(identity, body, form.agent_pubkey, self._agents.grant_url, now)
        if denial is not None:
            return denial
        return await self._enroll(identity, form, now, dialect)

    def _grant_dialect(self, headers: Headers) -> GrantDialect | None:
        """The dialect the proof header names. A request carrying both proof
        headers, or the legacy one while legacy clients are off, is refused,
        so no request can mix the two forms."""
        if _carries_both_proof_headers(headers):
            logger.warning("nip-fa: agent grant refused reason=both_proof_headers")
            return None
        if LEGACY_DIALECT.proof_header not in headers:
            return SPEC_DIALECT
        if not self._agents.accept_legacy_client:
            logger.warning("nip-fa: agent grant refused reason=legacy_client_disabled")
            return None
        return LEGACY_DIALECT

    async def _owner_session(self, subject_token: str) -> tuple[Identity, int] | Response:
        lookup = await self._sessions.lookup(subject_token)
        if lookup.status is not LookupStatus.FOUND:
            logger.warning("nip-fa: agent grant refused reason=session_%s", lookup.status.value)
            return invalid_request()
        identity = lookup.session.identity
        if lookup.revalidation is Revalidation.UNAVAILABLE:
            return issuance_unavailable()
        denial = await self._rate_limit_denial(self.grant_rate_limiter, lookup.record_key, identity.sub)
        if denial is not None:
            return denial
        now = self._sessions.now()
        if lookup.session.expired_at(now):
            return invalid_request()
        return identity, now

    async def _proof_denial(
        self, identity: Identity, body: _ProvenBody, agent_pubkey: str, url: str, now: int
    ) -> Response | None:
        result = _proof_signer(body.proof, url, body.raw, now)
        if isinstance(result, ProofFailure) or result.pubkey != agent_pubkey:
            reason = result.value if isinstance(result, ProofFailure) else "signer_is_not_agent_pubkey"
            logger.warning(
                "nip-fa: agent grant refused mpass_id=%s agent=%s reason=invalid_proof detail=%s",
                identity.sub, agent_pubkey, reason,
            )
            return invalid_request()
        return await self._replay_denial(self._grant_proofs, result.event_id, identity.sub)

    async def _replay_denial(self, guard: ProofReplayGuard, event_id: str, actor: str) -> Response | None:
        try:
            first_use = await guard.first_use(event_id)
        except ReplayGuardUnavailable:
            logger.error("nip-fa: proof replay guard unavailable actor=%s", actor)
            return issuance_unavailable()
        if first_use:
            return None
        logger.warning("nip-fa: agent request refused actor=%s reason=proof_replayed", actor)
        return invalid_request()

    async def _enroll(self, identity: Identity, form: AgentGrantRequest, now: int, dialect: GrantDialect) -> Response:
        issuance = await self.identity_keys.bind(identity)
        if issuance.status is KeyIssuanceStatus.UNAVAILABLE:
            return issuance_unavailable()
        if issuance.status is not KeyIssuanceStatus.ISSUED:
            return invalid_request()
        owner_pubkey = issuance.keypair.pubkey_hex
        if verified_owner(form.owner_attestation, form.agent_pubkey) != owner_pubkey:
            logger.warning(
                "nip-fa: agent grant refused mpass_id=%s agent=%s reason=owner_attestation",
                identity.sub, form.agent_pubkey,
            )
            return invalid_grant(400)
        token = new_grant_token()
        request = EnrollmentRequest(
            owner_sub=identity.sub,
            owner_pubkey=owner_pubkey,
            agent_pubkey=form.agent_pubkey,
            grant_hash=grant_hash(token),
            issued_at=now,
            expires_at=now + self._agents.grant_ttl_seconds,
            max_agents=self._agents.max_agents_per_user,
        )
        try:
            enrollment = await self.store.enroll(request)
        except AgentStoreUnavailable:
            return issuance_unavailable()
        if enrollment is not Enrollment.ENROLLED:
            logger.warning(
                "nip-fa: agent grant refused mpass_id=%s agent=%s reason=%s",
                identity.sub, form.agent_pubkey, enrollment.value,
            )
            return _ENROLLMENT_REFUSALS[enrollment]()
        logger.info(
            "nip-fa: agent grant issued mpass_id=%s agent=%s dialect=%s", identity.sub, form.agent_pubkey, dialect.name
        )
        return adapter_json(
            grant_response(
                token,
                self._agents.grant_ttl_seconds,
                owner_pubkey,
                self._config.nip_fi_issuer,
                dialect.issued_token_type,
            )
        )

    async def issue_assertion(self, request: Request) -> Response:
        """Authenticate (grant, then the agent key's NIP-98 proof) before
        authorizing (requested key, relay allowlist)."""
        if self._agents is None:
            return agent_unsupported()
        token, denial = _grant_bearer(request.headers)
        if denial is not None:
            return denial
        if LEGACY_DIALECT.proof_header in request.headers:
            return invalid_request()
        body = await _read_proven_body(request, MAX_ASSERTION_BODY_BYTES)
        if isinstance(body, Response):
            return body
        assertion_request = parse_assertion_body(body.raw)
        if assertion_request is None:
            return invalid_request()
        now = self._sessions.now()
        grant_or_denial = await self._usable_grant(token, now)
        if isinstance(grant_or_denial, Response):
            return grant_or_denial
        grant, credential_key = grant_or_denial
        denial = await self._rate_limit_denial(self.assertion_rate_limiter, credential_key, grant.agent_pubkey)
        if denial is not None:
            return denial
        denial = await self._assertion_denial(grant, body, assertion_request, now)
        if denial is not None:
            return denial
        return self._agent_assertion(grant, assertion_request.relay_url, now)

    async def _usable_grant(self, token: str, now: int) -> tuple[StoredGrant, str] | Response:
        """`now` is read before the grant, so an assertion signed after a
        concurrent revoke still expires within that revoke's relay deny."""
        if not is_grant_token(token):
            return invalid_grant(401)
        credential_key = grant_hash(token)
        try:
            grant = await self.store.grant(credential_key)
        except AgentStoreUnavailable:
            return issuance_unavailable()
        reason = grant_refusal_reason(grant, now)
        if reason is None:
            return grant, credential_key
        agent = grant.agent_pubkey if grant is not None else "-"
        logger.warning("nip-fa: agent assertion refused agent=%s reason=%s", agent, reason)
        return invalid_grant(401)

    async def _assertion_denial(
        self, grant: StoredGrant, body: _ProvenBody, assertion_request: AssertionRequest, now: int
    ) -> Response | None:
        result = _proof_signer(body.proof, self._agents.assertion_url, body.raw, now)
        if isinstance(result, ProofFailure) or result.pubkey != assertion_request.nostr_pubkey:
            reason = result.value if isinstance(result, ProofFailure) else "signer_is_not_nostr_pubkey"
            logger.warning(
                "nip-fa: agent assertion refused agent=%s reason=invalid_proof detail=%s",
                grant.agent_pubkey, reason,
            )
            return invalid_proof()
        denial = await self._replay_denial(self._assertion_proofs, result.event_id, grant.agent_pubkey)
        if denial is not None:
            return denial
        if assertion_request.nostr_pubkey != grant.agent_pubkey:
            return invalid_request()
        if assertion_request.relay_url not in self._config.relay_urls:
            logger.warning("nip-fa: agent assertion refused agent=%s reason=unknown_relay", grant.agent_pubkey)
            return authorization_denied()
        return None

    def _agent_assertion(self, grant: StoredGrant, relay_url: str, now: int) -> Response:
        expires_at = assertion_expiry(now, self._config.assertion_ttl_seconds, grant.expires_at)
        claims = agent_assertion_claims(
            issuer=self._config.nip_fi_issuer,
            owner_sub=grant.owner_sub,
            relay_url=relay_url,
            agent_pubkey=grant.agent_pubkey,
            owner_pubkey=grant.owner_pubkey,
            issued_at=now,
            expires_at=expires_at,
        )
        assertion = sign_assertion(claims, self._signing_key(), AGENT_ASSERTION_TYP)
        logger.info(
            "nip-fa: agent assertion issued mpass_id=%s agent=%s relay=%s exp=%d",
            grant.owner_sub, grant.agent_pubkey, relay_authority(relay_url), expires_at,
        )
        return adapter_json({"assertion": assertion, "nostr_pubkey": grant.agent_pubkey, "expires_at": expires_at})

    async def revoke(self, request: Request) -> Response:
        """Revocation lowers privilege, so it proceeds even when the owner's
        hourly IdP revalidation could not run."""
        if self._agents is None:
            return agent_unsupported()
        lookup, denial = await self._authenticate(request.headers)
        if denial is not None:
            return denial
        denial = await self._rate_limit_denial(
            self.revoke_rate_limiter, lookup.record_key, lookup.session.identity.sub
        )
        if denial is not None:
            return denial
        agent_pubkey = await self._read_revoke_form(request)
        if isinstance(agent_pubkey, Response):
            return agent_pubkey
        owner_sub = lookup.session.identity.sub
        try:
            revocation = await self.store.revoke(owner_sub, agent_pubkey)
        except AgentStoreUnavailable:
            return issuance_unavailable()
        if revocation is Revocation.NOT_FOUND:
            logger.warning(
                "nip-fa: agent revoke refused mpass_id=%s agent=%s reason=not_found", owner_sub, agent_pubkey
            )
            return agent_not_found()
        logger.info("nip-fa: agent revoked mpass_id=%s agent=%s outcome=%s", owner_sub, agent_pubkey, revocation.value)
        return await self._disconnect(owner_sub, agent_pubkey)

    async def _read_revoke_form(self, request: Request) -> str | Response:
        if "content-encoding" in request.headers:
            return invalid_request()
        try:
            raw = await read_body_within(request, MAX_AGENT_REVOKE_BODY_BYTES)
        except RequestTooLarge:
            return request_too_large()
        agent_pubkey = parse_agent_revoke_form(raw)
        return invalid_request() if agent_pubkey is None else agent_pubkey

    async def _disconnect(self, owner_sub: str, agent_pubkey: str) -> Response:
        """Every revoke, repeated ones included, disconnects again: the relay
        forgets its deny set on restart and a repeat never shortens it, so a
        client retrying after a 503 re-pushes the deny."""
        report = await self.disconnector.disconnect(agent_pubkey)
        if not report.complete:
            logger.error(
                "nip-fa: agent revoked but relay disconnect incomplete mpass_id=%s agent=%s failed=%s",
                owner_sub, agent_pubkey, ",".join(relay_authority(url) for url in report.failed_relays),
            )
            return issuance_unavailable()
        return adapter_json({"revoked": True})

    async def _rate_limit_denial(
        self, limiter: AssertionRateLimiter, credential_key: str, actor: str
    ) -> Response | None:
        try:
            decision = await limiter.check(credential_key)
        except RateLimiterUnavailable:
            logger.error("nip-fa: agent rate limiter unavailable actor=%s", actor)
            return issuance_unavailable()
        if decision.allowed:
            return None
        logger.warning("nip-fa: agent request refused actor=%s reason=rate_limited", actor)
        return rate_limited(decision.retry_after_seconds)
