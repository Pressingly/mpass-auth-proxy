"""NIP-FA "Agent keys" request bodies and grant credentials, per block/buzz
docs/nips/NIP-FA.md at b14899f.

The agent grant is an RFC 8693 token exchange with exactly six form fields;
the revocation form has exactly one. Both are parsed strictly: a field that is
missing, repeated, unknown or not exactly the expected value refuses the form.
A grant is an opaque random token; only its SHA-256 is ever stored.

The current buzz-app desktop (block/buzz-app 9c94152,
src-tauri/src/federated_identity/agent/mod.rs) still enrolls in its older
Builderlab dialect: `urn:builderlab:` token types, a seventh `runtime=local`
field, and the NIP-98 proof in `Nostr-Agent-Proof`. LEGACY_DIALECT accepts
exactly that and nothing looser; every check after parsing is shared."""

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import parse_qsl

TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SESSION_TOKEN_TYPE = "urn:nostr:params:oauth:token-type:nip-fa-session"
AGENT_GRANT_TOKEN_TYPE = "urn:nostr:params:oauth:token-type:nip-fi-agent-grant"
GRANT_TOKEN_TYPE_NA = "N_A"
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
MAX_AGENT_GRANT_BODY_BYTES = 8192
MAX_AGENT_REVOKE_BODY_BYTES = 1024

LEGACY_SESSION_TOKEN_TYPE = "urn:builderlab:params:oauth:token-type:bb-session"
LEGACY_AGENT_GRANT_TOKEN_TYPE = "urn:builderlab:params:oauth:token-type:nip-fi-agent-grant"
LEGACY_RUNTIME = "local"
_VARIABLE_GRANT_FIELDS = frozenset({"subject_token", "agent_pubkey", "owner_attestation"})


@dataclass(frozen=True)
class GrantDialect:
    """One accepted shape of the agent grant exchange: the header carrying
    the NIP-98 proof, the fields that must hold exactly these values, and the
    token type the response names."""

    name: str
    proof_header: str
    fixed_fields: Mapping[str, str]
    issued_token_type: str

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(self.fixed_fields) | _VARIABLE_GRANT_FIELDS


SPEC_DIALECT = GrantDialect(
    name="nip-fa",
    proof_header="nostr-authorization",
    fixed_fields=MappingProxyType({
        "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token_type": SESSION_TOKEN_TYPE,
        "requested_token_type": AGENT_GRANT_TOKEN_TYPE,
    }),
    issued_token_type=AGENT_GRANT_TOKEN_TYPE,
)
LEGACY_DIALECT = GrantDialect(
    name="buzz-app-legacy",
    proof_header="nostr-agent-proof",
    fixed_fields=MappingProxyType({
        "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token_type": LEGACY_SESSION_TOKEN_TYPE,
        "requested_token_type": LEGACY_AGENT_GRANT_TOKEN_TYPE,
        "runtime": LEGACY_RUNTIME,
    }),
    issued_token_type=LEGACY_AGENT_GRANT_TOKEN_TYPE,
)
REVOKE_FIELDS = frozenset({"agent_pubkey"})

_PUBKEY_PATTERN = re.compile(r"[0-9a-f]{64}")
_GRANT_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


@dataclass(frozen=True)
class AgentGrantRequest:
    subject_token: str
    agent_pubkey: str
    owner_attestation: str

    def __repr__(self) -> str:
        return f"AgentGrantRequest(agent_pubkey={self.agent_pubkey!r}, <credentials redacted>)"


def parse_form(raw: bytes, fields: frozenset[str]) -> dict[str, str] | None:
    """The form's fields when it carries exactly `fields`, each once, as valid
    UTF-8 after percent-decoding; otherwise None."""
    try:
        pairs = parse_qsl(
            raw.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            errors="strict",
            max_num_fields=len(fields),
        )
    except (UnicodeDecodeError, ValueError):
        return None
    form = dict(pairs)
    if len(form) != len(pairs) or set(form) != fields:
        return None
    return form


def is_pubkey(value: str) -> bool:
    return bool(_PUBKEY_PATTERN.fullmatch(value))


def parse_agent_grant_form(raw: bytes, dialect: GrantDialect = SPEC_DIALECT) -> AgentGrantRequest | None:
    form = parse_form(raw, dialect.fields)
    if form is None or any(form[name] != value for name, value in dialect.fixed_fields.items()):
        return None
    if not form["subject_token"] or not is_pubkey(form["agent_pubkey"]):
        return None
    return AgentGrantRequest(
        subject_token=form["subject_token"],
        agent_pubkey=form["agent_pubkey"],
        owner_attestation=form["owner_attestation"],
    )


def parse_agent_revoke_form(raw: bytes) -> str | None:
    """The agent pubkey to revoke, or None for any other form."""
    form = parse_form(raw, REVOKE_FIELDS)
    if form is None or not is_pubkey(form["agent_pubkey"]):
        return None
    return form["agent_pubkey"]


def new_grant_token() -> str:
    return secrets.token_urlsafe(32)


def is_grant_token(value: str) -> bool:
    """Shaped like a token new_grant_token issues, so anything else is
    refused without a database lookup."""
    return bool(_GRANT_TOKEN_PATTERN.fullmatch(value))


def grant_hash(grant_token: str) -> str:
    return hashlib.sha256(grant_token.encode("utf-8")).hexdigest()


def grant_response(
    grant_token: str,
    expires_in: int,
    owner_pubkey: str,
    issuer: str,
    issued_token_type: str = AGENT_GRANT_TOKEN_TYPE,
) -> dict:
    """RFC 8693 section 2.2.1, plus the two NIP-FA fields. The issued type is
    the one the request asked for, which the client checks."""
    return {
        "access_token": grant_token,
        "issued_token_type": issued_token_type,
        "token_type": GRANT_TOKEN_TYPE_NA,
        "expires_in": expires_in,
        "nostr_owner_pubkey": owner_pubkey,
        "nip_fi_issuer": issuer,
    }
