"""Buzz adapter configuration, read once from the environment at startup."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .routes import AGENT_ASSERTION_PATH, AGENT_GRANT_PATH, ASSERTIONS_PATH
from .urls import is_canonical_https_origin, is_canonical_relay_url, is_internal_http_origin, relay_audience

DEFAULT_SESSION_TTL_SECONDS = 2_592_000
DEFAULT_ASSERTION_TTL_SECONDS = 300
MIN_ASSERTION_TTL_SECONDS = 30
MAX_ASSERTION_TTL_SECONDS = 3600
DEFAULT_AGENT_GRANT_TTL_SECONDS = 691_200
DEFAULT_MAX_AGENTS_PER_USER = 5
MAX_COMMAND_PRINCIPAL_BYTES = 2048
_DEFAULT_MPASS_PROXY_ISSUER_URL = "http://mpass-auth-proxy:8000"

_TRUTHY = {"1", "true", "yes"}
_MASTER_SECRET_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_SALT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){16,64}")
_UNSAFE_URL_CHARACTERS = re.compile(r"[\s\\\x00-\x1f\x7f]")


class AdapterConfigError(RuntimeError):
    """The adapter is enabled but cannot run safely with this configuration."""


@dataclass(frozen=True)
class RelayEndpoint:
    """A relay as the adapter addresses it for NIP-FI admin disconnects: its
    public `relay_url`, the `internal_url` its disconnect API is reached on,
    and the `command_audience` the relay accepts on command JWTs."""

    relay_url: str
    internal_url: str
    command_audience: str


@dataclass(frozen=True)
class AgentConfig:
    """NIP-FA agent keys, on only with BUZZ_AGENTS_ENABLED. Without it the
    agent routes answer `403 agent_unsupported`, so turning the adapter on
    never requires the agent settings."""

    grant_url: str
    assertion_url: str
    relays: tuple[RelayEndpoint, ...]
    command_principal: str
    grant_ttl_seconds: int = DEFAULT_AGENT_GRANT_TTL_SECONDS
    max_agents_per_user: int = DEFAULT_MAX_AGENTS_PER_USER


@dataclass(frozen=True)
class AdapterConfig:
    enabled: bool
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS
    identity_master_secret: bytes = field(default=b"", repr=False)
    identity_salt: bytes = field(default=b"", repr=False)
    nip_fi_issuer: str = ""
    relay_urls: frozenset[str] = frozenset()
    assertion_ttl_seconds: int = DEFAULT_ASSERTION_TTL_SECONDS
    assertions_url: str = ""
    agents: AgentConfig | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "AdapterConfig":
        if not _flag_on(environ.get("BUZZ_ADAPTER_ENABLED", "")):
            return cls(enabled=False)
        _require_launchpad_db(environ)
        public_origin = _public_origin(environ)
        relay_urls = _relay_urls(environ)
        return cls(
            enabled=True,
            session_ttl_seconds=_session_ttl(environ),
            identity_master_secret=_master_secret(environ),
            identity_salt=_identity_salt(environ),
            nip_fi_issuer=_nip_fi_issuer(environ),
            relay_urls=frozenset(relay_urls),
            assertion_ttl_seconds=_assertion_ttl(environ),
            assertions_url=public_origin + ASSERTIONS_PATH,
            agents=_agent_config(environ, public_origin, relay_urls),
        )


def _agent_config(environ: Mapping[str, str], public_origin: str, relay_urls: list[str]) -> AgentConfig | None:
    if not _flag_on(environ.get("BUZZ_AGENTS_ENABLED", "")):
        return None
    return AgentConfig(
        grant_url=public_origin + AGENT_GRANT_PATH,
        assertion_url=public_origin + AGENT_ASSERTION_PATH,
        relays=_relays(environ, relay_urls),
        command_principal=_command_principal(environ),
        grant_ttl_seconds=_positive_int(environ, "BUZZ_AGENT_GRANT_TTL_SECONDS", DEFAULT_AGENT_GRANT_TTL_SECONDS),
        max_agents_per_user=_positive_int(environ, "BUZZ_MAX_AGENTS_PER_USER", DEFAULT_MAX_AGENTS_PER_USER),
    )


def _flag_on(raw: str) -> bool:
    return raw.strip().lower() in _TRUTHY


def _master_secret(environ: Mapping[str, str]) -> bytes:
    raw = environ.get("BUZZ_IDENTITY_MASTER_SECRET", "").strip()
    if not raw:
        raise AdapterConfigError(
            "BUZZ_ADAPTER_ENABLED is on but BUZZ_IDENTITY_MASTER_SECRET is empty "
            "— refusing to start. Generate one with `openssl rand -hex 32`."
        )
    if not _MASTER_SECRET_PATTERN.fullmatch(raw):
        raise AdapterConfigError(
            "BUZZ_IDENTITY_MASTER_SECRET must be exactly 64 hex characters "
            "(32 bytes) — refusing to start. The value is not shown here because "
            "it is the root of every custodial Buzz key."
        )
    return bytes.fromhex(raw)


def _identity_salt(environ: Mapping[str, str]) -> bytes:
    raw = environ.get("BUZZ_IDENTITY_SALT", "").strip()
    if not raw:
        raise AdapterConfigError(
            "BUZZ_ADAPTER_ENABLED is on but BUZZ_IDENTITY_SALT is empty "
            "— refusing to start. Generate one with `openssl rand -hex 16`."
        )
    if not _SALT_PATTERN.fullmatch(raw):
        raise AdapterConfigError(
            "BUZZ_IDENTITY_SALT must be hex, 32 to 128 characters (16 to 64 bytes) "
            "— refusing to start. Changing it re-keys every custodial Buzz key."
        )
    return bytes.fromhex(raw)


def _require_launchpad_db(environ: Mapping[str, str]) -> None:
    if not environ.get("LAUNCHPAD_DB_PASSWORD", "").strip():
        raise AdapterConfigError(
            "BUZZ_ADAPTER_ENABLED is on but LAUNCHPAD_DB_PASSWORD is empty "
            "— refusing to start. Buzz identities are bound in the launchpad database."
        )


def _session_ttl(environ: Mapping[str, str]) -> int:
    return _positive_int(environ, "BUZZ_ADAPTER_SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL_SECONDS)


def _positive_int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    if not raw.isdigit() or int(raw) <= 0:
        raise AdapterConfigError(f"{name} must be a positive integer, got {raw!r} — refusing to start.")
    return int(raw)


def _nip_fi_issuer(environ: Mapping[str, str]) -> str:
    raw = environ.get("BUZZ_NIP_FI_ISSUER", "").strip()
    if not raw:
        raise AdapterConfigError(
            "BUZZ_ADAPTER_ENABLED is on but BUZZ_NIP_FI_ISSUER is empty — refusing to start. "
            "Set it to the exact issuer string the Buzz relay's NIP-FI issuer policy names."
        )
    if not _is_issuer_url(raw):
        raise AdapterConfigError(
            f"BUZZ_NIP_FI_ISSUER must be an https URL with no query, fragment, userinfo or "
            f"trailing slash, got {raw!r} — refusing to start."
        )
    proxy_issuer = environ.get("MPASS_PROXY_ISSUER_URL", _DEFAULT_MPASS_PROXY_ISSUER_URL).strip()
    if raw == proxy_issuer:
        raise AdapterConfigError(
            "BUZZ_NIP_FI_ISSUER must differ from MPASS_PROXY_ISSUER_URL — refusing to start. "
            "Both are signed with the same key, so a shared issuer would let a relay and "
            "oauth2-proxy accept each other's tokens on claims alone."
        )
    return raw


def _is_issuer_url(raw: str) -> bool:
    if _UNSAFE_URL_CHARACTERS.search(raw) or not raw.startswith("https://") or raw.endswith("/"):
        return False
    try:
        parts = urlsplit(raw)
    except ValueError:
        return False
    return bool(parts.netloc) and "@" not in parts.netloc and not ("?" in raw or "#" in raw)


def _comma_list(environ: Mapping[str, str], name: str) -> list[str]:
    entries = [entry.strip() for entry in environ.get(name, "").split(",")]
    return [] if entries == [""] else entries


def _relays(environ: Mapping[str, str], relay_urls: list[str]) -> tuple[RelayEndpoint, ...]:
    if len(set(relay_urls)) != len(relay_urls):
        raise AdapterConfigError(
            "BUZZ_AGENTS_ENABLED is on and BUZZ_RELAY_URLS lists a relay twice — refusing to start. "
            "BUZZ_RELAY_INTERNAL_URLS pairs with it by position."
        )
    internal_urls = _internal_urls(environ, len(relay_urls))
    audiences = _command_audiences(environ, relay_urls)
    return tuple(
        RelayEndpoint(relay_url=relay_url, internal_url=internal_url, command_audience=audience)
        for relay_url, internal_url, audience in zip(relay_urls, internal_urls, audiences)
    )


def _relay_urls(environ: Mapping[str, str]) -> list[str]:
    entries = _comma_list(environ, "BUZZ_RELAY_URLS")
    if not entries:
        raise AdapterConfigError(
            "BUZZ_ADAPTER_ENABLED is on but BUZZ_RELAY_URLS is empty — refusing to start. "
            "List the relay URLs this adapter issues assertions for, comma-separated."
        )
    rejected = [entry for entry in entries if not is_canonical_relay_url(entry)]
    if rejected:
        raise AdapterConfigError(
            f"BUZZ_RELAY_URLS entries must be canonical wss://host[:port] relay URLs (lowercase, "
            f"default port omitted, no port 80, no trailing slash, path, query or fragment); "
            f"refusing to start on {rejected!r}. They are compared exactly, never normalised."
        )
    return entries


def _internal_urls(environ: Mapping[str, str], relay_count: int) -> list[str]:
    entries = _comma_list(environ, "BUZZ_RELAY_INTERNAL_URLS")
    if len(entries) != relay_count:
        raise AdapterConfigError(
            f"BUZZ_AGENTS_ENABLED is on, so BUZZ_RELAY_INTERNAL_URLS must list one internal URL per "
            f"BUZZ_RELAY_URLS entry, in the same order ({relay_count} expected, got {len(entries)}) "
            "— refusing to start. The adapter sends NIP-FI admin disconnects there when an agent "
            "is revoked."
        )
    rejected = [entry for entry in entries if not is_internal_http_origin(entry)]
    if rejected:
        raise AdapterConfigError(
            f"BUZZ_RELAY_INTERNAL_URLS entries must be http(s)://host[:port] origins with no path, "
            f"query, fragment, userinfo or trailing slash; refusing to start on {rejected!r}."
        )
    return entries


def _command_audiences(environ: Mapping[str, str], relay_urls: list[str]) -> list[str]:
    entries = _comma_list(environ, "BUZZ_RELAY_COMMAND_AUDIENCES")
    if not entries:
        return [relay_audience(relay_url) for relay_url in relay_urls]
    if len(entries) != len(relay_urls) or not all(_is_issuer_url(entry) for entry in entries):
        raise AdapterConfigError(
            f"BUZZ_RELAY_COMMAND_AUDIENCES, when set, must list one https audience per "
            f"BUZZ_RELAY_URLS entry, in the same order; refusing to start on {entries!r}. Each must "
            "be in that relay's command_audiences for BUZZ_NIP_FI_ISSUER."
        )
    return entries


def _command_principal(environ: Mapping[str, str]) -> str:
    raw = environ.get("BUZZ_COMMAND_PRINCIPAL", "").strip()
    if not raw or _UNSAFE_URL_CHARACTERS.search(raw) or len(raw.encode("utf-8")) > MAX_COMMAND_PRINCIPAL_BYTES:
        raise AdapterConfigError(
            "BUZZ_AGENTS_ENABLED is on but BUZZ_COMMAND_PRINCIPAL is empty, longer than "
            f"{MAX_COMMAND_PRINCIPAL_BYTES} bytes, or contains whitespace or control characters "
            "— refusing to start. Set it to the principal listed in each "
            "relay's authorized_principals for BUZZ_NIP_FI_ISSUER; it is the `sub` of the "
            "disconnect commands sent when an agent is revoked."
        )
    return raw


def _assertion_ttl(environ: Mapping[str, str]) -> int:
    raw = environ.get("BUZZ_ASSERTION_TTL_SECONDS", "").strip()
    if not raw:
        return DEFAULT_ASSERTION_TTL_SECONDS
    if not raw.isdigit() or not MIN_ASSERTION_TTL_SECONDS <= int(raw) <= MAX_ASSERTION_TTL_SECONDS:
        raise AdapterConfigError(
            f"BUZZ_ASSERTION_TTL_SECONDS must be an integer from {MIN_ASSERTION_TTL_SECONDS} to "
            f"{MAX_ASSERTION_TTL_SECONDS}, got {raw!r} — refusing to start."
        )
    return int(raw)


def _public_origin(environ: Mapping[str, str]) -> str:
    """The origin Buzz clients reach this adapter on, for the NIP-98 `u` check.
    Behind Traefik the request URL is the internal one, so it is configured."""
    explicit = environ.get("BUZZ_ADAPTER_PUBLIC_ORIGIN", "").strip()
    origin = explicit or _callback_origin(environ.get("MPASS_CALLBACK_URL", ""))
    if not is_canonical_https_origin(origin):
        source = "BUZZ_ADAPTER_PUBLIC_ORIGIN" if explicit else "the MPASS_CALLBACK_URL origin"
        raise AdapterConfigError(
            f"{source} must be a canonical https://host[:port] origin (lowercase, default port "
            f"omitted, no path or trailing slash), got {origin!r} — refusing to start. "
            "Set BUZZ_ADAPTER_PUBLIC_ORIGIN to the adapter's public origin."
        )
    return origin


def _callback_origin(callback_url: str) -> str:
    try:
        parts = urlsplit(callback_url.strip())
    except ValueError:
        return ""
    return f"{parts.scheme}://{parts.netloc}"
