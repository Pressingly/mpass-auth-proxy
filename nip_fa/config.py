"""Buzz adapter configuration, read once from the environment at startup."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .urls import is_canonical_https_origin, is_canonical_relay_url

DEFAULT_SESSION_TTL_SECONDS = 2_592_000
DEFAULT_ASSERTION_TTL_SECONDS = 300
MIN_ASSERTION_TTL_SECONDS = 30
MAX_ASSERTION_TTL_SECONDS = 3600
ASSERTIONS_PATH = "/nip-fa/v1/identity/assertions"
_DEFAULT_MPASS_PROXY_ISSUER_URL = "http://mpass-auth-proxy:8000"

_TRUTHY = {"1", "true", "yes"}
_MASTER_SECRET_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_SALT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){16,64}")
_UNSAFE_URL_CHARACTERS = re.compile(r"[\s\\\x00-\x1f\x7f]")


class AdapterConfigError(RuntimeError):
    """The adapter is enabled but cannot run safely with this configuration."""


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

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "AdapterConfig":
        if not _flag_on(environ.get("BUZZ_ADAPTER_ENABLED", "")):
            return cls(enabled=False)
        _require_launchpad_db(environ)
        return cls(
            enabled=True,
            session_ttl_seconds=_session_ttl(environ),
            identity_master_secret=_master_secret(environ),
            identity_salt=_identity_salt(environ),
            nip_fi_issuer=_nip_fi_issuer(environ),
            relay_urls=_relay_urls(environ),
            assertion_ttl_seconds=_assertion_ttl(environ),
            assertions_url=_public_origin(environ) + ASSERTIONS_PATH,
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
    raw = environ.get("BUZZ_ADAPTER_SESSION_TTL_SECONDS", "").strip()
    if not raw:
        return DEFAULT_SESSION_TTL_SECONDS
    if not raw.isdigit() or int(raw) <= 0:
        raise AdapterConfigError(
            f"BUZZ_ADAPTER_SESSION_TTL_SECONDS must be a positive integer, got {raw!r}"
            " — refusing to start."
        )
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


def _relay_urls(environ: Mapping[str, str]) -> frozenset[str]:
    entries = [entry.strip() for entry in environ.get("BUZZ_RELAY_URLS", "").split(",")]
    if entries == [""]:
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
    return frozenset(entries)


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
