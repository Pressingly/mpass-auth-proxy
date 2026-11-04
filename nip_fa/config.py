"""Buzz adapter configuration, read once from the environment at startup."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

DEFAULT_SESSION_TTL_SECONDS = 2_592_000

_TRUTHY = {"1", "true", "yes"}
_MASTER_SECRET_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_SALT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}){16,64}")


class AdapterConfigError(RuntimeError):
    """The adapter is enabled but cannot run safely with this configuration."""


@dataclass(frozen=True)
class AdapterConfig:
    enabled: bool
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS
    identity_master_secret: bytes = field(default=b"", repr=False)
    identity_salt: bytes = field(default=b"", repr=False)

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
