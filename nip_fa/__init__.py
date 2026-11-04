"""Buzz NIP-FA (Federated Identity Adapter) for mpass-auth-proxy.

Buzz desktop signs users in through this adapter, backed by the existing
mPass/Cognito login in main.py. It is mounted only when BUZZ_ADAPTER_ENABLED is
on.

Every public adapter route lives under `/nip-fa/`, so the bundle needs exactly
one `PathPrefix(`/nip-fa/`)` on the `mpass-bridge` Traefik router. A route
outside that prefix would fall through to the oauth2-proxy catch-all and answer
the desktop's non-redirecting HTTP client with a 302.
"""

from .adapter import (
    ROUTE_PREFIX,
    EmailVerificationRequired,
    IdentityUnavailable,
    NipFaAdapter,
    PlatformGateway,
)
from .config import AdapterConfig, AdapterConfigError
from .sessions import IdpUnavailable

__all__ = [
    "ROUTE_PREFIX",
    "AdapterConfig",
    "AdapterConfigError",
    "EmailVerificationRequired",
    "IdentityUnavailable",
    "IdpUnavailable",
    "NipFaAdapter",
    "PlatformGateway",
]
