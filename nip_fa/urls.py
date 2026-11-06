"""Canonical URL forms the adapter configures and compares exactly: NIP-FA
relay URLs, their NIP-FI audiences, and the adapter's public origin."""

import ipaddress
import re

RELAY_SCHEME = "wss://"
DEFAULT_RELAY_PORT = 443
UNSUPPORTED_RELAY_PORT = 80

_AUTHORITY_PATTERN = re.compile(r"(?P<host>\[[^\]]*\]|[^:\[\]]+)(?::(?P<port>[^:]*))?")
_PORT_PATTERN = re.compile(r"[1-9][0-9]{0,4}")
_DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_HOST_PATTERN = re.compile(r"[0-9.]+")
_MAX_DNS_NAME_LENGTH = 253


def is_canonical_relay_url(url: str) -> bool:
    """`wss://host[:port]` exactly as NIP-FA "Relay assertion" defines it."""
    if not url.startswith(RELAY_SCHEME):
        return False
    return _is_canonical_authority(relay_authority(url), DEFAULT_RELAY_PORT, UNSUPPORTED_RELAY_PORT)


def relay_authority(relay_url: str) -> str:
    return relay_url[len(RELAY_SCHEME):]


def relay_audience(relay_url: str) -> str:
    """NIP-FA: `https://` followed by the canonical relay authority, unchanged."""
    return "https://" + relay_authority(relay_url)


def is_canonical_https_origin(origin: str) -> bool:
    """`https://host[:port]` in the same canonical form as a relay URL."""
    prefix = "https://"
    if not origin.startswith(prefix):
        return False
    return _is_canonical_authority(origin[len(prefix):], 443, None)


def is_internal_http_origin(origin: str) -> bool:
    """`http://host[:port]` or `https://host[:port]`, canonical, for a relay's
    in-cluster address. The port is always allowed because services listen on
    non-default ports internally."""
    for scheme, default_port in (("http://", 80), ("https://", 443)):
        if origin.startswith(scheme):
            return _is_canonical_authority(origin[len(scheme):], default_port, None)
    return False


def _is_canonical_authority(authority: str, default_port: int, refused_port: int | None) -> bool:
    match = _AUTHORITY_PATTERN.fullmatch(authority)
    if match is None:
        return False
    port = match.group("port")
    if port is not None and not _is_allowed_port(port, default_port, refused_port):
        return False
    return _is_canonical_host(match.group("host"))


def _is_allowed_port(port: str, default_port: int, refused_port: int | None) -> bool:
    if not _PORT_PATTERN.fullmatch(port):
        return False
    number = int(port)
    return number <= 65535 and number not in (default_port, refused_port)


def _is_canonical_host(host: str) -> bool:
    if host.startswith("["):
        return _is_canonical_ipv6_literal(host[1:-1])
    if _NUMERIC_HOST_PATTERN.fullmatch(host):
        return _is_canonical_ipv4(host)
    return _is_canonical_dns_name(host)


def _is_canonical_ipv6_literal(text: str) -> bool:
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return address.scope_id is None and str(address) == text


def _is_canonical_ipv4(text: str) -> bool:
    try:
        return str(ipaddress.IPv4Address(text)) == text
    except ValueError:
        return False


def _is_canonical_dns_name(host: str) -> bool:
    if len(host) > _MAX_DNS_NAME_LENGTH:
        return False
    labels = host.split(".")
    if _NUMERIC_HOST_PATTERN.fullmatch(labels[-1]):
        return False
    return all(_DNS_LABEL_PATTERN.fullmatch(label) for label in labels)
