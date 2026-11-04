"""Pure request validation for the NIP-FA login routes."""

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "[::1]"})
SUPPORTED_CHALLENGE_METHOD = "S256"
EXCHANGE_FIELDS = frozenset({"code", "handoff_secret"})

_PORT_PATTERN = re.compile(r"[1-9][0-9]{0,4}")
_SHA256_B64URL_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_FORBIDDEN_URL_CHARACTERS = re.compile(r"[\s\\\x00-\x1f\x7f]")


@dataclass(frozen=True)
class LoginStart:
    return_to: str
    handoff_challenge: str


@dataclass(frozen=True)
class ExchangeRequest:
    code: str
    handoff_secret: str

    def __repr__(self) -> str:
        return "ExchangeRequest(<redacted>)"


def b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def challenge_matches(handoff_secret: str, handoff_challenge: str) -> bool:
    return hmac.compare_digest(
        b64url_sha256(handoff_secret).encode("ascii"),
        handoff_challenge.encode("ascii"),
    )


def is_loopback_callback(return_to: str) -> bool:
    """RFC 8252 §7.3 loopback redirect: `http`, an exact loopback IP literal,
    an explicit port, no userinfo and no fragment."""
    if _FORBIDDEN_URL_CHARACTERS.search(return_to):
        return False
    if not return_to.startswith("http://"):
        return False
    parts = urlsplit(return_to)
    host, separator, port = parts.netloc.rpartition(":")
    return (
        bool(separator)
        and host in LOOPBACK_HOSTS
        and _is_valid_port(port)
        and "#" not in return_to
    )


def _is_valid_port(port: str) -> bool:
    return bool(_PORT_PATTERN.fullmatch(port)) and int(port) <= 65535


def is_sha256_challenge(value: str) -> bool:
    if not _SHA256_B64URL_PATTERN.fullmatch(value):
        return False
    decoded = base64.urlsafe_b64decode(value + "=")
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value


def parse_login_start(query: list[tuple[str, str]]) -> LoginStart | None:
    values = _single_values(query, ("return_to", "handoff_challenge", "handoff_challenge_method"))
    if values is None:
        return None
    return_to, challenge, method = values
    if method != SUPPORTED_CHALLENGE_METHOD:
        return None
    if not is_loopback_callback(return_to) or not is_sha256_challenge(challenge):
        return None
    return LoginStart(return_to=return_to, handoff_challenge=challenge)


def _single_values(
    query: list[tuple[str, str]], names: tuple[str, ...]
) -> tuple[str, ...] | None:
    found = {name: [value for key, value in query if key == name] for name in names}
    if any(len(values) != 1 for values in found.values()):
        return None
    return tuple(found[name][0] for name in names)


def parse_exchange_body(raw: bytes) -> ExchangeRequest | None:
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(body, dict) or set(body) != EXCHANGE_FIELDS:
        return None
    code, secret = body["code"], body["handoff_secret"]
    if not _is_non_empty_ascii(code) or not _is_non_empty_ascii(secret):
        return None
    return ExchangeRequest(code=code, handoff_secret=secret)


def _is_non_empty_ascii(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value.isascii()


def with_query_params(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = urlencode([*parse_qsl(parts.query, keep_blank_values=True), *params.items()])
    return urlunsplit(parts._replace(query=query))
