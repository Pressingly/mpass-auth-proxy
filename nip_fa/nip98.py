"""NIP-98 HTTP Auth verification for the NIP-FA assertion route.

The proof travels as `Nostr-Authorization: Nostr <base64(event JSON)>`. The
base64 is the standard alphabet with padding (RFC 4648 section 4), as NIP-98
clients emit it; URL-safe or unpadded input is refused rather than guessed at.

Every check is exact: the `u` tag must equal the adapter's public endpoint URL
byte for byte, with none of the trailing-slash folding some relays apply."""

import base64
import binascii
import enum
import hashlib
import hmac
import json
import re
from dataclasses import dataclass

from coincurve import PublicKeyXOnly

from .bodies import strict_json_loads

HTTP_AUTH_KIND = 27235
MAX_AGE_SECONDS = 60
MAX_FUTURE_SECONDS = 5
MAX_HEADER_CHARS = 8192
SCHEME = "nostr"
EVENT_FIELDS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})

_HEX32_PATTERN = re.compile(r"[0-9a-f]{64}")
_HEX64_PATTERN = re.compile(r"[0-9a-f]{128}")
_STANDARD_BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


class ProofFailure(enum.Enum):
    MALFORMED_HEADER = "malformed_header"
    MALFORMED_EVENT = "malformed_event"
    WRONG_KIND = "wrong_kind"
    ID_MISMATCH = "id_mismatch"
    BAD_SIGNATURE = "bad_signature"
    STALE = "stale"
    FUTURE = "future"
    URL_MISMATCH = "url_mismatch"
    METHOD_MISMATCH = "method_mismatch"
    PAYLOAD_MISMATCH = "payload_mismatch"


@dataclass(frozen=True)
class VerifiedProof:
    pubkey: str


@dataclass(frozen=True)
class ExpectedRequest:
    url: str
    method: str
    body: bytes

    def __repr__(self) -> str:
        return f"ExpectedRequest(url={self.url!r}, method={self.method!r})"


def verify_http_auth(header_value: str, expected: ExpectedRequest, now: int) -> VerifiedProof | ProofFailure:
    event = decode_header(header_value)
    if event is None:
        return ProofFailure.MALFORMED_HEADER
    if not is_well_formed_event(event):
        return ProofFailure.MALFORMED_EVENT
    return _first_failure(event, expected, now) or VerifiedProof(event["pubkey"])


def decode_header(header_value: str) -> dict | None:
    if len(header_value) > MAX_HEADER_CHARS:
        return None
    scheme, _, encoded = header_value.partition(" ")
    if scheme.lower() != SCHEME or not _STANDARD_BASE64_PATTERN.fullmatch(encoded):
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
        event = strict_json_loads(raw)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return event if isinstance(event, dict) else None


def is_well_formed_event(event: dict) -> bool:
    return (
        set(event) == EVENT_FIELDS
        and _is_hex(event["id"], _HEX32_PATTERN)
        and _is_hex(event["pubkey"], _HEX32_PATTERN)
        and _is_hex(event["sig"], _HEX64_PATTERN)
        and _is_int(event["created_at"])
        and _is_int(event["kind"])
        and isinstance(event["content"], str)
        and _is_tag_list(event["tags"])
    )


def _is_hex(value: object, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_tag_list(tags: object) -> bool:
    return isinstance(tags, list) and all(
        isinstance(tag, list) and tag and all(isinstance(item, str) for item in tag) for tag in tags
    )


def event_id(event: dict) -> str:
    """NIP-01: sha256 of the compact UTF-8 JSON of [0, pubkey, created_at, kind, tags, content]."""
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _matches_computed_id(event: dict) -> bool:
    try:
        computed = event_id(event)
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(computed, event["id"])


def has_valid_signature(event: dict) -> bool:
    try:
        public_key = PublicKeyXOnly(bytes.fromhex(event["pubkey"]))
        return public_key.verify(bytes.fromhex(event["sig"]), bytes.fromhex(event["id"]))
    except ValueError:
        return False


def single_tag_value(tags: list[list[str]], name: str) -> str | None:
    """The value of the only `name` tag, or None when there is not exactly one
    such tag carrying exactly one value."""
    matches = [tag for tag in tags if tag[0] == name]
    if len(matches) != 1 or len(matches[0]) != 2:
        return None
    return matches[0][1]


def _first_failure(event: dict, expected: ExpectedRequest, now: int) -> ProofFailure | None:
    if event["kind"] != HTTP_AUTH_KIND:
        return ProofFailure.WRONG_KIND
    if not _matches_computed_id(event):
        return ProofFailure.ID_MISMATCH
    if not has_valid_signature(event):
        return ProofFailure.BAD_SIGNATURE
    if event["created_at"] < now - MAX_AGE_SECONDS:
        return ProofFailure.STALE
    if event["created_at"] > now + MAX_FUTURE_SECONDS:
        return ProofFailure.FUTURE
    return _first_tag_failure(event["tags"], expected)


def _first_tag_failure(tags: list[list[str]], expected: ExpectedRequest) -> ProofFailure | None:
    if single_tag_value(tags, "u") != expected.url:
        return ProofFailure.URL_MISMATCH
    if single_tag_value(tags, "method") != expected.method:
        return ProofFailure.METHOD_MISMATCH
    if single_tag_value(tags, "payload") != hashlib.sha256(expected.body).hexdigest():
        return ProofFailure.PAYLOAD_MISMATCH
    return None
