"""NIP-OA owner attestation: the `auth` tag by which an owner key authorizes an
agent key, as sent in a NIP-FA agent grant's `owner_attestation` field.

    preimage = "nostr:agent-auth:" + agent_pubkey + ":" + conditions
    sig      = BIP-340 Schnorr over SHA-256(preimage), by the owner key

Parsing and signature checks follow NIP-OA exactly. Which condition clauses an
adapter accepts is a separate policy (NIP-FA: accept empty conditions, refuse
any clause the adapter does not support), applied by `verified_owner`."""

import hashlib
import re
from dataclasses import dataclass

from coincurve import PublicKeyXOnly

from .bodies import strict_json_loads

TAG_NAME = "auth"
DOMAIN_SEPARATOR = "nostr:agent-auth:"
NO_SUPPORTED_CLAUSES: frozenset[str] = frozenset()

_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}")
_CLAUSE_PATTERN = re.compile(r"(?P<name>kind=|created_at<|created_at>)(?P<value>0|[1-9][0-9]{0,9})")
_CLAUSE_MAXIMUMS = {"kind=": 65535, "created_at<": 4_294_967_295, "created_at>": 4_294_967_295}


@dataclass(frozen=True)
class OwnerAttestation:
    owner_pubkey: str
    conditions: str
    signature: str


def parse_owner_attestation(raw: str) -> OwnerAttestation | None:
    """The tag in `raw` (the compact JSON array of its four strings), or None
    when it is not a well-formed NIP-OA `auth` tag."""
    try:
        tag = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    return attestation_from_tag(tag)


def attestation_from_tag(tag: object) -> OwnerAttestation | None:
    if not isinstance(tag, list) or len(tag) != 4 or not all(isinstance(item, str) for item in tag):
        return None
    name, owner, conditions, signature = tag
    if name != TAG_NAME or not _KEY_PATTERN.fullmatch(owner) or not _SIGNATURE_PATTERN.fullmatch(signature):
        return None
    if condition_clauses(conditions) is None:
        return None
    return OwnerAttestation(owner_pubkey=owner, conditions=conditions, signature=signature)


def condition_clauses(conditions: str) -> tuple[str, ...] | None:
    """The clause names in `conditions`, in order, or None when the string is
    malformed under NIP-OA. The empty string has no clauses."""
    if conditions == "":
        return ()
    names = []
    for clause in conditions.split("&"):
        match = _CLAUSE_PATTERN.fullmatch(clause)
        if match is None or int(match.group("value")) > _CLAUSE_MAXIMUMS[match.group("name")]:
            return None
        names.append(match.group("name"))
    return tuple(names)


def signing_digest(agent_pubkey: str, conditions: str) -> bytes:
    return hashlib.sha256((DOMAIN_SEPARATOR + agent_pubkey + ":" + conditions).encode("utf-8")).digest()


def is_signed_for(attestation: OwnerAttestation, agent_pubkey: str) -> bool:
    """The owner's signature authorizes `agent_pubkey`, and the owner is not
    the agent itself (self-attestation is invalid)."""
    if attestation.owner_pubkey == agent_pubkey:
        return False
    try:
        owner_key = PublicKeyXOnly(bytes.fromhex(attestation.owner_pubkey))
        digest = signing_digest(agent_pubkey, attestation.conditions)
        return owner_key.verify(bytes.fromhex(attestation.signature), digest)
    except ValueError:
        return False


def verified_owner(raw: str, agent_pubkey: str, supported_clauses: frozenset[str] = NO_SUPPORTED_CLAUSES) -> str | None:
    """The owner pubkey `raw` attests for `agent_pubkey`, or None when the tag
    is malformed, carries a clause outside `supported_clauses`, or is not
    validly signed for this agent."""
    attestation = parse_owner_attestation(raw)
    if attestation is None:
        return None
    if not set(condition_clauses(attestation.conditions)) <= supported_clauses:
        return None
    return attestation.owner_pubkey if is_signed_for(attestation, agent_pubkey) else None
