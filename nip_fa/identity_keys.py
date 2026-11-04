"""Custodial Nostr keys, derived from the mPass ID so one account has the same
key on every device.

    secret = HKDF-SHA256(ikm=master secret, salt=identity salt,
                         info=b"moneta-buzz/nostr-key/v1|" + mpass_id, length=32)

The issuer URL is deliberately not part of `info`: a domain change must not
re-key every user, and the per-deployment master secret already keeps
deployments apart."""

from typing import NamedTuple

from coincurve import PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_INFO_PREFIX = b"moneta-buzz/nostr-key/v1|"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_MAX_DERIVATION_ATTEMPTS = 256


class KeyDerivationError(Exception):
    """No valid secp256k1 scalar came out of any derivation attempt."""


class NostrKeypair(NamedTuple):
    secret_key_hex: str
    pubkey_hex: str

    def __repr__(self) -> str:
        return f"NostrKeypair(pubkey_hex={self.pubkey_hex!r}, secret_key_hex=<redacted>)"


def _derivation_info(mpass_id: str, attempt: int) -> bytes:
    counter = bytes([attempt]) if attempt else b""
    return KEY_INFO_PREFIX + mpass_id.encode("utf-8") + counter


def hkdf_candidate(master_secret: bytes, salt: bytes, mpass_id: str, attempt: int) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_derivation_info(mpass_id, attempt))
    return hkdf.derive(master_secret)


def is_valid_scalar(candidate: bytes) -> bool:
    return 1 <= int.from_bytes(candidate, "big") < SECP256K1_ORDER


def derive_secret_key(master_secret: bytes, salt: bytes, mpass_id: str) -> bytes:
    """The first valid scalar, trying the plain derivation and then the same
    `info` with a counter byte appended (deterministic either way)."""
    for attempt in range(_MAX_DERIVATION_ATTEMPTS):
        candidate = hkdf_candidate(master_secret, salt, mpass_id, attempt)
        if is_valid_scalar(candidate):
            return candidate
    raise KeyDerivationError(f"no valid secp256k1 scalar for mpass_id={mpass_id}")


def xonly_pubkey_hex(secret_key: bytes) -> str:
    return PrivateKey(secret_key).public_key_xonly.format().hex()


def derive_keypair(master_secret: bytes, salt: bytes, mpass_id: str) -> NostrKeypair:
    secret_key = derive_secret_key(master_secret, salt, mpass_id)
    return NostrKeypair(secret_key_hex=secret_key.hex(), pubkey_hex=xonly_pubkey_hex(secret_key))
