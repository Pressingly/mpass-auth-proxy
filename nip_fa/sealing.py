"""At-rest sealing of a session's Cognito refresh token.

The key is derived from the raw session token, which only the client holds;
Redis keys the record by the token's SHA-256. A Valkey dump therefore holds
neither the token nor a usable refresh token."""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_INFO = b"nip-fa/refresh-token/v1"
_NONCE_BYTES = 12


def _derive_key(session_token: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_KEY_INFO)
    return hkdf.derive(session_token.encode("utf-8"))


def seal(session_token: str, plaintext: str) -> str:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_derive_key(session_token)).encrypt(nonce, plaintext.encode("utf-8"), _KEY_INFO)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def unseal(session_token: str, sealed: str) -> str | None:
    """The plaintext, or None when the value was not sealed for this token."""
    try:
        blob = base64.b64decode(sealed, validate=True)
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        plaintext = AESGCM(_derive_key(session_token)).decrypt(nonce, ciphertext, _KEY_INFO)
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError, TypeError):
        return None
