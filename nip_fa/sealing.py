"""At-rest sealing of Cognito refresh tokens held in Redis.

The key is derived from a high-entropy secret only the client holds (the
session token, or the single-use login code) and Redis keys each record by that
secret's SHA-256. A Valkey dump therefore holds neither the secret nor a usable
refresh token. Each record kind seals under its own label, so a value sealed
for one cannot be opened as the other."""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_REFRESH_TOKEN = b"nip-fa/refresh-token/v1"
LOGIN_CODE_REFRESH_TOKEN = b"nip-fa/login-code/v1"
_NONCE_BYTES = 12


def _derive_key(secret: str, label: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label)
    return hkdf.derive(secret.encode("utf-8"))


def seal(secret: str, plaintext: str, label: bytes) -> str:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_derive_key(secret, label)).encrypt(nonce, plaintext.encode("utf-8"), label)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def unseal(secret: str, sealed: str, label: bytes) -> str | None:
    """The plaintext, or None when the value was not sealed for this secret and label."""
    try:
        blob = base64.b64decode(sealed, validate=True)
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        plaintext = AESGCM(_derive_key(secret, label)).decrypt(nonce, ciphertext, label)
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError, TypeError):
        return None
