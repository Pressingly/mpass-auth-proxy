"""At-rest sealing of the adapter's Redis records.

A whole record (identity, timestamps, Cognito refresh token) is sealed with
AES-GCM under a key derived from two things: the high-entropy secret only the
client holds (the session token, or the single-use login code), and a salt
derived from BUZZ_IDENTITY_MASTER_SECRET. Redis keys each record by that client
secret's SHA-256, so a Valkey dump holds neither input. Writing Valkey is not
enough to forge a session either: sealing a record for a token the attacker
invents still needs the master secret, and the custodial Nostr key is derived
from the identity inside that record.

Each record kind seals under its own label, used as both HKDF info and AAD, so
a value sealed for one cannot be opened as the other."""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_RECORD = b"nip-fa/session-record/v1"
LOGIN_CODE_RECORD = b"nip-fa/login-code-record/v1"
_RECORD_SEAL_SALT_INFO = b"nip-fa/record-seal-salt/v1"
_NONCE_BYTES = 12


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


class RecordSealer:
    def __init__(self, master_secret: bytes):
        self._salt = _hkdf(master_secret, None, _RECORD_SEAL_SALT_INFO)

    def __repr__(self) -> str:
        return "RecordSealer(<redacted>)"

    def _key(self, client_secret: str, label: bytes) -> bytes:
        return _hkdf(client_secret.encode("utf-8"), self._salt, label)

    def seal(self, client_secret: str, record: dict, label: bytes) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        plaintext = json.dumps(record).encode("utf-8")
        ciphertext = AESGCM(self._key(client_secret, label)).encrypt(nonce, plaintext, label)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def unseal(self, client_secret: str, sealed: str, label: bytes) -> dict | None:
        """The record, or None when it was not sealed by this deployment for
        this client secret and label."""
        try:
            blob = base64.b64decode(sealed, validate=True)
            nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
            plaintext = AESGCM(self._key(client_secret, label)).decrypt(nonce, ciphertext, label)
            record = json.loads(plaintext)
        except (InvalidTag, ValueError, TypeError):
            return None
        return record if isinstance(record, dict) else None
