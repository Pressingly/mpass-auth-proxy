import base64
import hashlib
import json

import pytest
from coincurve import PrivateKey

from nip_fa import nip98
from nip_fa.nip98 import ExpectedRequest, ProofFailure, VerifiedProof, verify_http_auth
from nip_fa.urls import is_canonical_https_origin, is_canonical_relay_url, relay_audience

OTHER_SECRET = bytes.fromhex("07" * 32)


def pubkey_of(secret: bytes) -> str:
    return PrivateKey(secret).public_key_xonly.format().hex()


def signed_event(secret: bytes, *, tags, created_at, kind=nip98.HTTP_AUTH_KIND, content="") -> dict:
    event = {
        "pubkey": pubkey_of(secret),
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
    }
    event["id"] = nip98.event_id(event)
    event["sig"] = PrivateKey(secret).sign_schnorr(bytes.fromhex(event["id"])).hex()
    return event


def http_auth_tags(body: bytes, url: str, method: str = "POST") -> list[list[str]]:
    return [["u", url], ["method", method], ["payload", hashlib.sha256(body).hexdigest()]]


def encode_proof(event: dict) -> str:
    return "Nostr " + base64.b64encode(json.dumps(event).encode("utf-8")).decode("ascii")


class TestRelayUrls:
    @pytest.mark.parametrize("url", [
        "wss://community.example.com",
        "wss://c.example.com:8443",
        "wss://[2001:db8::1]:8443",
        "wss://[::1]",
        "wss://192.0.2.10",
        "wss://192.0.2.10:7000",
        "wss://xn--bcher-kva.example",
        "wss://localhost:3000",
    ])
    def test_accepts_canonical_relay_urls(self, url):
        assert is_canonical_relay_url(url)

    @pytest.mark.parametrize("url", [
        "ws://community.example.com",
        "WSS://community.example.com",
        "wss://Community.example.com",
        "wss://community.example.com/",
        "wss://community.example.com/relay",
        "wss://community.example.com?x=1",
        "wss://community.example.com#f",
        "wss://community.example.com.",
        "wss://community.example.com:443",
        "wss://community.example.com:80",
        "wss://community.example.com:0",
        "wss://community.example.com:08443",
        "wss://community.example.com:65536",
        "wss://community.example.com:",
        "wss://user@community.example.com",
        "wss://[2001:DB8::1]:8443",
        "wss://[2001:0db8::1]",
        "wss://[2001:db8:0:0:0:0:0:1]",
        "wss://[fe80::1%25eth0]",
        "wss://2001:db8::1",
        "wss://010.0.0.1",
        "wss://192.0.2",
        "wss://example.123",
        "wss://bücher.example",
        "wss://-bad.example.com",
        "wss://exa_mple.com",
        "wss:// community.example.com",
        "wss://",
        "community.example.com",
    ])
    def test_rejects_everything_else(self, url):
        assert not is_canonical_relay_url(url)

    @pytest.mark.parametrize("relay, audience", [
        ("wss://community.example.com", "https://community.example.com"),
        ("wss://c.example.com:8443", "https://c.example.com:8443"),
        ("wss://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ])
    def test_audience_is_https_plus_the_authority_unchanged(self, relay, audience):
        assert relay_audience(relay) == audience

    @pytest.mark.parametrize("origin, valid", [
        ("https://auth.example.com", True),
        ("https://auth.example.com:8443", True),
        ("https://auth.example.com:443", False),
        ("https://auth.example.com/", False),
        ("https://Auth.example.com", False),
        ("http://auth.example.com", False),
    ])
    def test_public_origin_shape(self, origin, valid):
        assert is_canonical_https_origin(origin) is valid


class TestNip98Verifier:
    _URL = "https://auth.example.com/nip-fa/v1/identity/assertions"
    _BODY = b'{"relay_url":"wss://r.example.com","nostr_pubkey":"' + b"a" * 64 + b'"}'
    _NOW = 1_800_000_000

    def _expected(self, body=None):
        return ExpectedRequest(url=self._URL, method="POST", body=body if body is not None else self._BODY)

    def _event(self, **overrides):
        tags = overrides.pop("tags", http_auth_tags(self._BODY, self._URL))
        created_at = overrides.pop("created_at", self._NOW)
        return signed_event(OTHER_SECRET, tags=tags, created_at=created_at, **overrides)

    def _verify(self, header, body=None, now=None):
        return verify_http_auth(header, self._expected(body), now if now is not None else self._NOW)

    def test_known_good_event_verifies(self):
        event = self._event()
        assert self._verify(encode_proof(event)) == VerifiedProof(pubkey_of(OTHER_SECRET), event["id"])

    def test_event_id_is_nip01(self):
        event = {"pubkey": "a" * 64, "created_at": 1, "kind": 27235, "tags": [["u", "é"]], "content": "x\n\"y"}
        serialized = '[0,"' + "a" * 64 + '",1,27235,[["u","é"]],"x\\n\\"y"]'
        assert nip98.event_id(event) == hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @pytest.mark.parametrize("scheme", ["Nostr", "nostr", "NOSTR"])
    def test_scheme_is_case_insensitive(self, scheme):
        header = scheme + encode_proof(self._event())[len("Nostr"):]
        assert isinstance(self._verify(header), VerifiedProof)

    @pytest.mark.parametrize("field, value", [
        ("content", "tampered"),
        ("created_at", _NOW - 1),
        ("kind", 1),
        ("tags", [["u", _URL], ["method", "POST"], ["payload", "0" * 64]]),
    ])
    def test_tampering_a_signed_field_breaks_the_id(self, field, value):
        event = {**self._event(), field: value}
        expected = ProofFailure.WRONG_KIND if field == "kind" else ProofFailure.ID_MISMATCH
        assert self._verify(encode_proof(event)) is expected

    def test_tampered_signature_is_bad_signature(self):
        event = self._event()
        flipped = ("0" if event["sig"][0] != "0" else "1") + event["sig"][1:]
        assert self._verify(encode_proof({**event, "sig": flipped})) is ProofFailure.BAD_SIGNATURE

    def test_swapped_pubkey_with_recomputed_id_is_bad_signature(self):
        event = self._event()
        swapped = {**event, "pubkey": pubkey_of(bytes.fromhex("09" * 32))}
        swapped["id"] = nip98.event_id(swapped)
        assert self._verify(encode_proof(swapped)) is ProofFailure.BAD_SIGNATURE

    def test_pubkey_off_the_curve_is_bad_signature(self):
        event = {**self._event(), "pubkey": "f" * 64}
        event["id"] = nip98.event_id(event)
        assert self._verify(encode_proof(event)) is ProofFailure.BAD_SIGNATURE

    def test_wrong_kind(self):
        assert self._verify(encode_proof(self._event(kind=1))) is ProofFailure.WRONG_KIND

    @pytest.mark.parametrize("age, expected", [
        (0, None), (60, None), (61, ProofFailure.STALE), (-5, None), (-6, ProofFailure.FUTURE),
    ])
    def test_created_at_window(self, age, expected):
        result = self._verify(encode_proof(self._event(created_at=self._NOW - age)))
        assert (result if isinstance(result, ProofFailure) else None) is expected

    @pytest.mark.parametrize("url", [
        "https://auth.example.com/nip-fa/v1/identity/assertions/",
        "https://AUTH.example.com/nip-fa/v1/identity/assertions",
        "http://auth.example.com/nip-fa/v1/identity/assertions",
        "https://auth.example.com/nip-fa/v1/identity/key",
        "http://mpass-auth-proxy:8000/nip-fa/v1/identity/assertions",
    ])
    def test_u_must_match_exactly(self, url):
        tags = http_auth_tags(self._BODY, url)
        assert self._verify(encode_proof(self._event(tags=tags))) is ProofFailure.URL_MISMATCH

    @pytest.mark.parametrize("tags, expected", [
        ([["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest()]], ProofFailure.URL_MISMATCH),
        ([["u", _URL], ["u", _URL], ["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest()]],
         ProofFailure.URL_MISMATCH),
        ([["u", _URL, "extra"], ["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest()]],
         ProofFailure.URL_MISMATCH),
        ([["u", _URL], ["payload", hashlib.sha256(_BODY).hexdigest()]], ProofFailure.METHOD_MISMATCH),
        ([["u", _URL], ["method", "GET"], ["payload", hashlib.sha256(_BODY).hexdigest()]],
         ProofFailure.METHOD_MISMATCH),
        ([["u", _URL], ["method", "post"], ["payload", hashlib.sha256(_BODY).hexdigest()]],
         ProofFailure.METHOD_MISMATCH),
        ([["u", _URL], ["method", "POST"], ["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest()]],
         ProofFailure.METHOD_MISMATCH),
        ([["u", _URL], ["method", "POST"]], ProofFailure.PAYLOAD_MISMATCH),
        ([["u", _URL], ["method", "POST"], ["payload", "0" * 64]], ProofFailure.PAYLOAD_MISMATCH),
        ([["u", _URL], ["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest().upper()]],
         ProofFailure.PAYLOAD_MISMATCH),
        ([["u", _URL], ["method", "POST"], ["payload", hashlib.sha256(_BODY).hexdigest()],
          ["payload", hashlib.sha256(_BODY).hexdigest()]], ProofFailure.PAYLOAD_MISMATCH),
    ])
    def test_tag_cardinality_and_values(self, tags, expected):
        assert self._verify(encode_proof(self._event(tags=tags))) is expected

    def test_payload_binds_the_exact_body_bytes(self):
        header = encode_proof(self._event())
        reformatted = json.dumps(json.loads(self._BODY), indent=1).encode("utf-8")
        assert self._verify(header, body=reformatted) is ProofFailure.PAYLOAD_MISMATCH

    def test_url_safe_base64_is_refused(self):
        event = self._event(content="?>?>" * 4)
        raw = json.dumps(event).encode("utf-8")
        assert base64.b64encode(raw) != base64.urlsafe_b64encode(raw)
        header = "Nostr " + base64.urlsafe_b64encode(raw).decode("ascii")
        assert self._verify(header) is ProofFailure.MALFORMED_HEADER

    def test_unpadded_base64_is_refused(self):
        event = self._event()
        encoded = base64.b64encode(json.dumps(event).encode("utf-8")).decode("ascii")
        while not encoded.endswith("="):
            event = {**event, "content": event["content"] + "x"}
            event["id"] = nip98.event_id(event)
            encoded = base64.b64encode(json.dumps(event).encode("utf-8")).decode("ascii")
        assert self._verify("Nostr " + encoded.rstrip("=")) is ProofFailure.MALFORMED_HEADER

    @pytest.mark.parametrize("header", [
        "",
        "Nostr",
        "Nostr ",
        "Bearer abc",
        "Nostr not-base64!",
        "Nostr " + base64.b64encode(b"not json").decode(),
        "Nostr " + base64.b64encode(b"[1,2]").decode(),
        "Nostr " + base64.b64encode(b"\xff\xfe").decode(),
    ])
    def test_malformed_headers(self, header):
        assert self._verify(header) is ProofFailure.MALFORMED_HEADER

    def test_header_size_is_bounded_before_decoding(self):
        event = self._event(content="x" * nip98.MAX_HEADER_CHARS)
        assert self._verify(encode_proof(event)) is ProofFailure.MALFORMED_HEADER

    def test_deeply_nested_json_is_a_failure_not_a_crash(self):
        header = "Nostr " + base64.b64encode(b"[" * 3000 + b"]" * 3000).decode("ascii")
        assert self._verify(header) is ProofFailure.MALFORMED_HEADER

    @pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
    def test_event_json_must_be_utf8(self, encoding):
        header = "Nostr " + base64.b64encode(json.dumps(self._event()).encode(encoding)).decode("ascii")
        assert self._verify(header) is ProofFailure.MALFORMED_HEADER

    def test_duplicate_json_keys_are_refused(self):
        event = self._event()
        raw = json.dumps(event)[:-1] + ', "content": "other"}'
        header = "Nostr " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
        assert self._verify(header) is ProofFailure.MALFORMED_HEADER

    @pytest.mark.parametrize("mutate", [
        lambda e: {**e, "extra": 1},
        lambda e: {k: v for k, v in e.items() if k != "content"},
        lambda e: {**e, "created_at": True},
        lambda e: {**e, "created_at": float(e["created_at"])},
        lambda e: {**e, "created_at": str(e["created_at"])},
        lambda e: {**e, "kind": "27235"},
        lambda e: {**e, "pubkey": e["pubkey"].upper()},
        lambda e: {**e, "id": e["id"][:-1]},
        lambda e: {**e, "sig": e["sig"].upper()},
        lambda e: {**e, "tags": "u"},
        lambda e: {**e, "tags": [["u", 1]]},
        lambda e: {**e, "tags": [[]]},
        lambda e: {**e, "content": None},
    ])
    def test_event_shape_is_exact(self, mutate):
        assert self._verify(encode_proof(mutate(self._event()))) is ProofFailure.MALFORMED_EVENT

    def test_lone_surrogate_is_a_failure_not_a_crash(self):
        event = {**self._event(), "content": "\ud800"}
        assert self._verify(encode_proof(event)) is ProofFailure.ID_MISMATCH
