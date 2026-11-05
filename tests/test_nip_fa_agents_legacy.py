"""Contract tests for the current buzz-app desktop's agent enrollment (block/buzz-app
9c94152, src-tauri/src/federated_identity/agent/mod.rs `enroll` and `issue`,
crates/agent-controller/src/secret.rs `profile_auth`). Requests are rebuilt the way
the client builds them: form fields in its order, encoded like Rust's
`form_urlencoded`, a NIP-98 event with a random `nonce` tag, and the response
checks its `enroll` and `validate` make."""

import base64
import hashlib
import json
import secrets
from dataclasses import replace

import pytest
from coincurve import PrivateKey

import main as m
from nip_fa import nip98
from nip_fa.agents import Enrollment
from tests.test_main import (  # noqa: F401  (autouse fixtures apply by import)
    fake_token_endpoint,
    reset_jwks_cache,
    reset_launchpad_pool_state,
    stub_launchpad_lookup,
)
from tests.test_nip_fa_agent_units import attestation
from tests.test_nip_fa_agents import (  # noqa: F401  (fixtures apply by import)
    _AGENT,
    _AGENT_SECRET,
    _agents,
    _decode_agent_assertion,
    _denial,
    _grant_body,
    _owner_pubkey,
    _owner_secret,
    _post,
    _relay,
    _request_grant,
    agent_store,
    redis_store,
)
from tests.test_nip_fa_identity_key import identity_store  # noqa: F401
from tests.test_nip_fa_login import _T0, _signed_in, client, clock  # noqa: F401
from tests.test_nip_fa_nip98 import OTHER_SECRET

_GRANT_ROUTE = "/nip-fa/v1/nip-fi/agent-grant"
_ASSERTION_ROUTE = "/nip-fa/v1/nip-fi/agent-assertion"
_BUILDERLAB_SESSION = "urn:builderlab:params:oauth:token-type:bb-session"
_BUILDERLAB_GRANT = "urn:builderlab:params:oauth:token-type:nip-fi-agent-grant"
_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_RUST_FORM_SAFE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*-._")


def rust_form_encode(pairs: list[tuple[str, str]]) -> bytes:
    """`url::form_urlencoded::Serializer`: unreserved `*-._` and alphanumerics
    kept, space as `+`, every other byte as uppercase `%XX`."""
    def encode(text: str) -> str:
        return "".join(
            chr(byte) if byte in _RUST_FORM_SAFE else "+" if byte == 0x20 else f"%{byte:02X}"
            for byte in text.encode("utf-8")
        )

    return "&".join(f"{encode(name)}={encode(value)}" for name, value in pairs).encode("ascii")


def client_grant_fields(session_token: str, agent: str, auth: str, **overrides) -> list[tuple[str, str]]:
    """The client's `enroll` form, field for field and in its order."""
    fields = [
        ("grant_type", _TOKEN_EXCHANGE),
        ("subject_token", session_token),
        ("subject_token_type", _BUILDERLAB_SESSION),
        ("requested_token_type", _BUILDERLAB_GRANT),
        ("agent_pubkey", agent),
        ("runtime", "local"),
        ("owner_attestation", auth),
    ]
    return [(name, overrides.get(name, value)) for name, value in fields if overrides.get(name, value) is not None]


def client_proof(secret: bytes, url: str, body: bytes, created_at: int) -> str:
    """`profile_auth` plus `nostr()`: kind 27235, `u`, `method`, `payload`, a
    random `nonce`, serialized compact with sorted keys like serde_json."""
    event = {
        "pubkey": PrivateKey(secret).public_key_xonly.format().hex(),
        "created_at": created_at,
        "kind": 27235,
        "tags": [
            ["u", url],
            ["method", "POST"],
            ["payload", hashlib.sha256(body).hexdigest()],
            ["nonce", secrets.token_hex(16)],
        ],
        "content": "",
    }
    event["id"] = nip98.event_id(event)
    event["sig"] = PrivateKey(secret).sign_schnorr(bytes.fromhex(event["id"])).hex()
    return "Nostr " + base64.b64encode(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).decode()


def legacy_enroll(session_token, *, agent=_AGENT, secret=_AGENT_SECRET, auth=None, headers=None, **overrides):
    auth = auth or attestation(agent, _owner_secret())
    body = rust_form_encode(client_grant_fields(session_token, agent, auth, **overrides))
    proof = client_proof(secret, _agents().grant_url, body, _T0)
    request_headers = headers if headers is not None else [("Nostr-Agent-Proof", proof)]
    return _post(
        _GRANT_ROUTE, body, [("Content-Type", "application/x-www-form-urlencoded"), *request_headers]
    ), body, proof


def assert_client_accepts_enrollment(body: dict) -> str:
    """The checks the client's `enroll` makes before storing a grant."""
    token = body["access_token"]
    assert body["issued_token_type"] == _BUILDERLAB_GRANT
    assert body["token_type"] == "N_A"
    assert body["nostr_owner_pubkey"] == _owner_pubkey()
    assert body["nip_fi_issuer"]
    assert 0 < len(token) <= 1024 and not any(char.isspace() for char in token)
    return token


def client_assertion(grant: str, *, agent=_AGENT, secret=_AGENT_SECRET):
    """The client's `issue`: JSON with sorted keys, Bearer grant, NIP-98 in
    `Nostr-Authorization`."""
    body = json.dumps({"nostr_pubkey": agent, "relay_url": _relay()}, separators=(",", ":")).encode()
    proof = client_proof(secret, _agents().assertion_url, body, _T0)
    return _post(_ASSERTION_ROUTE, body, [
        ("Authorization", f"Bearer {grant}"),
        ("Content-Type", "application/json"),
        ("Nostr-Authorization", proof),
    ])


class TestClientContract:
    def test_enrolls_and_gets_an_assertion_the_client_accepts(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)

        enrolled, _, _ = legacy_enroll(session_token)

        assert enrolled.status_code == 200, enrolled.text
        assert enrolled.headers["cache-control"] == "no-store"
        grant = assert_client_accepts_enrollment(enrolled.json())
        [enrollment] = agent_store.enrollments
        assert (enrollment.agent_pubkey, enrollment.owner_pubkey) == (_AGENT, _owner_pubkey())

        issued = client_assertion(grant)

        assert issued.status_code == 200, issued.text
        reply = issued.json()
        header, claims = _decode_agent_assertion(reply["assertion"])
        assert header["typ"] == "nip-fi-agent+jwt"
        assert claims["nostr_pubkey"] == reply["nostr_pubkey"] == _AGENT
        assert claims["nostr_owner_pubkey"] == _owner_pubkey()
        assert claims["iss"] == enrolled.json()["nip_fi_issuer"]
        assert claims["aud"] == "https://" + _relay()[len("wss://"):]
        assert claims["exp"] == reply["expires_at"] > _T0
        assert claims["iat"] <= _T0 + 5 and claims["iat"] <= claims["exp"]
        assert len(reply["assertion"]) <= 8192 and all(reply["assertion"].split("."))

    def test_the_form_encoding_matches_the_client(self):
        encoded = rust_form_encode([("owner_attestation", '["auth","ab","",""]'), ("t", "a b~*")])
        assert encoded == b"owner_attestation=%5B%22auth%22%2C%22ab%22%2C%22%22%2C%22%22%5D&t=a+b%7E*"

    def test_spec_clients_still_get_the_spec_token_type(self, redis_store, clock, agent_store):
        response = _request_grant(_grant_body(_signed_in(redis_store, clock)))
        assert response.json()["issued_token_type"] == "urn:nostr:params:oauth:token-type:nip-fi-agent-grant"


class TestLegacyKeepsEveryCheck:
    def test_a_proof_is_single_use(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        first, body, proof = legacy_enroll(session_token)
        assert first.status_code == 200
        again = _post(_GRANT_ROUTE, body, [
            ("Content-Type", "application/x-www-form-urlencoded"), ("Nostr-Agent-Proof", proof),
        ])
        assert _denial(again) == (400, {"error": "invalid_request"})

    def test_proof_must_be_signed_by_the_agent(self, redis_store, clock, agent_store):
        response, _, _ = legacy_enroll(_signed_in(redis_store, clock), secret=OTHER_SECRET)
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_owner_attestation_must_be_the_owners(self, redis_store, clock, agent_store):
        auth = attestation(_AGENT, OTHER_SECRET)
        response, _, _ = legacy_enroll(_signed_in(redis_store, clock), auth=auth)
        assert _denial(response) == (400, {"error": "invalid_grant"})

    def test_unknown_session(self, redis_store, clock, agent_store):
        response, _, _ = legacy_enroll("no-such-session")
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_the_cap_applies(self, redis_store, clock, agent_store):
        agent_store.forced = Enrollment.CAP_REACHED
        response, _, _ = legacy_enroll(_signed_in(redis_store, clock))
        assert _denial(response) == (429, {"error": "rate_limited"})

    def test_ambient_credentials_are_refused(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        _, body, proof = legacy_enroll(session_token)
        for extra in (("Authorization", f"Bearer {session_token}"), ("Cookie", "_foss_oauth2_proxy=x")):
            response = _post(_GRANT_ROUTE, body, [
                ("Content-Type", "application/x-www-form-urlencoded"), ("Nostr-Agent-Proof", proof), extra,
            ])
            assert response.status_code == 400


class TestNoMixedForms:
    @pytest.mark.parametrize("overrides", [
        {"runtime": "remote"},
        {"runtime": "LOCAL"},
        {"runtime": ""},
        {"runtime": None},
        {"subject_token_type": "urn:nostr:params:oauth:token-type:nip-fa-session"},
        {"requested_token_type": "urn:nostr:params:oauth:token-type:nip-fi-agent-grant"},
    ])
    def test_the_legacy_header_needs_the_whole_legacy_form(self, redis_store, clock, agent_store, overrides):
        response, _, _ = legacy_enroll(_signed_in(redis_store, clock), **overrides)
        assert _denial(response) == (400, {"error": "invalid_request"})
        assert agent_store.enrollments == []

    def test_the_spec_header_refuses_the_legacy_form(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        _, body, proof = legacy_enroll(session_token)
        response = _post(_GRANT_ROUTE, body, [
            ("Content-Type", "application/x-www-form-urlencoded"), ("Nostr-Authorization", proof),
        ])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_both_proof_headers_are_refused(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        _, body, proof = legacy_enroll(session_token)
        response = _post(_GRANT_ROUTE, body, [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Nostr-Agent-Proof", proof),
            ("Nostr-Authorization", proof),
        ])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_two_legacy_proofs_are_refused(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        _, body, proof = legacy_enroll(session_token)
        response = _post(_GRANT_ROUTE, body, [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Nostr-Agent-Proof", proof),
            ("Nostr-Agent-Proof", proof),
        ])
        assert _denial(response) == (400, {"error": "invalid_request"})

    def test_the_assertion_route_refuses_the_legacy_proof_header(self, redis_store, clock, agent_store):
        session_token = _signed_in(redis_store, clock)
        enrolled, _, _ = legacy_enroll(session_token)
        grant = enrolled.json()["access_token"]
        body = json.dumps({"nostr_pubkey": _AGENT, "relay_url": _relay()}).encode()
        proof = client_proof(_AGENT_SECRET, _agents().assertion_url, body, _T0)
        response = _post(_ASSERTION_ROUTE, body, [
            ("Authorization", f"Bearer {grant}"),
            ("Content-Type", "application/json"),
            ("Nostr-Authorization", proof),
            ("Nostr-Agent-Proof", proof),
        ])
        assert _denial(response) == (400, {"error": "invalid_request"})


class TestLegacyFlagOff:
    @pytest.fixture()
    def legacy_off(self, monkeypatch):
        routes = m._buzz_adapter.agents
        monkeypatch.setattr(routes, "_agents", replace(routes._agents, accept_legacy_client=False))

    def test_the_legacy_form_is_refused(self, redis_store, clock, agent_store, legacy_off):
        response, _, _ = legacy_enroll(_signed_in(redis_store, clock))
        assert _denial(response) == (400, {"error": "invalid_request"})
        assert agent_store.enrollments == []

    def test_the_spec_form_still_works(self, redis_store, clock, agent_store, legacy_off):
        assert _request_grant(_grant_body(_signed_in(redis_store, clock))).status_code == 200
