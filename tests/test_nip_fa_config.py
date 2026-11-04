import json
import os
import subprocess
import sys

import pytest

from nip_fa.config import (
    DEFAULT_ASSERTION_TTL_SECONDS,
    DEFAULT_SESSION_TTL_SECONDS,
    AdapterConfig,
    AdapterConfigError,
)

_SECRET_HEX = "ab" * 32
_SALT_HEX = "ef" * 16
_ENABLED = {
    "BUZZ_ADAPTER_ENABLED": "true",
    "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX,
    "BUZZ_IDENTITY_SALT": _SALT_HEX,
    "LAUNCHPAD_DB_PASSWORD": "launchpad-db-password",
    "BUZZ_NIP_FI_ISSUER": "https://auth.example.com/nip-fi",
    "BUZZ_RELAY_URLS": "wss://relay.example.com",
    "MPASS_CALLBACK_URL": "https://auth.example.com/mpass-callback",
    "MPASS_SIGNING_KEY_ALLOW_EPHEMERAL": "true",
}
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BASE_ENV = {
    "OIDC_ISSUER_URL": "https://idp.example.com/pool",
    "OIDC_CLIENT_ID": "test-client-id",
    "MONETA_HOSTED_UI_URL": "https://ui.example.com",
    "MPASS_CALLBACK_URL": "https://auth.example.com/mpass-callback",
    "REDIS_URL": "redis://localhost:6379/0",
    "COOKIE_DOMAIN": ".example.com",
}


class TestAdapterConfig:
    @pytest.mark.parametrize("flag", ["", "false", "0", "no", "off"])
    def test_off_by_default_and_needs_no_secret(self, flag):
        config = AdapterConfig.from_env({"BUZZ_ADAPTER_ENABLED": flag})
        assert config.enabled is False

    @pytest.mark.parametrize("flag", ["true", "TRUE", "1", "yes", " true "])
    def test_enabled_with_valid_secret(self, flag):
        config = AdapterConfig.from_env({**_ENABLED, "BUZZ_ADAPTER_ENABLED": flag})
        assert config.enabled is True
        assert config.identity_master_secret == bytes.fromhex(_SECRET_HEX)
        assert config.identity_salt == bytes.fromhex(_SALT_HEX)
        assert config.session_ttl_seconds == DEFAULT_SESSION_TTL_SECONDS == 2_592_000

    def test_enabled_without_secret_refuses(self):
        with pytest.raises(AdapterConfigError, match="BUZZ_IDENTITY_MASTER_SECRET is empty"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_IDENTITY_MASTER_SECRET": ""})

    @pytest.mark.parametrize(
        "secret",
        ["ab" * 31, "ab" * 33, "zz" * 32, "0x" + "ab" * 31, "ab" * 16 + " " + "ab" * 15 + "a"],
    )
    def test_enabled_with_malformed_secret_refuses_without_echoing_it(self, secret):
        with pytest.raises(AdapterConfigError) as excinfo:
            AdapterConfig.from_env({**_ENABLED, "BUZZ_IDENTITY_MASTER_SECRET": secret})
        assert "64 hex characters" in str(excinfo.value)
        assert secret.strip() not in str(excinfo.value)

    def test_secret_and_salt_are_not_in_repr(self):
        config = AdapterConfig.from_env(_ENABLED)
        for value in (_SECRET_HEX, _SALT_HEX):
            assert value not in repr(config)
            assert repr(bytes.fromhex(value)) not in repr(config)

    def test_enabled_without_salt_refuses(self):
        with pytest.raises(AdapterConfigError, match="BUZZ_IDENTITY_SALT is empty"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_IDENTITY_SALT": " "})

    @pytest.mark.parametrize("salt", ["ef" * 15, "ef" * 65, "ef" * 16 + "e", "zz" * 16, "0x" + "ef" * 16])
    def test_enabled_with_malformed_salt_refuses_without_echoing_it(self, salt):
        with pytest.raises(AdapterConfigError) as excinfo:
            AdapterConfig.from_env({**_ENABLED, "BUZZ_IDENTITY_SALT": salt})
        assert "32 to 128 characters" in str(excinfo.value)
        assert salt not in str(excinfo.value)

    @pytest.mark.parametrize("salt", ["ef" * 16, "EF" * 64, "0123456789abcdef" * 2])
    def test_salt_accepts_16_to_64_bytes_of_hex(self, salt):
        assert AdapterConfig.from_env({**_ENABLED, "BUZZ_IDENTITY_SALT": salt}).identity_salt == bytes.fromhex(salt)

    def test_enabled_without_launchpad_db_password_refuses(self):
        with pytest.raises(AdapterConfigError, match="LAUNCHPAD_DB_PASSWORD is empty"):
            AdapterConfig.from_env({**_ENABLED, "LAUNCHPAD_DB_PASSWORD": ""})

    def test_session_ttl_override(self):
        config = AdapterConfig.from_env({**_ENABLED, "BUZZ_ADAPTER_SESSION_TTL_SECONDS": "3600"})
        assert config.session_ttl_seconds == 3600

    @pytest.mark.parametrize("ttl", ["0", "-5", "abc", "1.5"])
    def test_invalid_session_ttl_refuses(self, ttl):
        with pytest.raises(AdapterConfigError, match="BUZZ_ADAPTER_SESSION_TTL_SECONDS"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_ADAPTER_SESSION_TTL_SECONDS": ttl})


class TestAssertionConfig:
    def test_enabled_config_carries_the_assertion_settings(self):
        config = AdapterConfig.from_env(_ENABLED)
        assert config.nip_fi_issuer == "https://auth.example.com/nip-fi"
        assert config.relay_urls == frozenset({"wss://relay.example.com"})
        assert config.assertion_ttl_seconds == DEFAULT_ASSERTION_TTL_SECONDS == 300
        assert config.assertions_url == "https://auth.example.com/nip-fa/v1/identity/assertions"

    def test_disabled_config_needs_none_of_them(self):
        config = AdapterConfig.from_env({"BUZZ_ADAPTER_ENABLED": "false"})
        assert (config.nip_fi_issuer, config.relay_urls, config.assertions_url) == ("", frozenset(), "")

    def test_issuer_is_required(self):
        with pytest.raises(AdapterConfigError, match="BUZZ_NIP_FI_ISSUER is empty"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_NIP_FI_ISSUER": " "})

    @pytest.mark.parametrize("issuer", [
        "http://auth.example.com/nip-fi",
        "https://auth.example.com/nip-fi/",
        "https://auth.example.com/",
        "https://auth.example.com?x=1",
        "https://auth.example.com#f",
        "https://user@auth.example.com",
        "https://auth.example.com/a b",
        "https://",
        "auth.example.com",
    ])
    def test_issuer_must_be_an_exact_https_url(self, issuer):
        with pytest.raises(AdapterConfigError, match="BUZZ_NIP_FI_ISSUER must be an https URL"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_NIP_FI_ISSUER": issuer})

    @pytest.mark.parametrize("issuer", ["https://auth.example.com", "https://auth.example.com/nip-fi/v1"])
    def test_issuer_is_kept_byte_for_byte(self, issuer):
        assert AdapterConfig.from_env({**_ENABLED, "BUZZ_NIP_FI_ISSUER": issuer}).nip_fi_issuer == issuer

    def test_issuer_must_not_be_the_oauth2_proxy_issuer(self):
        env = {**_ENABLED, "MPASS_PROXY_ISSUER_URL": "https://auth.example.com", "BUZZ_NIP_FI_ISSUER": "https://auth.example.com"}
        with pytest.raises(AdapterConfigError, match="must differ from MPASS_PROXY_ISSUER_URL"):
            AdapterConfig.from_env(env)

    def test_relays_are_required(self):
        with pytest.raises(AdapterConfigError, match="BUZZ_RELAY_URLS is empty"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_RELAY_URLS": ""})

    def test_relays_are_a_comma_separated_list(self):
        env = {**_ENABLED, "BUZZ_RELAY_URLS": "wss://a.example.com, wss://b.example.com:8443,wss://[2001:db8::1]"}
        assert AdapterConfig.from_env(env).relay_urls == frozenset(
            {"wss://a.example.com", "wss://b.example.com:8443", "wss://[2001:db8::1]"}
        )

    @pytest.mark.parametrize("relays", [
        "wss://relay.example.com/",
        "wss://Relay.example.com",
        "wss://relay.example.com:443",
        "wss://relay.example.com:80",
        "ws://relay.example.com",
        "https://relay.example.com",
        "wss://relay.example.com,",
        "wss://a.example.com,,wss://b.example.com",
    ])
    def test_non_canonical_relays_refuse_rather_than_normalise(self, relays):
        with pytest.raises(AdapterConfigError, match="canonical wss://host"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_RELAY_URLS": relays})

    @pytest.mark.parametrize("ttl", ["30", "3600", "600"])
    def test_assertion_ttl_override(self, ttl):
        assert AdapterConfig.from_env({**_ENABLED, "BUZZ_ASSERTION_TTL_SECONDS": ttl}).assertion_ttl_seconds == int(ttl)

    @pytest.mark.parametrize("ttl", ["29", "3601", "0", "-5", "abc", "1.5"])
    def test_assertion_ttl_is_bounded(self, ttl):
        with pytest.raises(AdapterConfigError, match="BUZZ_ASSERTION_TTL_SECONDS must be an integer from 30 to 3600"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_ASSERTION_TTL_SECONDS": ttl})

    def test_public_origin_is_derived_from_the_callback(self):
        env = {**_ENABLED, "MPASS_CALLBACK_URL": "https://auth.corp.example:8443/mpass-callback?x=1"}
        assert AdapterConfig.from_env(env).assertions_url == "https://auth.corp.example:8443/nip-fa/v1/identity/assertions"

    def test_public_origin_override_wins(self):
        env = {**_ENABLED, "BUZZ_ADAPTER_PUBLIC_ORIGIN": "https://buzz-auth.corp.example"}
        assert AdapterConfig.from_env(env).assertions_url == "https://buzz-auth.corp.example/nip-fa/v1/identity/assertions"

    @pytest.mark.parametrize("origin", [
        "https://buzz-auth.corp.example/",
        "https://buzz-auth.corp.example/nip-fa",
        "https://Buzz-Auth.corp.example",
        "https://buzz-auth.corp.example:443",
        "http://buzz-auth.corp.example",
    ])
    def test_non_canonical_public_origin_refuses(self, origin):
        with pytest.raises(AdapterConfigError, match="BUZZ_ADAPTER_PUBLIC_ORIGIN must be a canonical"):
            AdapterConfig.from_env({**_ENABLED, "BUZZ_ADAPTER_PUBLIC_ORIGIN": origin})

    @pytest.mark.parametrize("callback", ["http://auth.corp.example/mpass-callback", "", "https://AUTH.corp.example/cb"])
    def test_unusable_callback_origin_refuses_and_names_the_override(self, callback):
        with pytest.raises(AdapterConfigError, match="MPASS_CALLBACK_URL origin.*BUZZ_ADAPTER_PUBLIC_ORIGIN"):
            AdapterConfig.from_env({**_ENABLED, "MPASS_CALLBACK_URL": callback})


def _run_main(script: str, **env_overrides) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ["PATH"], **_BASE_ENV, **env_overrides}
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=_REPO_ROOT, env=env, capture_output=True, text=True,
    )


_PROBE_SESSION_ROUTE = (
    "import main\n"
    "from fastapi.testclient import TestClient\n"
    "print(TestClient(main.app).get('/nip-fa/v1/session').status_code)\n"
)


_PROBE_ASSERTION_ROUTE = (
    "import main\n"
    "from fastapi.testclient import TestClient\n"
    "print(TestClient(main.app).post('/nip-fa/v1/identity/assertions').status_code)\n"
)
_PROBE_JWKS = (
    "import json, main\n"
    "from fastapi.testclient import TestClient\n"
    "response = TestClient(main.app).get('/.well-known/jwks.json')\n"
    "print(json.dumps({'status': response.status_code, 'body': response.json(), 'kid': main._SIGNING_KID}))\n"
)


def _jwks_probe(**env) -> dict:
    result = _run_main(_PROBE_JWKS, **env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


class TestJwksPublication:
    def test_served_for_the_adapter_with_email_capture_off(self):
        probe = _jwks_probe(**_ENABLED, LAUNCHPAD_EMAIL_CAPTURE="false")
        assert probe["status"] == 200
        [key] = probe["body"]["keys"]
        assert (key["kid"], key["alg"], key["kty"], key["use"]) == (probe["kid"], "RS256", "RSA", "sig")

    def test_still_404_with_both_signers_off(self):
        probe = _jwks_probe(LAUNCHPAD_EMAIL_CAPTURE="false", BUZZ_ADAPTER_ENABLED="false")
        assert probe["status"] == 404
        assert probe["kid"] is None
        assert "not the token signer" in probe["body"]["detail"]


class TestAdapterStartup:
    def test_flag_off_mounts_no_routes(self):
        result = _run_main(_PROBE_SESSION_ROUTE)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "404"

    def test_flag_on_mounts_routes(self):
        result = _run_main(_PROBE_SESSION_ROUTE, **_ENABLED)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "401"

    def test_flag_on_without_relays_refuses_to_start(self):
        result = _run_main("import main", **{**_ENABLED, "BUZZ_RELAY_URLS": ""})
        assert result.returncode != 0
        assert "BUZZ_RELAY_URLS is empty" in result.stderr

    def test_flag_on_without_a_signing_key_source_refuses_to_start(self):
        result = _run_main("import main", **{**_ENABLED, "MPASS_SIGNING_KEY_ALLOW_EPHEMERAL": "false"})
        assert result.returncode != 0
        assert "ephemeral RSA signing key" in result.stderr

    def test_flag_off_mounts_no_assertion_route(self):
        result = _run_main(_PROBE_ASSERTION_ROUTE)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "404"

    def test_flag_on_mounts_the_assertion_route(self):
        result = _run_main(_PROBE_ASSERTION_ROUTE, **_ENABLED)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "401"

    def test_flag_on_without_secret_refuses_to_start(self):
        result = _run_main("import main", **{**_ENABLED, "BUZZ_IDENTITY_MASTER_SECRET": ""})
        assert result.returncode != 0
        assert "BUZZ_IDENTITY_MASTER_SECRET is empty" in result.stderr

    def test_flag_on_without_salt_refuses_to_start(self):
        result = _run_main("import main", **{**_ENABLED, "BUZZ_IDENTITY_SALT": ""})
        assert result.returncode != 0
        assert "BUZZ_IDENTITY_SALT is empty" in result.stderr

    def test_flag_on_with_bad_secret_refuses_to_start(self):
        bad_secret = "cd" * 31
        result = _run_main("import main", **{**_ENABLED, "BUZZ_IDENTITY_MASTER_SECRET": bad_secret})
        assert result.returncode != 0
        assert "64 hex characters" in result.stderr
        assert bad_secret not in result.stderr


_FLAG_OFF_CALLBACK = """
import json, sys
import main
from fastapi.testclient import TestClient

class OneStateRedis:
    def __init__(self, state):
        self.values = {"bridge_state:s1": json.dumps(state)}

    async def getdel(self, key):
        return self.values.pop(key, None)

main.redis_client = OneStateRedis(json.loads(sys.argv[1]))
client = TestClient(main.app, raise_server_exceptions=False)
response = client.get(
    "/mpass-callback", params={"id_token": "a.b.c"}, cookies={"mpass_bridge": "s1"}, follow_redirects=False
)
print(response.status_code, response.headers.get("location", ""))
"""


class TestFlagOffCallback:
    @pytest.mark.parametrize("bridge_state", [
        {"flow": "nip-fa", "return_to": "http://127.0.0.1:5000/cb", "handoff_challenge": "x" * 43},
        {"redirect_uri": "https://auth.example.com/oauth2/callback", "state": "s1"},
    ])
    def test_state_for_no_enabled_flow_redirects_to_portal(self, bridge_state):
        env = {"PATH": os.environ["PATH"], **_BASE_ENV}
        result = subprocess.run(
            [sys.executable, "-c", _FLAG_OFF_CALLBACK, json.dumps(bridge_state)],
            cwd=_REPO_ROOT, env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        status, location = result.stdout.split()
        assert status == "302"
        assert "login_error=expired_flow" in location
        assert "127.0.0.1" not in location
