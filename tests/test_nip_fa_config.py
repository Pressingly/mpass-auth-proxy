import json
import os
import subprocess
import sys

import pytest

from nip_fa.config import DEFAULT_SESSION_TTL_SECONDS, AdapterConfig, AdapterConfigError

_SECRET_HEX = "ab" * 32
_SALT_HEX = "ef" * 16
_ENABLED = {
    "BUZZ_ADAPTER_ENABLED": "true",
    "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX,
    "BUZZ_IDENTITY_SALT": _SALT_HEX,
    "LAUNCHPAD_DB_PASSWORD": "launchpad-db-password",
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


class TestAdapterStartup:
    def test_flag_off_mounts_no_routes(self):
        result = _run_main(_PROBE_SESSION_ROUTE)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "404"

    def test_flag_on_mounts_routes(self):
        result = _run_main(_PROBE_SESSION_ROUTE, **_ENABLED)
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
