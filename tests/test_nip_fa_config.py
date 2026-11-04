import os
import subprocess
import sys

import pytest

from nip_fa.config import DEFAULT_SESSION_TTL_SECONDS, AdapterConfig, AdapterConfigError

_SECRET_HEX = "ab" * 32
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
        config = AdapterConfig.from_env(
            {"BUZZ_ADAPTER_ENABLED": flag, "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX}
        )
        assert config.enabled is True
        assert config.identity_master_secret == bytes.fromhex(_SECRET_HEX)
        assert config.session_ttl_seconds == DEFAULT_SESSION_TTL_SECONDS == 2_592_000

    def test_enabled_without_secret_refuses(self):
        with pytest.raises(AdapterConfigError, match="BUZZ_IDENTITY_MASTER_SECRET is empty"):
            AdapterConfig.from_env({"BUZZ_ADAPTER_ENABLED": "true"})

    @pytest.mark.parametrize(
        "secret",
        ["ab" * 31, "ab" * 33, "zz" * 32, "0x" + "ab" * 31, "ab" * 16 + " " + "ab" * 15 + "a"],
    )
    def test_enabled_with_malformed_secret_refuses_without_echoing_it(self, secret):
        with pytest.raises(AdapterConfigError) as excinfo:
            AdapterConfig.from_env(
                {"BUZZ_ADAPTER_ENABLED": "true", "BUZZ_IDENTITY_MASTER_SECRET": secret}
            )
        assert "64 hex characters" in str(excinfo.value)
        assert secret.strip() not in str(excinfo.value)

    def test_secret_is_not_in_repr(self):
        config = AdapterConfig.from_env(
            {"BUZZ_ADAPTER_ENABLED": "true", "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX}
        )
        assert _SECRET_HEX not in repr(config)
        assert repr(bytes.fromhex(_SECRET_HEX)) not in repr(config)

    def test_session_ttl_override(self):
        config = AdapterConfig.from_env({
            "BUZZ_ADAPTER_ENABLED": "true",
            "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX,
            "BUZZ_ADAPTER_SESSION_TTL_SECONDS": "3600",
        })
        assert config.session_ttl_seconds == 3600

    @pytest.mark.parametrize("ttl", ["0", "-5", "abc", "1.5"])
    def test_invalid_session_ttl_refuses(self, ttl):
        with pytest.raises(AdapterConfigError, match="BUZZ_ADAPTER_SESSION_TTL_SECONDS"):
            AdapterConfig.from_env({
                "BUZZ_ADAPTER_ENABLED": "true",
                "BUZZ_IDENTITY_MASTER_SECRET": _SECRET_HEX,
                "BUZZ_ADAPTER_SESSION_TTL_SECONDS": ttl,
            })


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
        result = _run_main(
            _PROBE_SESSION_ROUTE,
            BUZZ_ADAPTER_ENABLED="true",
            BUZZ_IDENTITY_MASTER_SECRET=_SECRET_HEX,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "401"

    def test_flag_on_without_secret_refuses_to_start(self):
        result = _run_main("import main", BUZZ_ADAPTER_ENABLED="true")
        assert result.returncode != 0
        assert "BUZZ_IDENTITY_MASTER_SECRET is empty" in result.stderr

    def test_flag_on_with_bad_secret_refuses_to_start(self):
        bad_secret = "cd" * 31
        result = _run_main(
            "import main", BUZZ_ADAPTER_ENABLED="true", BUZZ_IDENTITY_MASTER_SECRET=bad_secret
        )
        assert result.returncode != 0
        assert "64 hex characters" in result.stderr
        assert bad_secret not in result.stderr
