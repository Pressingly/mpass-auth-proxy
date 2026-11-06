"""BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT: on by default, read only with agents on."""

import json

import pytest

from nip_fa.config import AdapterConfig, AdapterConfigError
from tests.test_nip_fa_config import _AGENTS, _ENABLED, _PROBE_AGENT_ROUTES, _run_main


class TestLegacyClientFlag:
    def test_accepted_by_default(self):
        assert AdapterConfig.from_env(_AGENTS).agents.accept_legacy_client is True

    @pytest.mark.parametrize("value, accepted", [
        ("", True), ("true", True), ("1", True), ("YES", True), ("false", False), ("0", False), (" no ", False),
    ])
    def test_values(self, value, accepted):
        env = {**_AGENTS, "BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT": value}
        assert AdapterConfig.from_env(env).agents.accept_legacy_client is accepted

    @pytest.mark.parametrize("value", ["off", "maybe", "2"])
    def test_an_unclear_value_refuses(self, value):
        with pytest.raises(AdapterConfigError, match="BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT must be true or false"):
            AdapterConfig.from_env({**_AGENTS, "BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT": value})

    def test_not_read_with_agents_off(self):
        env = {**_ENABLED, "BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT": "maybe"}
        assert AdapterConfig.from_env(env).agents is None


class TestLegacyClientFlagAtImport:
    def test_adapter_on_ignores_it_with_agents_off(self):
        env = {**_ENABLED, "LAUNCHPAD_EMAIL_CAPTURE": "false", "BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT": "maybe"}
        result = _run_main(_PROBE_AGENT_ROUTES, **env)
        assert result.returncode == 0, result.stderr
        probe = json.loads(result.stdout.strip().splitlines()[-1])
        assert probe["answers"] == [[403, {"error": "agent_unsupported"}]] * 3

    def test_all_flags_off_ignores_it_too(self):
        result = _run_main("import main", BUZZ_AGENTS_ACCEPT_LEGACY_CLIENT="maybe")
        assert result.returncode == 0, result.stderr
