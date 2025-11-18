"""Tests for config module."""

import pytest
import tempfile
from pathlib import Path

from fxtunnel.config import (
    load_config, init_config, get_profile, get_server_config,
    list_profiles, parse_tunnel_config, get_tunnels_from_profile,
    ConfigError, CONFIG_DIR, CONFIG_FILE
)


class TestParseConfig:
    """Tests for configuration parsing."""

    def test_parse_tunnel_dict(self):
        """Dict tunnel spec should parse correctly."""
        spec = {"local": 5432, "remote": 5432}
        local, remote, mode = parse_tunnel_config(spec)

        assert local == 5432
        assert remote == 5432
        assert mode == "tcp"

    def test_parse_tunnel_dict_with_mode(self):
        """Dict tunnel spec with mode should parse correctly."""
        spec = {"local": 53, "remote": 53, "mode": "udp"}
        local, remote, mode = parse_tunnel_config(spec)

        assert local == 53
        assert remote == 53
        assert mode == "udp"

    def test_parse_tunnel_string(self):
        """String tunnel spec should parse correctly."""
        spec = "5432:5432"
        local, remote, mode = parse_tunnel_config(spec)

        assert local == 5432
        assert remote == 5432
        assert mode == "tcp"

    def test_parse_tunnel_string_with_mode(self):
        """String tunnel spec with mode should parse correctly."""
        spec = "53:53:udp"
        local, remote, mode = parse_tunnel_config(spec)

        assert local == 53
        assert remote == 53
        assert mode == "udp"

    def test_parse_tunnel_different_ports(self):
        """Tunnel with different local and remote ports should work."""
        spec = "15432:5432"
        local, remote, mode = parse_tunnel_config(spec)

        assert local == 15432
        assert remote == 5432

    def test_parse_tunnel_invalid_dict(self):
        """Invalid dict spec should raise ConfigError."""
        spec = {"local": 5432}  # Missing remote
        with pytest.raises(ConfigError):
            parse_tunnel_config(spec)

    def test_parse_tunnel_invalid_string(self):
        """Invalid string spec should raise ConfigError."""
        spec = "5432"  # Missing remote
        with pytest.raises(ConfigError):
            parse_tunnel_config(spec)

    def test_parse_tunnel_invalid_type(self):
        """Invalid type should raise ConfigError."""
        spec = 5432  # Not dict or string
        with pytest.raises(ConfigError):
            parse_tunnel_config(spec)


class TestGetTunnelsFromProfile:
    """Tests for extracting tunnels from profile."""

    def test_empty_profile(self):
        """Profile without tunnels should return empty list."""
        profile = {}
        tunnels = get_tunnels_from_profile(profile)
        assert tunnels == []

    def test_mixed_tunnel_formats(self):
        """Profile with mixed tunnel formats should parse all."""
        profile = {
            "tunnels": [
                {"local": 5432, "remote": 5432},
                "6379:6379",
                {"local": 53, "remote": 53, "mode": "udp"}
            ]
        }
        tunnels = get_tunnels_from_profile(profile)

        assert len(tunnels) == 3
        assert tunnels[0] == (5432, 5432, "tcp")
        assert tunnels[1] == (6379, 6379, "tcp")
        assert tunnels[2] == (53, 53, "udp")


class TestServerConfig:
    """Tests for server configuration."""

    def test_defaults(self):
        """Server config should have default values."""
        # This will return defaults if no config file exists
        config = get_server_config()

        assert config['port'] == 9000
        assert config['bind'] == '0.0.0.0'
        assert config['max_clients'] == 10
        assert config['allowed_ports'] is None


class TestConfigWithTempDir:
    """Tests that require a temporary config directory."""

    @pytest.fixture
    def temp_config(self, monkeypatch, tmp_path):
        """Create a temporary config directory."""
        config_dir = tmp_path / ".fxtunnel"
        config_file = config_dir / "config.yaml"

        # Monkey-patch the config paths
        import fxtunnel.config as config_module
        monkeypatch.setattr(config_module, 'CONFIG_DIR', config_dir)
        monkeypatch.setattr(config_module, 'CONFIG_FILE', config_file)

        return config_dir, config_file

    def test_init_config_creates_file(self, temp_config):
        """init_config should create config file."""
        config_dir, config_file = temp_config

        path = init_config()
        assert path == config_file
        assert config_file.exists()

    def test_init_config_force_overwrites(self, temp_config):
        """init_config with force should overwrite existing."""
        config_dir, config_file = temp_config

        # Create initial config
        init_config()
        original_content = config_file.read_text()

        # Write different content
        config_file.write_text("modified: true\n")

        # Force overwrite
        init_config(force=True)
        new_content = config_file.read_text()

        assert new_content == original_content

    def test_init_config_without_force_fails(self, temp_config):
        """init_config without force should fail if file exists."""
        config_dir, config_file = temp_config

        init_config()

        with pytest.raises(ConfigError):
            init_config(force=False)

    def test_load_config_empty_file(self, temp_config):
        """Loading empty config should return empty dict."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file.write_text("")

        config = load_config()
        assert config == {}

    def test_load_config_invalid_yaml(self, temp_config):
        """Loading invalid YAML should raise ConfigError."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file.write_text("invalid: yaml: content: [")

        with pytest.raises(ConfigError):
            load_config()

    def test_get_profile_success(self, temp_config):
        """get_profile should return profile data."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)

        config_content = """
profiles:
  dev:
    server: 192.168.1.100
    port: 9000
    tunnels:
      - 5432:5432
"""
        config_file.write_text(config_content)

        profile = get_profile("dev")
        assert profile["server"] == "192.168.1.100"
        assert profile["port"] == 9000

    def test_get_profile_not_found(self, temp_config):
        """get_profile should raise ConfigError for missing profile."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)

        config_content = """
profiles:
  dev:
    server: 192.168.1.100
"""
        config_file.write_text(config_content)

        with pytest.raises(ConfigError, match="Profile 'prod' not found"):
            get_profile("prod")

    def test_get_profile_merges_defaults(self, temp_config):
        """Profile should inherit from defaults."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)

        config_content = """
defaults:
  verbose: true
  bind: 0.0.0.0

profiles:
  dev:
    server: 192.168.1.100
    tunnels:
      - 5432:5432
"""
        config_file.write_text(config_content)

        profile = get_profile("dev")
        assert profile["verbose"] is True
        assert profile["bind"] == "0.0.0.0"
        assert profile["server"] == "192.168.1.100"

    def test_list_profiles(self, temp_config):
        """list_profiles should return all profile names."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)

        config_content = """
profiles:
  dev:
    server: dev.example.com
  prod:
    server: prod.example.com
  staging:
    server: staging.example.com
"""
        config_file.write_text(config_content)

        profiles = list_profiles()
        assert set(profiles) == {"dev", "prod", "staging"}

    def test_list_profiles_empty(self, temp_config):
        """list_profiles with no profiles should return empty list."""
        config_dir, config_file = temp_config
        config_dir.mkdir(parents=True, exist_ok=True)

        config_file.write_text("profiles: {}")

        profiles = list_profiles()
        assert profiles == []
