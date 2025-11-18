"""
Configuration management for fxTunnel.
"""

import os
import stat
from pathlib import Path
from typing import Any
import yaml


def get_data_dir() -> Path:
    """Get data directory from environment or default to ~/.fxtunnel"""
    env_dir = os.environ.get('FXTUNNEL_DATA_DIR')
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".fxtunnel"


# Paths
CONFIG_DIR = get_data_dir()
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Default configuration template
DEFAULT_CONFIG = """# fxTunnel Configuration
# https://github.com/your-repo/fxtunnel

# Default settings (inherited by all profiles)
defaults:
  bind: localhost
  verbose: false
  accept_new_host: false

# Connection profiles
profiles:
  # Example: Development server
  # dev:
  #   server: 192.168.1.100
  #   port: 9000
  #   tunnels:
  #     - local: 5432
  #       remote: 5432
  #     - local: 6379
  #       remote: 6379

  # Example: Simple PostgreSQL
  # pg:
  #   server: db.example.com
  #   tunnels:
  #     - 5432:5432

# Server configuration (optional)
server:
  port: 9000
  bind: 0.0.0.0
  max_clients: 10
  # allowed_ports: [5432, 6379, 80, 443, 3000, 8000, 8080]
"""


class ConfigError(Exception):
    """Configuration error."""
    pass


def load_config() -> dict[str, Any]:
    """Load configuration from file."""
    if not CONFIG_FILE.exists():
        return {}

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f) or {}
        return config
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {CONFIG_FILE}: {e}")
    except Exception as e:
        raise ConfigError(f"Failed to load config: {e}")


def init_config(force: bool = False) -> Path:
    """Initialize configuration file with template."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if CONFIG_FILE.exists() and not force:
        raise ConfigError(f"Config file already exists: {CONFIG_FILE}")

    CONFIG_FILE.write_text(DEFAULT_CONFIG)
    os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    return CONFIG_FILE


def get_profile(name: str) -> dict[str, Any]:
    """Get a profile by name."""
    config = load_config()

    profiles = config.get('profiles', {})
    if not profiles or name not in profiles:
        available = list(profiles.keys()) if profiles else []
        raise ConfigError(
            f"Profile '{name}' not found. "
            f"Available profiles: {', '.join(available) if available else 'none'}"
        )

    # Merge defaults with profile
    defaults = config.get('defaults', {})
    profile = profiles[name]

    result = {**defaults, **profile}

    return result


def get_server_config() -> dict[str, Any]:
    """Get server configuration."""
    config = load_config()

    server_config = config.get('server', {})

    # Apply defaults
    defaults = {
        'port': 9000,
        'bind': '0.0.0.0',
        'max_clients': 10,
        'allowed_ports': None,  # None means all ports allowed
    }

    return {**defaults, **server_config}


def list_profiles() -> list[str]:
    """List available profile names."""
    config = load_config()
    profiles = config.get('profiles', {})
    return list(profiles.keys()) if profiles else []


def parse_tunnel_config(tunnel_spec) -> tuple[int, int, str]:
    """
    Parse tunnel specification from config.

    Formats:
      - {"local": 5432, "remote": 5432}
      - {"local": 5432, "remote": 5432, "mode": "tcp"}
      - "5432:5432"
      - "5432:5432:udp"
    """
    if isinstance(tunnel_spec, dict):
        local_port = tunnel_spec.get('local')
        remote_port = tunnel_spec.get('remote')
        mode = tunnel_spec.get('mode', 'tcp')

        if local_port is None or remote_port is None:
            raise ConfigError(f"Invalid tunnel config: {tunnel_spec}")

        return int(local_port), int(remote_port), mode

    elif isinstance(tunnel_spec, str):
        parts = tunnel_spec.split(':')
        if len(parts) == 2:
            return int(parts[0]), int(parts[1]), 'tcp'
        elif len(parts) == 3:
            return int(parts[0]), int(parts[1]), parts[2]
        else:
            raise ConfigError(f"Invalid tunnel spec: {tunnel_spec}")

    else:
        raise ConfigError(f"Invalid tunnel format: {tunnel_spec}")


def get_tunnels_from_profile(profile: dict[str, Any]) -> list[tuple[int, int, str]]:
    """Extract tunnel specifications from profile."""
    tunnels_config = profile.get('tunnels', [])
    tunnels = []

    for spec in tunnels_config:
        tunnels.append(parse_tunnel_config(spec))

    return tunnels
