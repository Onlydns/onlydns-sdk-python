"""Configuration management for OnlyDNS SDK and CLI.

Handles credentials storage and resolution from environment variables or
the user configuration directory (~/.config/onlydns/config.json).
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


def get_config_dir() -> Path:
    """Get the configuration directory path (~/.config/onlydns or $XDG_CONFIG_HOME/onlydns)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "onlydns"
    return Path.home() / ".config" / "onlydns"


def get_config_file_path() -> Path:
    """Get the primary configuration file path."""
    return get_config_dir() / "config.json"


def load_config() -> Dict[str, Any]:
    """Load configuration from ~/.config/onlydns/config.json if it exists."""
    config_path = get_config_file_path()
    if config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, OSError):
            return {}

    # Check fallback single-file location ~/.config/onlydns.json
    fallback_path = (Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))) / "onlydns.json"
    if fallback_path.is_file():
        try:
            with open(fallback_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, OSError):
            return {}

    return {}


def save_config(config_data: Dict[str, Any]) -> Path:
    """Save configuration dictionary to ~/.config/onlydns/config.json.

    Creates directory with 0o700 permissions and writes file with 0o600 permissions.
    """
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    try:
        config_dir.chmod(0o700)
    except OSError:
        pass

    config_path = get_config_file_path()
    # Write to temp file or directly with restrictive permissions
    content = json.dumps(config_data, indent=2) + "\n"
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(content)

    try:
        config_path.chmod(0o600)
    except OSError:
        pass

    return config_path


def get_stored_api_token() -> Optional[str]:
    """Retrieve stored API token from configuration file."""
    cfg = load_config()
    token = cfg.get("api_key") or cfg.get("api_token") or cfg.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def get_api_key() -> Optional[str]:
    """Resolve API key from environment variables or stored configuration.

    Priority:
    1. ONLYDNS_API_KEY environment variable
    2. ONLYDNS_API_TOKEN environment variable
    3. Stored config file (~/.config/onlydns/config.json)
    """
    env_token = os.environ.get("ONLYDNS_API_KEY") or os.environ.get("ONLYDNS_API_TOKEN")
    if env_token and env_token.strip():
        return env_token.strip()
    return get_stored_api_token()


def set_api_key(api_key: str, base_url: Optional[str] = None) -> Path:
    """Save or update API key in the configuration file."""
    cfg = load_config()
    cfg["api_key"] = api_key.strip()
    if base_url:
        cfg["base_url"] = base_url.strip()
    return save_config(cfg)


def clear_config() -> bool:
    """Remove stored configuration file."""
    config_path = get_config_file_path()
    if config_path.is_file():
        try:
            config_path.unlink()
            return True
        except OSError:
            return False
    return False
