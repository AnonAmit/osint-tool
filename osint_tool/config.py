"""
Configuration module for OSINT CLI Tool.
Handles API keys and other configuration settings.
"""

import os
import yaml
from pathlib import Path
from rich.console import Console

console = Console()

# Default configuration
DEFAULT_CONFIG = {
    "api_keys": {
        "virustotal": None,
        "shodan": None,
        "emailrep": None,
        "haveibeenpwned": None,
        "ipinfo": None,
        "github": None,
    },
    "settings": {
        "output_directory": "osint_results",
        "timeout": 30,
        "max_threads": 10,
        "user_agent": "OSINT-CLI-Tool/1.0",
    }
}

# Global config variable
config = DEFAULT_CONFIG.copy()


def initialize_config():
    """Initialize configuration from environment variables or config file."""
    # Check for config file
    config_file = Path(os.path.expanduser("~/.osint_tool_config.yaml"))
    
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                loaded_config = yaml.safe_load(f)
                if loaded_config:
                    update_config_recursively(config, loaded_config)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load config file: {e}[/yellow]")
    
    # Load from environment variables (overrides file config)
    load_from_env()
    
    # Create output directory if it doesn't exist
    output_dir = Path(config["settings"]["output_directory"])
    output_dir.mkdir(exist_ok=True, parents=True)


def update_config_recursively(target, source):
    """Update configuration recursively."""
    for key, value in source.items():
        if isinstance(value, dict) and key in target:
            update_config_recursively(target[key], value)
        else:
            target[key] = value


def load_from_env():
    """Load configuration from environment variables."""
    # API Keys
    for api in config["api_keys"]:
        env_var = f"OSINT_{api.upper()}_API_KEY"
        if env_var in os.environ:
            config["api_keys"][api] = os.environ[env_var]
    
    # Settings
    if "OSINT_OUTPUT_DIR" in os.environ:
        config["settings"]["output_directory"] = os.environ["OSINT_OUTPUT_DIR"]
    
    if "OSINT_TIMEOUT" in os.environ:
        try:
            config["settings"]["timeout"] = int(os.environ["OSINT_TIMEOUT"])
        except ValueError:
            pass
    
    if "OSINT_MAX_THREADS" in os.environ:
        try:
            config["settings"]["max_threads"] = int(os.environ["OSINT_MAX_THREADS"])
        except ValueError:
            pass


def get_api_key(service):
    """Get API key for a specific service."""
    return config["api_keys"].get(service.lower())


def get_setting(setting):
    """Get a specific setting."""
    return config["settings"].get(setting)


def set_api_key(service, key):
    """Set API key for a specific service."""
    config["api_keys"][service.lower()] = key


def set_setting(setting, value):
    """Set a specific setting."""
    config["settings"][setting] = value


def save_config():
    """Save the current configuration to a file."""
    config_file = Path(os.path.expanduser("~/.osint_tool_config.yaml"))
    try:
        with open(config_file, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except Exception as e:
        console.print(f"[red]Error saving config: {e}[/red]")
        return False 