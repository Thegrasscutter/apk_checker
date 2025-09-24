"""
Configuration management for Agneyastra.
"""

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional


@dataclass
class Config:
    """Main configuration class for Agneyastra."""
    
    # Core settings
    debug: bool = False
    api_keys: List[str] = field(default_factory=list)
    project_ids: Dict[str, List[str]] = field(default_factory=dict)
    project_configs: Dict[str, Dict] = field(default_factory=dict)
    
    # Service settings
    correlate: bool = False
    secrets_extract: bool = False
    assets_extract: bool = False
    
    # File paths
    report_path: str = "./report.html"
    template_file: str = ""
    pentest_data_file_path: str = ""
    api_key_file: str = ""
    secrets_regex_file: str = ""
    
    # Service-specific configurations
    auth_config: Dict[str, Any] = field(default_factory=dict)
    bucket_config: Dict[str, Any] = field(default_factory=dict)
    firestore_config: Dict[str, Any] = field(default_factory=dict)
    rtdb_config: Dict[str, Any] = field(default_factory=dict)
    
    def update(self, config_data: Dict[str, Any]) -> None:
        """Update configuration with data from file."""
        if "general" in config_data:
            general = config_data["general"]
            self.debug = general.get("debug", self.debug)
        
        if "services" in config_data:
            services = config_data["services"]
            self.auth_config = services.get("auth", {})
            self.bucket_config = services.get("bucket", {})
            self.firestore_config = services.get("firestore", {})
            self.rtdb_config = services.get("rtdb", {})


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing config file: {e}")


def get_default_config_path() -> Path:
    """Get the default configuration file path."""
    return Path.home() / ".config" / "agneyastra" / "config.yaml"


def ensure_config_directory() -> Path:
    """Ensure the configuration directory exists."""
    config_dir = Path.home() / ".config" / "agneyastra"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir