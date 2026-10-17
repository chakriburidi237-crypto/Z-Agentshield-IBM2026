"""Configuration management for Z-AgentShield.

Loads application settings from environment variables or .env file.
Provides safe dictionary representations to prevent credential leakage.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings for Z-AgentShield."""

    # Application Metadata & Runtime Mode
    app_env: str = "demo"
    app_name: str = "Z-AgentShield"
    debug: bool = False
    log_level: str = "INFO"

    # API Server Network Settings
    host: str = "127.0.0.1"
    port: int = 8000

    # Persistence
    database_path: str = "data/zagentshield.db"

    # Policy Configuration File
    policy_config_path: str = "config/policies.yaml"

    # Risk Scoring Thresholds (0.0 to 100.0)
    risk_threshold_review: float = 40.0
    risk_threshold_block: float = 75.0

    # Behavioral Anomaly Detection Parameters
    anomaly_window_seconds: int = 60
    anomaly_burst_threshold: int = 10
    isolation_forest_contamination: float = 0.05

    # Data Redaction Flags
    redact_secrets: bool = True
    redact_pii: bool = True

    # Dashboard Network Settings
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8501

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return a representation of the configuration with any sensitive fields masked."""
        sensitive_patterns = {"key", "secret", "token", "password", "auth", "credential"}
        raw_dict = self.model_dump()
        safe_dict: Dict[str, Any] = {}

        for key, value in raw_dict.items():
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in sensitive_patterns):
                safe_dict[key] = "********" if value else None
            else:
                safe_dict[key] = value

        return safe_dict


@lru_cache()
def get_settings() -> Settings:
    """Return a cached singleton instance of Settings."""
    return Settings()
