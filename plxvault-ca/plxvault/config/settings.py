"""PlxVault configuration settings."""

import os
from typing import List


class Settings:
    """Application settings loaded from environment."""

    def __init__(self):
        self.environment: str = os.getenv("PLXVAULT_ENV", "development")
        self.debug: bool = os.getenv("PLXVAULT_DEBUG", "false").lower() == "true"

        # Server
        self.host: str = os.getenv("PLXVAULT_HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PLXVAULT_PORT", "8000"))

        # Database
        self.database_url: str = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://plxvault:plxvault@localhost:5432/plxvault",
        )

        # Redis
        self.redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379")

        # Security
        self.secret_key: str = os.getenv("PLXVAULT_SECRET_KEY", "change-me-in-production")
        self.master_key_source: str = os.getenv("MASTER_KEY_SOURCE", "env")

        # CORS
        cors_origins = os.getenv("CORS_ORIGINS", "*")
        self.cors_origins: List[str] = (
            ["*"] if cors_origins == "*" else cors_origins.split(",")
        )

        # CA defaults
        self.default_ca: str = os.getenv("DEFAULT_CA", "PlxVault-Root-CA")
        self.default_validity_days: int = int(os.getenv("DEFAULT_VALIDITY_DAYS", "365"))
        self.default_key_algorithm: str = os.getenv("DEFAULT_KEY_ALGORITHM", "ecdsa-p256")

        # Post-quantum
        self.pqc_enabled: bool = os.getenv("PQC_ENABLED", "true").lower() == "true"
        self.pqc_default_hybrid: bool = (
            os.getenv("PQC_DEFAULT_HYBRID", "false").lower() == "true"
        )

        # Rate limiting
        self.rate_limit_enabled: bool = (
            os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
        )
        self.rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
        self.rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"
