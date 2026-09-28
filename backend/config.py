"""
Configuration management for Resilience Forge.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
import os

from utils.secrets import get_secret

# Known insecure development defaults. A secret still equal to one of these in a
# non-DEBUG deployment is rejected by enforce_secure_config() (DRRA-006).
DEV_SECRET_KEY = "dev-secret-key-change-in-production"
DEV_DB_URL = "postgresql://drra_admin:drra_secure_password@localhost:5432/resilience_forge"
DEV_MINIO_KEY = "minioadmin"

# Secrets resolved through the external-secrets provider (utils.secrets). Env
# vars still take precedence over the default_factory; the factory adds support
# for `{NAME}_FILE` mounts (Vault Agent / k8s / Docker secrets) and rotation.
_FILE_BACKED_SECRETS = {
    "DATABASE_URL": DEV_DB_URL,
    "MINIO_ACCESS_KEY": DEV_MINIO_KEY,
    "MINIO_SECRET_KEY": DEV_MINIO_KEY,
    "SECRET_KEY": DEV_SECRET_KEY,
    "GEMINI_API_KEY": "",
}


class Settings(BaseSettings):
    """Application settings loaded from environment variables and secret mounts."""

    # API Configuration
    API_TITLE: str = "Resilience Forge (DRRA)"
    API_VERSION: str = "0.1.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # Secrets provider posture (see utils.secrets): "env" or "file".
    SECRETS_PROVIDER: str = os.getenv("SECRETS_PROVIDER", "env")

    # Database
    DATABASE_URL: str = Field(default_factory=lambda: get_secret("DATABASE_URL", DEV_DB_URL))

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

    # MinIO
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    MINIO_ACCESS_KEY: str = Field(default_factory=lambda: get_secret("MINIO_ACCESS_KEY", DEV_MINIO_KEY))
    MINIO_SECRET_KEY: str = Field(default_factory=lambda: get_secret("MINIO_SECRET_KEY", DEV_MINIO_KEY))
    MINIO_SECURE: bool = os.getenv("MINIO_SECURE", "False").lower() == "true"
    MINIO_BUCKET_LOGS: str = os.getenv("MINIO_BUCKET_LOGS", "immutable-logs")
    MINIO_BUCKET_ARTIFACTS: str = os.getenv("MINIO_BUCKET_ARTIFACTS", "forensic-artifacts")

    # Security
    SECRET_KEY: str = Field(default_factory=lambda: get_secret("SECRET_KEY", DEV_SECRET_KEY))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Gemini AI
    GEMINI_API_KEY: str = Field(default_factory=lambda: get_secret("GEMINI_API_KEY", ""))
    GEMINI_MODEL: str = "gemini-2.5-flash"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8080"
    ]
    
    # Detection thresholds
    MASS_MODIFICATION_THRESHOLD: float = 0.15  # 15% file modification rate
    ENTROPY_THRESHOLD: float = 0.85  # Encryption entropy detection
    MTTC_TARGET_SECONDS: int = 60  # Mean Time to Contain target
    
    # VIGIL model
    VIGIL_MODEL_PATH: str = os.getenv("VIGIL_MODEL_PATH", "")
    VIGIL_DECISION_THRESHOLD: float = 0.85  # theta
    VIGIL_CONTAMINATION: float = 0.02

    # SHIELD containment
    SHIELD_CONTAINMENT_PROVIDER: str = os.getenv("SHIELD_CONTAINMENT_PROVIDER", "simulation")  # simulation|crowdstrike
    SHIELD_SIM_SPEED: float = float(os.getenv("SHIELD_SIM_SPEED", "0"))  # 0 = instant (report modelled MTTC)

    # Defensibility Index calibration (canonical mapping; see services/defensibility.py)
    DI_MAX_SCORE: int = 100
    DI_WEIGHT_DETECTION: float = 0.30     # alpha  — MTTD efficiency
    DI_WEIGHT_ISOLATION: float = 0.30     # beta   — MTTC efficiency
    DI_WEIGHT_RECOVERY: float = 0.25      # gamma  — prevention (1 - APCR)
    DI_WEIGHT_IMMUTABILITY: float = 0.15  # delta  — recovery fidelity
    DI_DETECTION_DEADLINE_SECONDS: float = 300.0  # T_drrt

    class Config:
        env_file = ".env"
        case_sensitive = True

    def refresh_secrets(self) -> None:
        """Re-resolve file-backed secrets so a rotated `{NAME}_FILE` mount is
        picked up without a process restart (DRRA-006 rotation support).

        Env vars still win over file mounts, so a secret pinned via a plain env
        var is left untouched; only file/default-backed secrets are refreshed.
        """
        for name, default in _FILE_BACKED_SECRETS.items():
            if os.getenv(name) is not None:
                continue  # a plain env var pins this secret; do not override it
            setattr(self, name, get_secret(name, default))

    def assert_production_ready(self) -> list:
        """Return a list of misconfigurations that are unsafe in production.

        This is the audit; `enforce_secure_config` turns it into a hard failure.
        """
        problems = []
        if not self.SECRET_KEY or self.SECRET_KEY == DEV_SECRET_KEY:
            problems.append("SECRET_KEY is unset or the built-in development default")
        if self.MINIO_ACCESS_KEY == DEV_MINIO_KEY and self.MINIO_SECRET_KEY == DEV_MINIO_KEY:
            problems.append("MinIO is using default minioadmin credentials")
        if not self.MINIO_ACCESS_KEY or not self.MINIO_SECRET_KEY:
            problems.append("MinIO credentials are unset")
        if "drra_secure_password" in self.DATABASE_URL:
            problems.append("DATABASE_URL contains the default database password")
        if not self.MINIO_SECURE:
            problems.append("MINIO_SECURE is False (TLS disabled for object storage)")
        return problems

    def enforce_secure_config(self) -> None:
        """Fail fast: raise if the deployment is running on insecure defaults.

        Called at startup when DEBUG is False so the process refuses to serve
        with development credentials rather than silently exposing them.
        """
        problems = self.assert_production_ready()
        if problems:
            raise RuntimeError(
                "Refusing to start with insecure configuration (DRRA-006). "
                "Provide real secrets via `{NAME}_FILE` mounts or environment "
                "variables. Problems: " + "; ".join(problems)
            )

settings = Settings()
