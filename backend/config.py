"""
Configuration management for Resilience Forge.
"""

from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    API_TITLE: str = "Resilience Forge (DRRA)"
    API_VERSION: str = "0.1.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://drra_admin:drra_secure_password@localhost:5432/resilience_forge")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    
    # MinIO
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    MINIO_SECURE: bool = os.getenv("MINIO_SECURE", "False").lower() == "true"
    MINIO_BUCKET_LOGS: str = os.getenv("MINIO_BUCKET_LOGS", "immutable-logs")
    MINIO_BUCKET_ARTIFACTS: str = os.getenv("MINIO_BUCKET_ARTIFACTS", "forensic-artifacts")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Gemini AI
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
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

    def assert_production_ready(self) -> list:
        """Return a list of misconfigurations that are unsafe in production.

        Called at startup when DEBUG is False so the process fails fast rather
        than silently running with development credentials.
        """
        problems = []
        if self.SECRET_KEY == "dev-secret-key-change-in-production":
            problems.append("SECRET_KEY is the built-in development default")
        if self.MINIO_ACCESS_KEY == "minioadmin" and self.MINIO_SECRET_KEY == "minioadmin":
            problems.append("MinIO is using default minioadmin credentials")
        if "drra_secure_password" in self.DATABASE_URL:
            problems.append("DATABASE_URL contains the default database password")
        if not self.MINIO_SECURE:
            problems.append("MINIO_SECURE is False (TLS disabled for object storage)")
        return problems

settings = Settings()
