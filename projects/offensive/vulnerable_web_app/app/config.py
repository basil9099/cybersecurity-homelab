"""Application configuration for BREACH."""

from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Application settings - intentionally insecure for training purposes."""

    APP_NAME: str = "BREACH"
    DEBUG: bool = True  # VULN: Debug mode enabled in production
    HOST: str = "127.0.0.1"
    PORT: int = 8080

    # Database
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATABASE_PATH: str = str(Path(__file__).resolve().parent.parent / "breach.db")

    # VULN: Hardcoded secret key
    SECRET_KEY: str = "super_secret_key_12345"

    # VULN: Weak JWT secret
    JWT_SECRET: str = "breach-jwt-secret"
    JWT_ALGORITHM: str = "HS256"

    # CTF Flag configuration
    FLAG_PREFIX: str = "FLAG"
    FLAG_FORMAT: str = "FLAG{{{content}}}"

    # File storage for path traversal challenge
    FILES_DIR: str = str(Path(__file__).resolve().parent.parent / "sandbox_files")


settings = Settings()
