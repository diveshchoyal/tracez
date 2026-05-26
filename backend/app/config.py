"""TraceZ Backend — Configuration from environment variables."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the backend directory
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    # Try .env.example as fallback in dev
    _example = Path(__file__).resolve().parent.parent / ".env.example"
    if _example.exists():
        load_dotenv(_example)


class Settings:
    """Application settings loaded from environment variables."""

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./tracez.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-in-production-" + "x" * 32)
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@1")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "divesh@9192")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

    # CORS
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "chrome-extension://,http://localhost:3000").split(",")
        if o.strip()
    ]

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    SCAN_RATE_LIMIT: int = 30
    AUTH_RATE_LIMIT: int = 5

    # JWT
    JWT_EXPIRY_HOURS: int = 12
    JWT_ALGORITHM: str = "HS256"

    # Files
    MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024  # 50 MB

    # Blocklist
    BLOCKLIST_SYNC_HOURS: int = 6

    @property
    def is_dev(self) -> bool:
        return self.ENVIRONMENT == "development"


settings = Settings()
