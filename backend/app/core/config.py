"""EviPhish Core Configuration.

Defines application settings, security constraints, and database connection.
"""
from pathlib import Path
import os
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    APP_NAME: str = "EviPhish - Evidence-First Phishing Email Forensics Platform"
    APP_VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"
    
    # Storage & DB
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'eviphish.db'}"
    
    # Security & Upload Constraints
    MAX_UPLOAD_SIZE_BYTES: int = 15 * 1024 * 1024  # 15 MB
    ALLOWED_EXTENSIONS: set[str] = {".eml"}
    
    # Reputation
    REPUTATION_PROVIDER: str = "emailrep"
    EMAILREP_API_KEY: str | None = os.getenv("EMAILREP_API_KEY")
    
    # CORS: Restricted to local development frontend
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

settings = Settings()
