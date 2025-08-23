"""Simple configuration for the encoding server."""

import os
from typing import List

class Settings:
    # Basic settings
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALLOWED_HOSTS: List[str] = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # Storage paths
    TEMP_STORAGE: str = os.getenv("TEMP_STORAGE", "/tmp/encoding")
    ENCRYPTED_STORAGE: str = os.getenv("ENCRYPTED_STORAGE", "/encrypted-storage")
    
    # FFmpeg
    FFMPEG_PATH: str = os.getenv("FFMPEG_PATH", "ffmpeg")
    MAX_CONCURRENT_JOBS: int = int(os.getenv("MAX_CONCURRENT_JOBS", "4"))
    
    # Encryption
    ENCRYPTION_MODE: str = os.getenv("ENCRYPTION_MODE", "dual")  # "automated", "manual", "dual"

settings = Settings()