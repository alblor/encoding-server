"""Simple configuration for the encoding server."""

import logging
import os
from typing import List

class Settings:
    # Basic settings
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Logging configuration - SINGLE SOURCE OF TRUTH
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING").upper()
    
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
    
    def get_log_level(self) -> int:
        """Convert LOG_LEVEL string to logging level integer."""
        levels = {
            "DEBUG": logging.DEBUG,      # 10 - Most verbose
            "INFO": logging.INFO,        # 20 - Job lifecycle  
            "WARNING": logging.WARNING,  # 30 - Security warnings
            "ERROR": logging.ERROR,      # 40 - Failures only
            "CRITICAL": logging.CRITICAL # 50 - System critical
        }
        return levels.get(self.LOG_LEVEL, logging.WARNING)
    
    def get_log_level_string(self) -> str:
        """Get lowercase log level for uvicorn."""
        return self.LOG_LEVEL.lower()

settings = Settings()