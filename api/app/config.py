"""Secure configuration for the encoding server with Docker secrets integration."""

import logging
import os
from typing import List, Optional
from .secret_manager import get_secret_manager, SecretNotFoundError

class Settings:
    def __init__(self):
        """Initialize settings with SecretManager integration."""
        # Get the SecretManager instance (must be initialized first)
        try:
            self.secret_manager = get_secret_manager()
            self._secrets_available = True
        except RuntimeError:
            # SecretManager not initialized yet (during startup)
            self.secret_manager = None
            self._secrets_available = False
            
        # Initialize settings
        self._initialize_settings()
    
    def _initialize_settings(self):
        """Initialize all configuration settings."""
        # Basic settings (non-sensitive, from environment)
        self.DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
        self.HOST: str = os.getenv("HOST", "0.0.0.0")
        self.PORT: int = int(os.getenv("PORT", "8000"))
        
        # Logging configuration - SINGLE SOURCE OF TRUTH
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING").upper()
        
        # Security settings (sensitive, from Docker secrets)
        self.SECRET_KEY: str = self._get_secret_or_fail("jwt_secret")
        self.ENCRYPTION_MASTER_KEY: str = self._get_secret_or_fail("encryption_master_key")
        self.API_MASTER_KEY: str = self._get_secret_or_fail("api_master_key")
        
        # Non-sensitive security settings
        self.ALLOWED_HOSTS: List[str] = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
        
        # Redis configuration with authentication
        import urllib.parse
        redis_password = self._get_secret_or_fail("redis_password")
        redis_host = os.getenv("REDIS_HOST", "redis-secure")
        redis_port = os.getenv("REDIS_PORT", "6379")
        # URL-encode the password to handle special characters
        encoded_password = urllib.parse.quote(redis_password, safe="")
        self.REDIS_URL: str = f"redis://:{encoded_password}@{redis_host}:{redis_port}"
        
        # Storage paths (non-sensitive)
        self.TEMP_STORAGE: str = os.getenv("TEMP_STORAGE", "/tmp/encoding")
        self.ENCRYPTED_STORAGE: str = os.getenv("ENCRYPTED_STORAGE", "/encrypted-storage")
        
        # FFmpeg configuration (non-sensitive)
        self.FFMPEG_PATH: str = os.getenv("FFMPEG_PATH", "ffmpeg")
        self.MAX_CONCURRENT_JOBS: int = int(os.getenv("MAX_CONCURRENT_JOBS", "4"))
        
        # Encryption configuration (non-sensitive)
        self.ENCRYPTION_MODE: str = os.getenv("ENCRYPTION_MODE", "dual")  # "automated", "manual", "dual"
        
    def _get_secret_or_fail(self, secret_name: str) -> str:
        """
        Get a secret from SecretManager or fail fast if not available.
        
        Args:
            secret_name: Name of the secret to retrieve
            
        Returns:
            The secret value
            
        Raises:
            RuntimeError: If secret cannot be retrieved
        """
        if not self._secrets_available or not self.secret_manager:
            raise RuntimeError(
                f"Cannot initialize secure configuration: SecretManager not available. "
                f"Required secret: {secret_name}"
            )
        
        try:
            # Register as required secret for health monitoring
            self.secret_manager.register_required_secret(secret_name)
            return self.secret_manager.get_secret(secret_name, required=True)
        except SecretNotFoundError as e:
            raise RuntimeError(
                f"Critical configuration error: {e}. "
                f"Generate secrets with: ./scripts/generate_secrets.sh"
            )
    
    def reinitialize_with_secret_manager(self, secret_manager):
        """
        Reinitialize settings after SecretManager is available.
        
        Args:
            secret_manager: Initialized SecretManager instance
        """
        self.secret_manager = secret_manager
        self._secrets_available = True
        self._initialize_settings()
        logging.getLogger(__name__).info("🔐 Settings reinitialized with Docker secrets")
    
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

# Global settings instance (will be properly initialized in main.py)
settings: Optional[Settings] = None


def initialize_settings() -> Settings:
    """
    Initialize the global settings instance.
    
    Returns:
        The initialized Settings instance
    """
    global settings
    
    if settings is not None:
        return settings
        
    settings = Settings()
    return settings


def get_settings() -> Settings:
    """
    Get the global settings instance.
    
    Returns:
        The initialized Settings instance
        
    Raises:
        RuntimeError: If settings have not been initialized
    """
    if settings is None:
        raise RuntimeError("Settings have not been initialized. Call initialize_settings() first.")
    return settings