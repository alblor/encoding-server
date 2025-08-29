"""
Centralized Secret Management System for Secure Media Encoding Server.

This module provides secure access to Docker secrets and manages the lifecycle
of sensitive configuration data without exposing secrets in environment variables
or hardcoding them in the application.

Author: Lorenzo Albanese (alblor)
"""

import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional, Set
from threading import Lock, Thread
import hashlib

logger = logging.getLogger(__name__)


class SecretNotFoundError(Exception):
    """Raised when a required secret cannot be found."""
    pass


class SecretManager:
    """
    Centralized secret management for Docker secrets integration.
    
    Provides secure access to secrets mounted at /run/secrets/ by Docker,
    with caching, validation, and monitoring capabilities.
    """
    
    def __init__(self, secrets_path: str = "/run/secrets", cache_ttl: int = 300):
        """
        Initialize the SecretManager.
        
        Args:
            secrets_path: Path where Docker mounts secrets (default: /run/secrets)
            cache_ttl: Cache time-to-live in seconds (default: 300s = 5min)
        """
        self.secrets_path = Path(secrets_path)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = Lock()
        self._required_secrets: Set[str] = set()
        self._health_status = {"healthy": True, "last_check": time.time(), "errors": []}
        
        # Log initialization
        if self.secrets_path.exists():
            logger.info(f"🔐 SecretManager initialized with Docker secrets at {secrets_path}")
        else:
            logger.warning(f"⚠️  Secrets path {secrets_path} does not exist - running without Docker secrets")
        
        # Start health monitoring thread
        self._start_health_monitor()
    
    def register_required_secret(self, secret_name: str) -> None:
        """
        Register a secret as required for system operation.
        
        Args:
            secret_name: Name of the required secret
        """
        self._required_secrets.add(secret_name)
        logger.debug(f"Registered required secret: {secret_name}")
    
    def get_secret(self, secret_name: str, required: bool = True) -> str:
        """
        Retrieve a secret value.
        
        Args:
            secret_name: Name of the secret to retrieve
            required: Whether the secret is required (raises exception if missing)
            
        Returns:
            The secret value as a string
            
        Raises:
            SecretNotFoundError: If required secret is not found
        """
        # Check cache first
        with self._cache_lock:
            if secret_name in self._cache:
                cache_entry = self._cache[secret_name]
                if time.time() - cache_entry["timestamp"] < self.cache_ttl:
                    logger.debug(f"Secret '{secret_name}' retrieved from cache")
                    return cache_entry["value"]
                else:
                    # Cache expired, remove entry
                    del self._cache[secret_name]
                    logger.debug(f"Cache expired for secret '{secret_name}'")
        
        # Try to read from Docker secrets
        secret_file = self.secrets_path / secret_name
        
        if secret_file.exists() and secret_file.is_file():
            try:
                # Read secret value
                secret_value = secret_file.read_text().strip()
                
                if not secret_value:
                    raise ValueError(f"Secret file {secret_name} is empty")
                
                # Cache the value
                with self._cache_lock:
                    self._cache[secret_name] = {
                        "value": secret_value,
                        "timestamp": time.time(),
                        "file_hash": self._get_file_hash(secret_file)
                    }
                
                logger.info(f"🔑 Secret '{secret_name}' loaded successfully from Docker secrets")
                return secret_value
                
            except Exception as e:
                error_msg = f"Failed to read secret '{secret_name}': {e}"
                logger.error(error_msg)
                
                if required:
                    raise SecretNotFoundError(error_msg)
                return ""
        
        # Secret file not found
        error_msg = f"Secret file '{secret_name}' not found at {secret_file}"
        
        if required:
            logger.error(f"❌ {error_msg}")
            raise SecretNotFoundError(error_msg)
        else:
            logger.warning(f"⚠️  {error_msg} (optional)")
            return ""
    
    def get_secret_hash(self, secret_name: str) -> Optional[str]:
        """
        Get SHA-256 hash of secret for validation without exposing the value.
        
        Args:
            secret_name: Name of the secret
            
        Returns:
            SHA-256 hash of the secret or None if not found
        """
        try:
            secret_value = self.get_secret(secret_name, required=False)
            if secret_value:
                return hashlib.sha256(secret_value.encode()).hexdigest()[:16]  # First 16 chars
        except Exception:
            pass
        return None
    
    def invalidate_cache(self, secret_name: Optional[str] = None) -> None:
        """
        Invalidate cached secrets.
        
        Args:
            secret_name: Specific secret to invalidate, or None for all secrets
        """
        with self._cache_lock:
            if secret_name:
                if secret_name in self._cache:
                    del self._cache[secret_name]
                    logger.info(f"Cache invalidated for secret '{secret_name}'")
            else:
                self._cache.clear()
                logger.info("All secret caches invalidated")
    
    def health_check(self) -> Dict:
        """
        Perform health check on secret management system.
        
        Returns:
            Dictionary containing health status information
        """
        health_info = {
            "secret_manager": "healthy",
            "secrets_path_exists": self.secrets_path.exists(),
            "cached_secrets": len(self._cache),
            "required_secrets_status": {},
            "last_check": time.time(),
            "errors": []
        }
        
        # Check all required secrets
        missing_secrets = []
        
        for secret_name in self._required_secrets:
            try:
                secret_hash = self.get_secret_hash(secret_name)
                health_info["required_secrets_status"][secret_name] = {
                    "available": secret_hash is not None,
                    "hash_prefix": secret_hash if secret_hash else "missing"
                }
                
                if not secret_hash:
                    missing_secrets.append(secret_name)
                    
            except Exception as e:
                health_info["required_secrets_status"][secret_name] = {
                    "available": False,
                    "error": str(e)
                }
                missing_secrets.append(secret_name)
        
        if missing_secrets:
            health_info["secret_manager"] = "degraded"
            health_info["errors"].append(f"Missing required secrets: {missing_secrets}")
        
        # Update internal health status
        with self._cache_lock:
            self._health_status = {
                "healthy": len(missing_secrets) == 0,
                "last_check": time.time(),
                "errors": health_info["errors"]
            }
        
        return health_info
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Get SHA-256 hash of file for change detection."""
        try:
            return hashlib.sha256(file_path.read_bytes()).hexdigest()[:16]
        except Exception:
            return "unknown"
    
    def _start_health_monitor(self) -> None:
        """Start background health monitoring thread."""
        def health_monitor():
            while True:
                try:
                    time.sleep(60)  # Check every minute
                    self.health_check()
                except Exception as e:
                    logger.error(f"Health monitor error: {e}")
        
        monitor_thread = Thread(target=health_monitor, daemon=True, name="SecretManager-HealthMonitor")
        monitor_thread.start()
        logger.info("🏥 SecretManager health monitoring started")
    
    def get_status_summary(self) -> Dict:
        """Get a summary of the current secret manager status."""
        with self._cache_lock:
            return {
                "secrets_path": str(self.secrets_path),
                "path_exists": self.secrets_path.exists(),
                "cached_secrets_count": len(self._cache),
                "required_secrets_count": len(self._required_secrets),
                "health_status": self._health_status.copy()
            }
    
    def __str__(self) -> str:
        """String representation of SecretManager."""
        return f"SecretManager(path={self.secrets_path}, cached={len(self._cache)}, required={len(self._required_secrets)})"


# Global instance (initialized in main.py)
secret_manager: Optional[SecretManager] = None


def get_secret_manager() -> SecretManager:
    """
    Get the global SecretManager instance.
    
    Returns:
        The initialized SecretManager instance
        
    Raises:
        RuntimeError: If SecretManager has not been initialized
    """
    if secret_manager is None:
        raise RuntimeError("SecretManager has not been initialized. Call initialize_secret_manager() first.")
    return secret_manager


def initialize_secret_manager(secrets_path: str = "/run/secrets", cache_ttl: int = 300) -> SecretManager:
    """
    Initialize the global SecretManager instance.
    
    Args:
        secrets_path: Path where Docker mounts secrets
        cache_ttl: Cache time-to-live in seconds
        
    Returns:
        The initialized SecretManager instance
    """
    global secret_manager
    
    if secret_manager is not None:
        logger.warning("SecretManager already initialized, returning existing instance")
        return secret_manager
    
    secret_manager = SecretManager(secrets_path, cache_ttl)
    logger.info("🔐 Global SecretManager initialized successfully")
    return secret_manager