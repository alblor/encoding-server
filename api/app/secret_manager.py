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
        Initialize the SecretManager with support for multiple fallback paths.
        
        Args:
            secrets_path: Primary path where Docker mounts secrets (default: /run/secrets)
            cache_ttl: Cache time-to-live in seconds (default: 300s = 5min)
        """
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = Lock()
        self._required_secrets: Set[str] = set()
        self._health_status = {"healthy": True, "last_check": time.time(), "errors": []}
        
        # Define multiple secret paths in order of preference (Docker-in-LXC support)
        self.secret_paths = [
            Path(os.environ.get("SECURE_SECRETS_PATH", "/tmp/secure-secrets")),  # LXC fallback (tmpfs)
            Path(secrets_path),                                                  # Standard Docker secrets
            Path("./secrets"),                                                   # Local development fallback
        ]
        
        # Find the first available path and log status
        self.primary_path = None
        for i, path in enumerate(self.secret_paths):
            if path.exists() and path.is_dir():
                self.primary_path = path
                path_type = ["tmpfs fallback", "Docker secrets", "local development"][i]
                logger.info(f"🔐 SecretManager using {path_type} at: {path}")
                break
        
        if not self.primary_path:
            logger.warning("⚠️  No secrets directory found - will use environment variable fallback")
            self.primary_path = Path(secrets_path)  # Default fallback for error handling
        
        # Legacy compatibility - maintain secrets_path for backward compatibility
        self.secrets_path = self.primary_path
        
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
        
        # Try to read from multiple secret paths in order of preference
        last_error = None
        for i, path in enumerate(self.secret_paths):
            secret_file = path / secret_name
            
            if secret_file.exists() and secret_file.is_file():
                try:
                    # Read secret value
                    secret_value = secret_file.read_text().strip()
                    
                    if not secret_value:
                        logger.warning(f"Secret file {secret_file} is empty")
                        continue  # Try next path
                    
                    # Cache the value
                    with self._cache_lock:
                        self._cache[secret_name] = {
                            "value": secret_value,
                            "timestamp": time.time(),
                            "file_hash": self._get_file_hash(secret_file)
                        }
                    
                    path_type = ["tmpfs fallback", "Docker secrets", "local development"][i]
                    logger.info(f"🔑 Secret '{secret_name}' loaded successfully from {path_type}")
                    return secret_value
                    
                except PermissionError as e:
                    logger.warning(f"Permission denied reading {secret_file}: {e}")
                    last_error = e
                    continue  # Try next path
                except Exception as e:
                    error_msg = f"Failed to read secret '{secret_name}' from {secret_file}: {e}"
                    logger.warning(error_msg)
                    last_error = e
                    continue  # Try next path
        
        # Fallback to environment variable (Docker-in-LXC compatibility)
        env_var_name = secret_name.upper()
        if env_var_name in os.environ:
            env_value = os.environ[env_var_name].strip()
            if env_value:
                logger.info(f"🔑 Secret '{secret_name}' loaded from environment variable")
                # Cache the environment variable value
                with self._cache_lock:
                    self._cache[secret_name] = {
                        "value": env_value,
                        "timestamp": time.time(),
                        "file_hash": "env_variable"  # Special marker for env vars
                    }
                return env_value
        
        # Secret not found anywhere
        tried_paths = [str(path / secret_name) for path in self.secret_paths]
        error_msg = f"Secret '{secret_name}' not found in any location: {tried_paths}"
        if last_error:
            error_msg += f" (last error: {last_error})"
        
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
    
    def get_lifecycle_status(self) -> Dict:
        """
        Check secret lifecycle status to determine if secrets are shredded on host.
        
        Returns:
            Dictionary containing lifecycle information
        """
        # Check host filesystem for shredded secrets
        host_secrets_path = Path("./secrets")  # Host filesystem path
        shred_marker = "SHREDDED_FOR_SECURITY"
        
        secret_status = {}
        total_secrets = 0
        shredded_secrets = 0
        
        # Check each required secret on host filesystem
        secret_names = ["jwt_secret", "encryption_master_key", "redis_password", "api_master_key"]
        
        for secret_name in secret_names:
            total_secrets += 1
            host_secret_file = host_secrets_path / secret_name
            
            if host_secret_file.exists():
                try:
                    content = host_secret_file.read_text().strip()
                    if content.startswith(shred_marker):
                        secret_status[secret_name] = "SHREDDED"
                        shredded_secrets += 1
                    else:
                        secret_status[secret_name] = "ON_DISK"
                except Exception:
                    secret_status[secret_name] = "UNKNOWN"
            else:
                secret_status[secret_name] = "MISSING"
        
        # Determine overall security mode
        if shredded_secrets == total_secrets:
            security_mode = "MAXIMUM_SECURITY"
            security_description = "Secrets exist only in container memory (tmpfs)"
            attack_surface = "MINIMAL"
        elif shredded_secrets > 0:
            security_mode = "MIXED_SECURITY"
            security_description = f"{shredded_secrets}/{total_secrets} secrets shredded"
            attack_surface = "ELEVATED"
        else:
            security_mode = "STANDARD_SECURITY"  
            security_description = "Secrets stored on host filesystem"
            attack_surface = "STANDARD"
        
        return {
            "security_mode": security_mode,
            "security_description": security_description,
            "attack_surface": attack_surface,
            "total_secrets": total_secrets,
            "shredded_secrets": shredded_secrets,
            "disk_secrets": total_secrets - shredded_secrets,
            "secret_details": secret_status,
            "memory_only_operation": shredded_secrets == total_secrets,
            "disk_exposure_reduced": f"{(shredded_secrets/total_secrets)*100:.1f}%" if total_secrets > 0 else "0%"
        }
    
    def get_status_summary(self) -> Dict:
        """Get a summary of the current secret manager status."""
        with self._cache_lock:
            base_status = {
                "secrets_path": str(self.secrets_path),
                "path_exists": self.secrets_path.exists(),
                "cached_secrets_count": len(self._cache),
                "required_secrets_count": len(self._required_secrets),
                "health_status": self._health_status.copy()
            }
            
            # Add lifecycle status
            lifecycle_status = self.get_lifecycle_status()
            base_status["lifecycle"] = lifecycle_status
            
            return base_status
    
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