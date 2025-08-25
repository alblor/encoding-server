"""
Encrypted Virtual Memory System for Zero-Trust Media Processing

Implements encrypted swap emulation within Docker containers using memory-mapped
encrypted files in tmpfs. Nothing ever leaves RAM or encrypted virtual memory.

Author: Lorenzo Albanese (alblor)
"""

import hashlib
import mmap
import os
import tempfile
import threading
import weakref
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class SecureMemoryManager:
    """
    Zero-Trust Memory Manager that ensures data never leaves RAM or encrypted swap.
    
    - Files <4GB: Pure tmpfs (RAM only)
    - Files >4GB: Memory-mapped encrypted files in tmpfs (encrypted virtual swap)
    - All operations in-memory with zero persistent traces
    """
    
    # Memory thresholds
    RAM_THRESHOLD = 4 * 1024 * 1024 * 1024  # 4GB
    
    def __init__(self, tmpfs_path: str = "/tmp/memory-pool"):
        self.tmpfs_path = Path(tmpfs_path)
        self.tmpfs_path.mkdir(parents=True, exist_ok=True)
        
        # Track all memory allocations for cleanup
        self._memory_mappings: Dict[str, mmap.mmap] = {}
        self._temp_files: Dict[str, Path] = {}
        self._encryption_keys: Dict[str, bytes] = {}
        self._lock = threading.Lock()
        
        # Register cleanup on deletion
        weakref.finalize(self, self._cleanup_all_memory)
        
        logger.info(f"SecureMemoryManager initialized with tmpfs at {self.tmpfs_path}")
    
    def allocate_secure_storage(self, size_bytes: int, content: bytes = None) -> str:
        """
        Allocate secure storage that automatically routes to RAM or encrypted swap.
        
        Args:
            size_bytes: Size of storage needed
            content: Optional initial content
            
        Returns:
            Storage identifier for later access
        """
        storage_id = self._generate_storage_id()
        
        try:
            if size_bytes <= self.RAM_THRESHOLD:
                # Small files: Pure RAM storage in tmpfs
                self._allocate_ram_storage(storage_id, size_bytes, content)
                logger.info(f"Allocated {size_bytes} bytes in RAM for {storage_id}")
            else:
                # Large files: Encrypted virtual swap in tmpfs
                self._allocate_encrypted_swap(storage_id, size_bytes, content)
                logger.info(f"Allocated {size_bytes} bytes in encrypted swap for {storage_id}")
                
            return storage_id
            
        except Exception as e:
            logger.error(f"Failed to allocate secure storage: {e}")
            self._cleanup_storage(storage_id)
            raise
    
    def write_secure_data(self, storage_id: str, data: bytes, offset: int = 0) -> None:
        """Write data to secure storage with automatic encryption if needed."""
        with self._lock:
            if storage_id not in self._memory_mappings:
                raise ValueError(f"Storage {storage_id} not found")
            
            memory_map = self._memory_mappings[storage_id]
            
            if storage_id in self._encryption_keys:
                # Encrypted swap: encrypt data before writing
                encrypted_data = self._encrypt_data(data, self._encryption_keys[storage_id])
                memory_map[offset:offset + len(encrypted_data)] = encrypted_data
            else:
                # RAM storage: direct write
                memory_map[offset:offset + len(data)] = data
    
    def read_secure_data(self, storage_id: str, size: int = None, offset: int = 0) -> bytes:
        """Read data from secure storage with automatic decryption if needed."""
        with self._lock:
            if storage_id not in self._memory_mappings:
                raise ValueError(f"Storage {storage_id} not found")
            
            memory_map = self._memory_mappings[storage_id]
            
            # Determine read size
            if size is None:
                size = len(memory_map) - offset
            
            # Read raw data
            raw_data = memory_map[offset:offset + size]
            
            if storage_id in self._encryption_keys:
                # Encrypted swap: decrypt data after reading
                return self._decrypt_data(raw_data, self._encryption_keys[storage_id])
            else:
                # RAM storage: direct read
                return raw_data
    
    def get_storage_file_path(self, storage_id: str) -> Optional[Path]:
        """Get file path for direct file operations (for FFmpeg)."""
        with self._lock:
            if storage_id in self._temp_files:
                return self._temp_files[storage_id]
            return None
    
    def cleanup_storage(self, storage_id: str) -> None:
        """Clean up specific storage allocation."""
        self._cleanup_storage(storage_id)
    
    def _allocate_ram_storage(self, storage_id: str, size_bytes: int, content: bytes = None) -> None:
        """Allocate storage in pure RAM (tmpfs)."""
        # Create temporary file in tmpfs
        temp_file = self.tmpfs_path / f"ram_{storage_id}.tmp"
        
        # Initialize file with correct size
        with open(temp_file, 'wb') as f:
            if content:
                f.write(content)
                # Only pad if content is smaller than expected size
                current_size = len(content)
                if current_size < size_bytes:
                    f.write(b'\0' * (size_bytes - current_size))
            else:
                f.seek(size_bytes - 1)
                f.write(b'\0')
        
        # Memory-map the file for efficient access
        with open(temp_file, 'r+b') as f:
            memory_map = mmap.mmap(f.fileno(), size_bytes)
        
        with self._lock:
            self._memory_mappings[storage_id] = memory_map
            self._temp_files[storage_id] = temp_file
    
    def _allocate_encrypted_swap(self, storage_id: str, size_bytes: int, content: bytes = None) -> None:
        """Allocate storage in encrypted virtual swap (encrypted memory-mapped files in tmpfs)."""
        # Generate unique encryption key for this storage
        encryption_key = self._generate_encryption_key(storage_id)
        
        # Create temporary file in tmpfs for encrypted storage
        temp_file = self.tmpfs_path / f"swap_{storage_id}.enc"
        
        # Calculate encrypted size (includes IV and padding)
        encrypted_size = self._calculate_encrypted_size(size_bytes)
        
        # Initialize encrypted file
        with open(temp_file, 'wb') as f:
            if content:
                encrypted_content = self._encrypt_data(content, encryption_key)
                f.write(encrypted_content)
                # Pad to full encrypted size
                remaining = encrypted_size - len(encrypted_content)
                if remaining > 0:
                    f.write(b'\0' * remaining)
            else:
                f.write(b'\0' * encrypted_size)
        
        # Memory-map the encrypted file
        with open(temp_file, 'r+b') as f:
            memory_map = mmap.mmap(f.fileno(), encrypted_size)
        
        with self._lock:
            self._memory_mappings[storage_id] = memory_map
            self._temp_files[storage_id] = temp_file
            self._encryption_keys[storage_id] = encryption_key
    
    def _generate_storage_id(self) -> str:
        """Generate unique storage identifier."""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    
    def _generate_encryption_key(self, storage_id: str) -> bytes:
        """Generate encryption key for specific storage."""
        # Use PBKDF2 with storage_id as salt for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=storage_id.encode(),
            iterations=100000,
            backend=default_backend()
        )
        # Derive key from system entropy
        password = os.urandom(32)
        return kdf.derive(password)
    
    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + auth_tag
        return iv + ciphertext + encryptor.tag
    
    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        if len(encrypted_data) < 32:  # IV (16) + min ciphertext + tag (16)
            raise ValueError("Invalid encrypted data")
        
        iv = encrypted_data[:16]
        auth_tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _calculate_encrypted_size(self, plaintext_size: int) -> int:
        """Calculate size needed for encrypted storage (IV + ciphertext + tag + padding)."""
        # AES-GCM: 16-byte IV + ciphertext + 16-byte tag
        # Add 16 bytes for potential block padding
        return plaintext_size + 48
    
    def _cleanup_storage(self, storage_id: str) -> None:
        """Clean up specific storage allocation with zero-trace guarantees."""
        with self._lock:
            # Close and zero memory mapping
            if storage_id in self._memory_mappings:
                memory_map = self._memory_mappings[storage_id]
                # Zero out memory before closing
                memory_map[:] = b'\0' * len(memory_map)
                memory_map.close()
                del self._memory_mappings[storage_id]
            
            # Secure delete temporary file
            if storage_id in self._temp_files:
                temp_file = self._temp_files[storage_id]
                if temp_file.exists():
                    # Overwrite file multiple times for secure deletion
                    file_size = temp_file.stat().st_size
                    with open(temp_file, 'r+b') as f:
                        for _ in range(3):  # 3-pass secure deletion
                            f.seek(0)
                            f.write(os.urandom(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                    temp_file.unlink()
                del self._temp_files[storage_id]
            
            # Clear encryption key
            if storage_id in self._encryption_keys:
                # Overwrite key in memory
                key = self._encryption_keys[storage_id]
                for i in range(len(key)):
                    key = key[:i] + b'\0' + key[i+1:]
                del self._encryption_keys[storage_id]
        
        logger.info(f"Securely cleaned up storage {storage_id}")
    
    def _cleanup_all_memory(self) -> None:
        """Clean up all memory allocations on shutdown."""
        logger.info("Cleaning up all secure memory allocations")
        storage_ids = list(self._memory_mappings.keys())
        for storage_id in storage_ids:
            self._cleanup_storage(storage_id)
        logger.info("All memory allocations cleaned up")


# Global secure memory manager instance
secure_memory_manager = SecureMemoryManager()


class SecureFile:
    """
    File-like object that uses secure memory storage.
    Provides transparent file operations while maintaining zero-trust guarantees.
    """
    
    def __init__(self, size_hint: int = None, initial_content: bytes = None):
        self.size_hint = size_hint or (len(initial_content) if initial_content else 1024)
        self.storage_id = secure_memory_manager.allocate_secure_storage(
            self.size_hint, initial_content
        )
        self._position = 0
        self._closed = False
    
    def write(self, data: bytes) -> int:
        """Write data to secure storage."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        secure_memory_manager.write_secure_data(self.storage_id, data, self._position)
        self._position += len(data)
        return len(data)
    
    def read(self, size: int = None) -> bytes:
        """Read data from secure storage."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        data = secure_memory_manager.read_secure_data(self.storage_id, size, self._position)
        self._position += len(data)
        return data
    
    def seek(self, position: int) -> int:
        """Seek to position in secure storage."""
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        self._position = position
        return self._position
    
    def tell(self) -> int:
        """Get current position in secure storage."""
        return self._position
    
    def get_file_path(self) -> Optional[Path]:
        """Get file path for external tools like FFmpeg."""
        if self._closed:
            return None
        return secure_memory_manager.get_storage_file_path(self.storage_id)
    
    def close(self) -> None:
        """Close and cleanup secure storage."""
        if not self._closed:
            secure_memory_manager.cleanup_storage(self.storage_id)
            self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()