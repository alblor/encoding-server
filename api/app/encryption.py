"""Dual-mode encryption system for media files with Docker secrets integration."""

import base64
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Optional, Tuple, Dict
import redis

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    Handles both automated and manual encryption modes with secure key management.
    
    Uses Docker secrets for master key and Redis for encrypted key storage.
    """
    
    def __init__(self, master_key: str, redis_client: redis.Redis):
        """
        Initialize EncryptionManager with secure key storage.
        
        Args:
            master_key: Master encryption key from Docker secrets
            redis_client: Authenticated Redis client for key storage
        """
        self.chunk_size = 64 * 1024  # 64KB chunks for streaming
        self.master_key = base64.b64decode(master_key.encode())
        self.redis_client = redis_client
        self.key_ttl = 3600  # Keys expire after 1 hour
        
        logger.info("🔐 EncryptionManager initialized with secure key vault")
    
    def generate_key(self) -> bytes:
        """Generate a random AES-256 key."""
        return os.urandom(32)  # 256 bits
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ECDH keypair for automated mode."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_bytes, public_bytes
    
    def encrypt_file(self, input_path: str, output_path: str, key: bytes) -> dict:
        """Encrypt a file using AES-256-GCM."""
        iv = os.urandom(16)  # 128-bit IV for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        # Write IV at the beginning of the file
        with open(output_file, 'wb') as outf:
            outf.write(iv)
            
            with open(input_file, 'rb') as inf:
                while chunk := inf.read(self.chunk_size):
                    encrypted_chunk = encryptor.update(chunk)
                    outf.write(encrypted_chunk)
            
            # Write the authentication tag
            outf.write(encryptor.finalize())
            tag = encryptor.tag
            outf.write(tag)
        
        return {
            'encrypted_file': str(output_file),
            'iv': iv.hex(),
            'size': output_file.stat().st_size,
            'original_size': input_file.stat().st_size
        }
    
    def decrypt_file(self, input_path: str, output_path: str, key: bytes) -> dict:
        """Decrypt a file using AES-256-GCM."""
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        with open(input_file, 'rb') as inf:
            # Read IV (first 16 bytes)
            iv = inf.read(16)
            
            # Read the encrypted data (everything except the last 16 bytes which is the tag)
            file_size = input_file.stat().st_size
            encrypted_size = file_size - 16 - 16  # minus IV and tag
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            decryptor = cipher.decryptor()
            
            with open(output_file, 'wb') as outf:
                remaining = encrypted_size
                while remaining > 0:
                    chunk_size = min(self.chunk_size, remaining)
                    encrypted_chunk = inf.read(chunk_size)
                    if not encrypted_chunk:
                        break
                    
                    decrypted_chunk = decryptor.update(encrypted_chunk)
                    outf.write(decrypted_chunk)
                    remaining -= len(encrypted_chunk)
            
            # Read and verify the authentication tag
            tag = inf.read(16)
            decryptor.finalize_with_tag(tag)
        
        return {
            'decrypted_file': str(output_file),
            'size': output_file.stat().st_size
        }
    
    def automated_encrypt(self, data: bytes) -> Tuple[bytes, str]:
        """Automated mode: server handles encryption transparently."""
        key = self.generate_key()
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Generate secure key ID and store encrypted key in Redis
        key_id = secrets.token_hex(16)
        self._store_encrypted_key(key_id, key)
        
        # Combine IV + encrypted data + tag
        result = iv + encrypted_data + encryptor.tag
        
        return result, key_id
    
    def automated_decrypt(self, encrypted_data: bytes, key_id: str) -> bytes:
        """Automated mode: server handles decryption transparently."""
        # Extract components
        iv = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        
        # Retrieve key from secure Redis storage
        key = self._retrieve_encrypted_key(key_id)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _store_encrypted_key(self, key_id: str, key: bytes) -> None:
        """
        Store an encryption key securely in Redis using master key encryption.
        
        Args:
            key_id: Unique identifier for the key
            key: The raw key bytes to store
        """
        try:
            # Derive a unique encryption key for this storage operation using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=key_id.encode()[:16],  # Use key_id prefix as salt
                info=b"key-encryption",
            )
            storage_key = hkdf.derive(self.master_key)
            
            # Generate IV for this encryption operation
            iv = os.urandom(16)
            
            # Encrypt the key using AES-GCM
            cipher = Cipher(algorithms.AES(storage_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_key = encryptor.update(key) + encryptor.finalize()
            
            # Create storage metadata
            key_data = {
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "iv": base64.b64encode(iv).decode(),
                "tag": base64.b64encode(encryptor.tag).decode(),
                "created_at": int(time.time()),
                "key_length": len(key)
            }
            
            # Store in Redis with TTL
            redis_key = f"key:{key_id}"
            self.redis_client.setex(redis_key, self.key_ttl, json.dumps(key_data))
            
            logger.debug(f"Stored encrypted key {key_id} in Redis (TTL: {self.key_ttl}s)")
            
        except Exception as e:
            logger.error(f"Failed to store key {key_id}: {e}")
            raise ValueError(f"Failed to store encryption key: {e}")
    
    def _retrieve_encrypted_key(self, key_id: str) -> bytes:
        """
        Retrieve and decrypt an encryption key from Redis.
        
        Args:
            key_id: The unique identifier for the key
            
        Returns:
            The decrypted key bytes
            
        Raises:
            ValueError: If key is not found or cannot be decrypted
        """
        try:
            # Get key data from Redis
            redis_key = f"key:{key_id}"
            key_data_json = self.redis_client.get(redis_key)
            
            if not key_data_json:
                raise ValueError(f"Encryption key {key_id} not found or expired")
            
            key_data = json.loads(key_data_json)
            
            # Extract components
            encrypted_key = base64.b64decode(key_data["encrypted_key"])
            iv = base64.b64decode(key_data["iv"])
            tag = base64.b64decode(key_data["tag"])
            
            # Derive the same storage key used for encryption
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=key_id.encode()[:16],
                info=b"key-encryption",
            )
            storage_key = hkdf.derive(self.master_key)
            
            # Decrypt the key
            cipher = Cipher(algorithms.AES(storage_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            key = decryptor.update(encrypted_key) + decryptor.finalize()
            
            logger.debug(f"Retrieved encrypted key {key_id} from Redis")
            return key
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid key data format for {key_id}: {e}")
            raise ValueError(f"Invalid key data format: {e}")
        except Exception as e:
            logger.error(f"Failed to retrieve key {key_id}: {e}")
            raise ValueError(f"Failed to retrieve encryption key: {e}")
    
    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired keys from Redis (manual cleanup).
        
        Returns:
            Number of keys cleaned up
        """
        try:
            # Find all key entries
            pattern = "key:*"
            keys = self.redis_client.keys(pattern)
            
            cleaned = 0
            for key in keys:
                # Check if key still exists (TTL cleanup)
                if not self.redis_client.exists(key):
                    cleaned += 1
            
            logger.info(f"Manual key cleanup completed: {cleaned} expired keys found")
            return cleaned
            
        except Exception as e:
            logger.error(f"Key cleanup failed: {e}")
            return 0
    
    def decrypt_password_based_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Decrypt a password-based encrypted file (matching client-side encrypt_media.py format).
        
        File format: [32-byte salt][16-byte IV][encrypted data][16-byte tag]
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        with open(input_file, 'rb') as inf:
            # Read salt (first 32 bytes)
            salt = inf.read(32)
            if len(salt) != 32:
                raise ValueError("Invalid encrypted file format: missing salt")
            
            # Read IV (next 16 bytes)
            iv = inf.read(16)
            if len(iv) != 16:
                raise ValueError("Invalid encrypted file format: missing IV")
            
            # Read the encrypted data and tag
            file_size = input_file.stat().st_size
            encrypted_size = file_size - 32 - 16 - 16  # minus salt, IV, and tag
            
            if encrypted_size < 0:
                raise ValueError("Invalid encrypted file format: file too small")
            
            # Derive key from password using same method as client
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                iterations=100000  # Must match client iterations
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Read encrypted data
            encrypted_data = inf.read(encrypted_size)
            if len(encrypted_data) != encrypted_size:
                raise ValueError("Invalid encrypted file format: incomplete encrypted data")
            
            # Read authentication tag (last 16 bytes)
            tag = inf.read(16)
            if len(tag) != 16:
                raise ValueError("Invalid encrypted file format: missing authentication tag")
        
        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Write decrypted data to output file
        with open(output_file, 'wb') as outf:
            outf.write(decrypted_data)
        
        return {
            'decrypted_file': str(output_file),
            'size': len(decrypted_data),
            'original_encrypted_size': file_size
        }
    
    def encrypt_password_based_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Encrypt a file using password-based encryption (matching client-side encrypt_media.py format).
        
        File format: [32-byte salt][16-byte IV][encrypted data][16-byte tag]
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Generate random salt and IV (matching client format)
        salt = os.urandom(32)  # 256-bit salt
        iv = os.urandom(16)    # 128-bit IV for GCM
        
        # Derive key from password using same method as client
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000  # Must match client iterations
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Initialize cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt file with exact client format
        with open(output_file, 'wb') as outf:
            # Write metadata header (matching client format)
            outf.write(salt)  # 32 bytes
            outf.write(iv)    # 16 bytes
            
            # Encrypt file content in chunks
            with open(input_file, 'rb') as inf:
                while chunk := inf.read(self.chunk_size):
                    encrypted_chunk = encryptor.update(chunk)
                    outf.write(encrypted_chunk)
            
            # Finalize and write authentication tag
            encryptor.finalize()
            outf.write(encryptor.tag)  # 16 bytes
        
        return {
            'encrypted_file': str(output_file),
            'original_size': input_file.stat().st_size,
            'encrypted_size': output_file.stat().st_size,
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256',
            'iterations': 100000
        }