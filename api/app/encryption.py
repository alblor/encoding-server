"""Dual-mode encryption system for media files."""

import os
import secrets
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class EncryptionManager:
    """Handles both automated and manual encryption modes."""
    
    def __init__(self):
        self.chunk_size = 64 * 1024  # 64KB chunks for streaming
    
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
        
        # Store key securely (in production, use proper key management)
        key_id = secrets.token_hex(16)
        
        # Combine IV + encrypted data + tag
        result = iv + encrypted_data + encryptor.tag
        
        return result, key_id
    
    def automated_decrypt(self, encrypted_data: bytes, key_id: str) -> bytes:
        """Automated mode: server handles decryption transparently."""
        # Extract components
        iv = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        
        # In production, retrieve key from secure storage using key_id
        # For now, we'll need to store keys temporarily
        key = self._get_key_for_id(key_id)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _get_key_for_id(self, key_id: str) -> bytes:
        """Retrieve encryption key for given ID (implement secure storage)."""
        # This is a placeholder - implement proper key management
        # In production, use Redis, HashiCorp Vault, or similar
        return b"temporary_key_for_development_only"