#!/usr/bin/env python3
"""
Client-side media encryption utility for manual encryption mode.

This tool encrypts media files before sending them to the encoding server
for scenarios where the operator should not have access to plaintext content.

Author: Lorenzo Albanese (alblor)
"""

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class MediaEncryptor:
    """Secure media file encryption for untrusted operator scenarios."""
    
    def __init__(self, chunk_size: int = 64 * 1024):
        self.chunk_size = chunk_size
    
    def generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000  # Strong iteration count
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Encrypt a media file using AES-256-GCM with password-derived key.
        
        Returns metadata needed for decryption.
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Generate random salt and IV
        salt = os.urandom(32)  # 256-bit salt
        iv = os.urandom(16)    # 128-bit IV for GCM
        
        # Derive key from password
        key = self.generate_key_from_password(password, salt)
        
        # Initialize cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # Create output directory if it doesn't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Encrypt file
        with open(output_file, 'wb') as outf:
            # Write metadata header
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
        
        # Return encryption metadata
        return {
            'encrypted_file': str(output_file),
            'original_size': input_file.stat().st_size,
            'encrypted_size': output_file.stat().st_size,
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256',
            'iterations': 100000
        }
    
    def get_file_info(self, encrypted_path: str) -> dict:
        """Get information about an encrypted file."""
        encrypted_file = Path(encrypted_path)
        
        if not encrypted_file.exists():
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
        
        file_size = encrypted_file.stat().st_size
        
        # Check minimum file size (salt + iv + tag = 64 bytes)
        if file_size < 64:
            raise ValueError("File too small to be a valid encrypted media file")
        
        # Calculate content size (total - salt - iv - tag)
        content_size = file_size - 32 - 16 - 16
        
        return {
            'file_path': str(encrypted_file),
            'total_size': file_size,
            'content_size': content_size,
            'metadata_size': 64,
            'algorithm': 'AES-256-GCM (assumed)',
            'status': 'encrypted'
        }


def main():
    """Command-line interface for media encryption."""
    parser = argparse.ArgumentParser(
        description="Encrypt media files for secure processing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a video file
  python encrypt_media.py movie.mp4 --output movie.enc
  
  # Encrypt with custom output location
  python encrypt_media.py /path/to/video.mp4 --output /secure/encrypted.enc
  
  # Get info about encrypted file
  python encrypt_media.py --info encrypted_file.enc
        """
    )
    
    parser.add_argument('input_file', help='Input media file to encrypt')
    parser.add_argument('--output', '-o', help='Output encrypted file path')
    # Password argument removed for security - use secure input methods only
    parser.add_argument('--info', action='store_true', help='Show information about encrypted file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    encryptor = MediaEncryptor()
    
    try:
        if args.info:
            # Show file information
            info = encryptor.get_file_info(args.input_file)
            print(f"Encrypted File Information:")
            print(f"  File: {info['file_path']}")
            print(f"  Total Size: {info['total_size']:,} bytes")
            print(f"  Content Size: {info['content_size']:,} bytes")
            print(f"  Metadata Size: {info['metadata_size']} bytes")
            print(f"  Algorithm: {info['algorithm']}")
            print(f"  Status: {info['status']}")
            return
        
        # Encrypt file
        input_path = args.input_file
        
        # Generate output path if not provided
        if not args.output:
            input_file = Path(input_path)
            output_path = str(input_file.with_suffix(input_file.suffix + '.enc'))
        else:
            output_path = args.output
        
        # Get password using secure methods only
        import getpass
        
        # Method 1: Environment variable (for automation)
        password = os.environ.get('MEDIA_ENCRYPTION_PASSWORD')
        if password:
            if args.verbose:
                print("🔐 Using password from environment variable (MEDIA_ENCRYPTION_PASSWORD)")
        else:
            # Method 2: Interactive secure prompt (default)
            password = getpass.getpass("🔐 Enter encryption password: ")
            confirm_password = getpass.getpass("🔐 Confirm password: ")
            
            if password != confirm_password:
                print("❌ Error: Passwords do not match", file=sys.stderr)
                sys.exit(1)
        
        if not password:
            print("Error: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        if args.verbose:
            print(f"Encrypting: {input_path}")
            print(f"Output: {output_path}")
        
        # Perform encryption
        result = encryptor.encrypt_file(input_path, output_path, password)
        
        print(f"✓ Encryption completed successfully")
        print(f"  Input: {input_path} ({result['original_size']:,} bytes)")
        print(f"  Output: {result['encrypted_file']} ({result['encrypted_size']:,} bytes)")
        print(f"  Algorithm: {result['algorithm']}")
        print(f"  Key Derivation: {result['kdf']} ({result['iterations']:,} iterations)")
        
        if args.verbose:
            overhead = result['encrypted_size'] - result['original_size']
            print(f"  Encryption Overhead: {overhead} bytes")
        
        print(f"\n⚠️  IMPORTANT: Store your password securely!")
        print(f"   The encrypted file cannot be recovered without the password.")
        
        # Security: Clear password from memory
        if 'confirm_password' in locals():
            confirm_password = None  # Clear confirmation password
        password = None  # Clear main password
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()