#!/usr/bin/env python3
"""
Client-side media decryption utility for manual encryption mode.

This tool decrypts media files received from the encoding server
for scenarios using manual encryption mode.

Author: Lorenzo Albanese (alblor)
"""

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class MediaDecryptor:
    """Secure media file decryption for manual encryption mode."""
    
    def __init__(self, chunk_size: int = 64 * 1024):
        self.chunk_size = chunk_size
    
    def generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive decryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000  # Must match encryption iterations
        )
        return kdf.derive(password.encode('utf-8'))
    
    def decrypt_file(self, input_path: str, output_path: str, password: str) -> dict:
        """
        Decrypt a media file encrypted with AES-256-GCM.
        
        Returns metadata about the decryption process.
        """
        input_file = Path(input_path)
        output_file = Path(output_path)
        
        if not input_file.exists():
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")
        
        file_size = input_file.stat().st_size
        
        # Check minimum file size (salt + iv + tag = 64 bytes)
        if file_size < 64:
            raise ValueError("File too small to be a valid encrypted media file")
        
        # Create output directory if it doesn't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(input_file, 'rb') as inf:
                # Read metadata from header
                salt = inf.read(32)  # 256-bit salt
                iv = inf.read(16)    # 128-bit IV
                
                if len(salt) != 32 or len(iv) != 16:
                    raise ValueError("Invalid file format: corrupted header")
                
                # Derive key from password
                key = self.generate_key_from_password(password, salt)
                
                # Calculate content size (total - salt - iv - tag)
                content_size = file_size - 32 - 16 - 16
                
                # Read encrypted content (everything except the tag)
                encrypted_content = inf.read(content_size)
                
                # Read authentication tag
                tag = inf.read(16)
                
                if len(tag) != 16:
                    raise ValueError("Invalid file format: missing or corrupted authentication tag")
                
                # Initialize cipher for decryption
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()
                
                # Decrypt content in chunks
                with open(output_file, 'wb') as outf:
                    remaining = len(encrypted_content)
                    offset = 0
                    
                    while remaining > 0:
                        chunk_size = min(self.chunk_size, remaining)
                        encrypted_chunk = encrypted_content[offset:offset + chunk_size]
                        
                        if not encrypted_chunk:
                            break
                        
                        decrypted_chunk = decryptor.update(encrypted_chunk)
                        outf.write(decrypted_chunk)
                        
                        offset += chunk_size
                        remaining -= chunk_size
                
                # Finalize decryption (this verifies the authentication tag)
                decryptor.finalize()
        
        except InvalidTag:
            # Clean up partial output file
            if output_file.exists():
                output_file.unlink()
            raise ValueError("Decryption failed: Invalid password or corrupted file")
        
        # Return decryption metadata
        return {
            'decrypted_file': str(output_file),
            'original_size': file_size,
            'decrypted_size': output_file.stat().st_size,
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256',
            'verification': 'passed'
        }
    
    def verify_encrypted_file(self, encrypted_path: str) -> dict:
        """Verify the structure of an encrypted file without decrypting."""
        encrypted_file = Path(encrypted_path)
        
        if not encrypted_file.exists():
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
        
        file_size = encrypted_file.stat().st_size
        
        # Check minimum file size
        if file_size < 64:
            return {
                'valid': False,
                'reason': 'File too small to be valid encrypted media'
            }
        
        try:
            with open(encrypted_file, 'rb') as f:
                # Check header structure
                salt = f.read(32)
                iv = f.read(16)
                
                if len(salt) != 32 or len(iv) != 16:
                    return {
                        'valid': False,
                        'reason': 'Invalid header format'
                    }
                
                # Skip to the end to check for authentication tag
                f.seek(-16, 2)  # Seek to 16 bytes from end
                tag = f.read(16)
                
                if len(tag) != 16:
                    return {
                        'valid': False,
                        'reason': 'Missing or invalid authentication tag'
                    }
        
        except Exception as e:
            return {
                'valid': False,
                'reason': f'File read error: {str(e)}'
            }
        
        content_size = file_size - 64  # Total minus metadata
        
        return {
            'valid': True,
            'file_size': file_size,
            'content_size': content_size,
            'metadata_size': 64,
            'format': 'AES-256-GCM encrypted media'
        }


def main():
    """Command-line interface for media decryption."""
    parser = argparse.ArgumentParser(
        description="Decrypt media files from secure processing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt a file
  python decrypt_media.py encrypted.enc --output video.mp4
  
  # Decrypt with custom output location
  python decrypt_media.py /secure/encrypted.enc --output /output/video.mp4
  
  # Verify encrypted file structure
  python decrypt_media.py --verify encrypted_file.enc
        """
    )
    
    parser.add_argument('input_file', help='Encrypted media file to decrypt')
    parser.add_argument('--output', '-o', help='Output decrypted file path')
    # Password argument removed for security - use secure input methods only
    parser.add_argument('--verify', action='store_true', help='Verify encrypted file structure only')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    decryptor = MediaDecryptor()
    
    try:
        if args.verify:
            # Verify file structure
            result = decryptor.verify_encrypted_file(args.input_file)
            
            print(f"Encrypted File Verification:")
            print(f"  File: {args.input_file}")
            
            if result['valid']:
                print(f"  ✓ Valid encrypted media file")
                print(f"  Format: {result['format']}")
                print(f"  Total Size: {result['file_size']:,} bytes")
                print(f"  Content Size: {result['content_size']:,} bytes")
                print(f"  Metadata Size: {result['metadata_size']} bytes")
            else:
                print(f"  ✗ Invalid encrypted file")
                print(f"  Reason: {result['reason']}")
                sys.exit(1)
            
            return
        
        # Decrypt file
        input_path = args.input_file
        
        # Generate output path if not provided
        if not args.output:
            input_file = Path(input_path)
            # Remove .enc extension if present
            if input_file.suffix == '.enc':
                output_path = str(input_file.with_suffix(''))
            else:
                output_path = str(input_file.with_suffix('.decrypted' + input_file.suffix))
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
            password = getpass.getpass("🔐 Enter decryption password: ")
        
        if not password:
            print("Error: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        if args.verbose:
            print(f"Decrypting: {input_path}")
            print(f"Output: {output_path}")
        
        # Perform decryption
        result = decryptor.decrypt_file(input_path, output_path, password)
        
        print(f"✓ Decryption completed successfully")
        print(f"  Input: {input_path} ({result['original_size']:,} bytes)")
        print(f"  Output: {result['decrypted_file']} ({result['decrypted_size']:,} bytes)")
        print(f"  Algorithm: {result['algorithm']}")
        print(f"  Authentication: {result['verification']}")
        
        if args.verbose:
            overhead = result['original_size'] - result['decrypted_size']
            print(f"  Removed Overhead: {overhead} bytes")
        
        # Security: Clear password from memory
        password = None
        
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