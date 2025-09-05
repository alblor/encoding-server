#!/usr/bin/env python3
"""
Comprehensive test suite for batch encryption/decryption functionality.

This test suite validates the batch processing capabilities of the media encryption
system including recursive processing, file filtering, security preservation,
and error handling scenarios.

Author: Lorenzo Albanese (alblor)
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Add the client-tools directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'client-tools'))

from batch_encrypt import BatchEncryptor
from batch_decrypt import BatchDecryptor
from encrypt_media import MediaEncryptor
from decrypt_media import MediaDecryptor


class TestBatchEncryptionBase(unittest.TestCase):
    """Base class for batch encryption tests with common setup."""
    
    def setUp(self):
        """Set up test environment with temporary directories and test files."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp(prefix="batch_test_")
        self.input_dir = Path(self.temp_dir) / "input"
        self.output_dir = Path(self.temp_dir) / "output"
        self.restored_dir = Path(self.temp_dir) / "restored"
        
        # Create directory structure
        self.input_dir.mkdir(parents=True)
        self.output_dir.mkdir(parents=True)
        self.restored_dir.mkdir(parents=True)
        
        # Test password
        self.test_password = "test_batch_password_123"
        
        # Create test file structure
        self.create_test_files()
    
    def tearDown(self):
        """Clean up temporary directories."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def create_test_files(self):
        """Create a comprehensive test file structure."""
        # Create subdirectories
        subdir1 = self.input_dir / "subdir1"
        subdir2 = self.input_dir / "subdir2"
        subdir1.mkdir()
        subdir2.mkdir()
        
        # Create test files with various extensions and sizes
        test_files = {
            "video1.mp4": b"MP4 video content " * 100,  # ~1.8KB
            "video2.mkv": b"MKV video content " * 500,  # ~9KB
            "audio.aac": b"AAC audio content " * 50,    # ~850B
            "document.txt": b"Text document content",    # Small file
            "large_video.avi": b"Large AVI content " * 10000,  # ~170KB
            "subdir1/nested_video.mp4": b"Nested MP4 content " * 200,  # ~3.6KB
            "subdir1/nested_audio.flac": b"FLAC audio content " * 300,  # ~5.4KB
            "subdir2/another_video.webm": b"WebM content " * 150,  # ~2.7KB
            "subdir2/temp_file.tmp": b"Temporary file content",  # Should be excluded in some tests
            ".hidden_file.mp4": b"Hidden file content " * 100,  # Hidden file
        }
        
        # Write test files
        for relative_path, content in test_files.items():
            file_path = self.input_dir / relative_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)
    
    def get_file_list(self, directory: Path, extension: str = None) -> list:
        """Get list of files in directory, optionally filtered by extension."""
        files = []
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                if extension is None or file_path.suffix.lower() == extension.lower():
                    files.append(file_path)
        return sorted(files)
    
    def verify_file_content(self, original_file: Path, decrypted_file: Path):
        """Verify that decrypted file matches original content."""
        original_content = original_file.read_bytes()
        decrypted_content = decrypted_file.read_bytes()
        self.assertEqual(original_content, decrypted_content, 
                        f"Content mismatch: {original_file} vs {decrypted_file}")


class TestBatchEncryption(TestBatchEncryptionBase):
    """Test batch encryption functionality."""
    
    def test_basic_batch_encryption(self):
        """Test basic batch encryption without filters."""
        encryptor = BatchEncryptor()
        
        # Scan all files
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        # Should find all files except hidden ones by default
        self.assertGreaterEqual(len(files_to_process), 8)  # At least 8 non-hidden files
        
        # Perform batch encryption
        result = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        # Verify results
        self.assertEqual(result['successful'], len(files_to_process))
        self.assertEqual(result['failed'], 0)
        
        # Check that encrypted files were created
        encrypted_files = self.get_file_list(self.output_dir, ".enc")
        self.assertEqual(len(encrypted_files), len(files_to_process))
    
    def test_extension_filtering(self):
        """Test batch encryption with extension filtering."""
        encryptor = BatchEncryptor()
        
        # Filter only video files
        extensions = {'mp4', 'mkv', 'avi', 'webm'}
        files_to_process = encryptor.scan_directory(
            self.input_dir, 
            recursive=True,
            extensions=extensions
        )
        
        # Should find 5 video files (excluding hidden)
        self.assertEqual(len(files_to_process), 5)
        
        # Verify all files have correct extensions
        for file_path in files_to_process:
            self.assertIn(file_path.suffix.lower().lstrip('.'), extensions)
    
    def test_size_filtering(self):
        """Test batch encryption with size filtering."""
        encryptor = BatchEncryptor()
        
        # Filter files larger than 2KB
        min_size = 2048  # 2KB
        files_to_process = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            min_size=min_size
        )
        
        # Verify all files are larger than min_size
        for file_path in files_to_process:
            self.assertGreaterEqual(file_path.stat().st_size, min_size)
    
    def test_exclude_patterns(self):
        """Test batch encryption with exclude patterns."""
        encryptor = BatchEncryptor()
        
        # Exclude .tmp files and subdir2
        exclude_patterns = ['*.tmp', 'subdir2/*']
        files_to_process = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            exclude_patterns=exclude_patterns
        )
        
        # Verify excluded files are not included
        for file_path in files_to_process:
            self.assertFalse(file_path.name.endswith('.tmp'))
            self.assertNotIn('subdir2', file_path.parts)
    
    def test_include_hidden_files(self):
        """Test including hidden files in batch encryption."""
        encryptor = BatchEncryptor()
        
        # Scan with hidden files included
        files_with_hidden = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            include_hidden=True
        )
        
        # Scan without hidden files
        files_without_hidden = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            include_hidden=False
        )
        
        # Should find more files when including hidden
        self.assertGreater(len(files_with_hidden), len(files_without_hidden))
        
        # Verify hidden file is included only when specified
        hidden_files = [f for f in files_with_hidden if f.name.startswith('.')]
        self.assertEqual(len(hidden_files), 1)
    
    def test_max_depth_limit(self):
        """Test directory recursion depth limiting."""
        encryptor = BatchEncryptor()
        
        # Create deeper directory structure
        deep_dir = self.input_dir / "level1" / "level2" / "level3"
        deep_dir.mkdir(parents=True)
        deep_file = deep_dir / "deep_file.mp4"
        deep_file.write_bytes(b"Deep file content")
        
        # Scan with depth limit of 1 (only direct subdirectories)
        files_depth_1 = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            max_depth=1
        )
        
        # Scan with no depth limit
        files_unlimited = encryptor.scan_directory(
            self.input_dir,
            recursive=True,
            max_depth=-1
        )
        
        # Should find fewer files with depth limit
        self.assertLess(len(files_depth_1), len(files_unlimited))
        
        # Deep file should not be in depth-limited results
        deep_file_found = any('level3' in str(f) for f in files_depth_1)
        self.assertFalse(deep_file_found)
    
    def test_resume_functionality(self):
        """Test resuming interrupted batch encryption."""
        encryptor = BatchEncryptor()
        
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        # First batch - encrypt some files
        first_batch = files_to_process[:3]
        result1 = encryptor.encrypt_batch(
            first_batch,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        self.assertEqual(result1['successful'], 3)
        
        # Second batch - encrypt all files with resume enabled
        result2 = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            resume=True,
            verbose=False,
            progress=False
        )
        
        # Should skip already encrypted files
        self.assertGreater(result2['skipped'], 0)
        total_processed = result2['successful'] - result2['skipped']
        self.assertEqual(total_processed, len(files_to_process) - 3)


class TestBatchDecryption(TestBatchEncryptionBase):
    """Test batch decryption functionality."""
    
    def setUp(self):
        """Set up test environment and encrypt some files for decryption tests."""
        super().setUp()
        
        # First encrypt some files
        encryptor = BatchEncryptor()
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        self.encryption_result = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
    
    def test_basic_batch_decryption(self):
        """Test basic batch decryption."""
        decryptor = BatchDecryptor()
        
        # Scan for encrypted files
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        
        # Should find all encrypted files
        self.assertEqual(len(encrypted_files), self.encryption_result['successful'])
        
        # Perform batch decryption
        result = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        # Verify results
        self.assertEqual(result['successful'], len(encrypted_files))
        self.assertEqual(result['failed'], 0)
        
        # Verify file contents match originals
        self.verify_decrypted_content()
    
    def verify_decrypted_content(self):
        """Verify that all decrypted files match their original content."""
        for original_file in self.input_dir.rglob("*"):
            if original_file.is_file() and not original_file.name.startswith('.'):
                # Find corresponding decrypted file
                relative_path = original_file.relative_to(self.input_dir)
                decrypted_file = self.restored_dir / relative_path
                
                if decrypted_file.exists():
                    self.verify_file_content(original_file, decrypted_file)
    
    def test_decryption_with_wrong_password(self):
        """Test batch decryption with incorrect password."""
        decryptor = BatchDecryptor()
        
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        wrong_password = "wrong_password"
        
        # Attempt decryption with wrong password
        result = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            wrong_password,
            verbose=False,
            progress=False
        )
        
        # All decryptions should fail
        self.assertEqual(result['successful'], 0)
        self.assertEqual(result['failed'], len(encrypted_files))
    
    def test_decryption_resume_functionality(self):
        """Test resuming interrupted batch decryption."""
        decryptor = BatchDecryptor()
        
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        
        # First batch - decrypt some files
        first_batch = encrypted_files[:2]
        result1 = decryptor.decrypt_batch(
            first_batch,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        self.assertEqual(result1['successful'], 2)
        
        # Second batch - decrypt all files with resume
        result2 = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            resume=True,
            verbose=False,
            progress=False
        )
        
        # Should skip already decrypted files
        self.assertGreater(result2['skipped'], 0)
    
    def test_integrity_verification(self):
        """Test integrity verification during batch decryption."""
        decryptor = BatchDecryptor()
        
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        
        # Decrypt with integrity verification
        result = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            verify_integrity=True,
            verbose=False,
            progress=False
        )
        
        # Should have integrity verification flag
        self.assertTrue(result.get('integrity_verified', False))
        
        # All files should decrypt successfully
        self.assertEqual(result['successful'], len(encrypted_files))


class TestManifestGeneration(TestBatchEncryptionBase):
    """Test manifest generation and validation."""
    
    def test_encryption_manifest_generation(self):
        """Test generation of encryption manifest."""
        encryptor = BatchEncryptor()
        
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        # Encrypt files
        result = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        # Generate manifest
        manifest_path = encryptor.generate_manifest(result, self.output_dir)
        
        # Verify manifest file exists and has correct structure
        self.assertTrue(manifest_path.exists())
        
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        # Verify manifest structure
        self.assertIn('batch_info', manifest)
        self.assertIn('successful_files', manifest)
        self.assertEqual(len(manifest['successful_files']), result['successful'])
        
        # Verify batch info
        batch_info = manifest['batch_info']
        self.assertEqual(batch_info['algorithm'], 'AES-256-GCM')
        self.assertEqual(batch_info['total_files'], result['total_files'])
    
    def test_decryption_manifest_validation(self):
        """Test validation against encryption manifest during decryption."""
        # First encrypt with manifest
        encryptor = BatchEncryptor()
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        encrypt_result = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        encrypt_manifest_path = encryptor.generate_manifest(encrypt_result, self.output_dir)
        
        # Then decrypt with validation
        decryptor = BatchDecryptor()
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        
        decrypt_result = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        # Validate against encryption manifest
        validation_results = decryptor.validate_against_manifest(
            decrypt_result,
            encrypt_manifest_path
        )
        
        # Verify validation results
        self.assertTrue(validation_results['validation_performed'])
        self.assertEqual(validation_results['manifest_files'], validation_results['decrypted_files'])
        self.assertEqual(len(validation_results['missing_files']), 0)


class TestErrorHandling(TestBatchEncryptionBase):
    """Test error handling and edge cases."""
    
    def test_empty_directory(self):
        """Test batch encryption on empty directory."""
        empty_dir = Path(self.temp_dir) / "empty"
        empty_dir.mkdir()
        
        encryptor = BatchEncryptor()
        files_to_process = encryptor.scan_directory(empty_dir, recursive=True)
        
        self.assertEqual(len(files_to_process), 0)
    
    def test_nonexistent_directory(self):
        """Test handling of nonexistent directories."""
        nonexistent = Path(self.temp_dir) / "nonexistent"
        
        encryptor = BatchEncryptor()
        
        # Should handle gracefully and return empty list
        files_to_process = encryptor.scan_directory(nonexistent, recursive=True)
        self.assertEqual(len(files_to_process), 0)
    
    def test_file_permission_errors(self):
        """Test handling of files with permission errors."""
        encryptor = BatchEncryptor()
        
        # Create a file and remove read permissions
        protected_file = self.input_dir / "protected.mp4"
        protected_file.write_bytes(b"Protected content")
        
        # Make file unreadable (only on Unix-like systems)
        if hasattr(os, 'chmod'):
            protected_file.chmod(0o000)
            
            try:
                files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
                
                # File should be in skipped list
                skipped_files = [f[0] for f in encryptor.skipped_files]
                self.assertIn(protected_file, skipped_files)
                
            finally:
                # Restore permissions for cleanup
                protected_file.chmod(0o644)
    
    def test_corrupted_encrypted_file_handling(self):
        """Test handling of corrupted encrypted files during decryption."""
        # First encrypt a file
        encryptor = BatchEncryptor()
        test_file = self.input_dir / "test.mp4"
        encrypted_file = self.output_dir / "test.mp4.enc"
        
        result = encryptor.encrypt_file(str(test_file), str(encrypted_file), self.test_password)
        self.assertTrue(encrypted_file.exists())
        
        # Corrupt the encrypted file
        with open(encrypted_file, 'r+b') as f:
            f.seek(50)  # Corrupt some bytes in the middle
            f.write(b'CORRUPTED')
        
        # Try to decrypt
        decryptor = BatchDecryptor()
        decrypt_result = decryptor.decrypt_single_file(
            encrypted_file,
            self.restored_dir / "test.mp4",
            self.test_password,
            verbose=False
        )
        
        # Should fail gracefully
        self.assertFalse(decrypt_result['success'])
        self.assertIsNotNone(decrypt_result['error'])


class TestParallelProcessing(TestBatchEncryptionBase):
    """Test parallel processing functionality."""
    
    def test_parallel_encryption(self):
        """Test parallel processing during batch encryption."""
        encryptor = BatchEncryptor(max_workers=2)
        
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        # Encrypt with parallel processing
        result = encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            parallel=True,
            verbose=False,
            progress=False
        )
        
        # Should still work correctly
        self.assertEqual(result['successful'], len(files_to_process))
        self.assertEqual(result['failed'], 0)
    
    def test_parallel_decryption(self):
        """Test parallel processing during batch decryption."""
        # First encrypt files
        encryptor = BatchEncryptor()
        files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
        
        encryptor.encrypt_batch(
            files_to_process,
            self.input_dir,
            self.output_dir,
            self.test_password,
            verbose=False,
            progress=False
        )
        
        # Then decrypt with parallel processing
        decryptor = BatchDecryptor(max_workers=2)
        encrypted_files = decryptor.scan_directory(self.output_dir, recursive=True)
        
        result = decryptor.decrypt_batch(
            encrypted_files,
            self.output_dir,
            self.restored_dir,
            self.test_password,
            parallel=True,
            verbose=False,
            progress=False
        )
        
        # Should work correctly
        self.assertEqual(result['successful'], len(encrypted_files))
        self.assertEqual(result['failed'], 0)


class TestSecurityPreservation(TestBatchEncryptionBase):
    """Test that security features are preserved in batch operations."""
    
    def test_password_security(self):
        """Test that password security is maintained."""
        encryptor = BatchEncryptor()
        
        # Mock password input to avoid interactive prompt
        with patch('getpass.getpass', return_value=self.test_password):
            # Test that password is not stored in arguments or easily accessible
            files_to_process = encryptor.scan_directory(self.input_dir, recursive=True)
            
            result = encryptor.encrypt_batch(
                files_to_process,
                self.input_dir,
                self.output_dir,
                self.test_password,
                verbose=False,
                progress=False
            )
            
            # Should not find password in string representation
            encryptor_str = str(encryptor)
            self.assertNotIn(self.test_password, encryptor_str)
    
    def test_encryption_algorithm_consistency(self):
        """Test that batch encryption uses the same algorithms as single-file encryption."""
        # Single file encryption
        single_encryptor = MediaEncryptor()
        test_file = self.input_dir / "test.mp4"
        single_encrypted = self.output_dir / "single_test.mp4.enc"
        
        single_result = single_encryptor.encrypt_file(
            str(test_file), str(single_encrypted), self.test_password
        )
        
        # Batch file encryption
        batch_encryptor = BatchEncryptor()
        batch_encrypted = self.output_dir / "batch_test.mp4.enc"
        
        batch_result = batch_encryptor.encrypt_single_file(
            test_file, batch_encrypted, self.test_password, verbose=False
        )
        
        # Should use same algorithm
        self.assertEqual(single_result['algorithm'], batch_result['algorithm'])
        self.assertEqual(single_result['kdf'], batch_result['kdf'])
        self.assertEqual(single_result['iterations'], batch_result['iterations'])
    
    def test_decryption_verification_consistency(self):
        """Test that batch decryption maintains same verification as single-file."""
        # Encrypt a file with batch encryption
        encryptor = BatchEncryptor()
        test_file = self.input_dir / "test.mp4"
        encrypted_file = self.output_dir / "test.mp4.enc"
        
        encryptor.encrypt_single_file(test_file, encrypted_file, self.test_password)
        
        # Decrypt with single-file decryptor
        single_decryptor = MediaDecryptor()
        single_decrypted = self.restored_dir / "single_test.mp4"
        
        single_result = single_decryptor.decrypt_file(
            str(encrypted_file), str(single_decrypted), self.test_password
        )
        
        # Decrypt with batch decryptor
        batch_decryptor = BatchDecryptor()
        batch_decrypted = self.restored_dir / "batch_test.mp4"
        
        batch_result = batch_decryptor.decrypt_single_file(
            encrypted_file, batch_decrypted, self.test_password
        )
        
        # Should use same verification
        self.assertEqual(single_result['algorithm'], batch_result['algorithm'])
        self.assertEqual(single_result['verification'], batch_result['verification'])
        
        # Content should be identical
        self.verify_file_content(single_decrypted, batch_decrypted)


def run_batch_tests():
    """Run all batch encryption tests."""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestBatchEncryption,
        TestBatchDecryption,
        TestManifestGeneration,
        TestErrorHandling,
        TestParallelProcessing,
        TestSecurityPreservation
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"BATCH ENCRYPTION TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError: ')[-1].split('\n')[0]}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('\n')[-2]}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_batch_tests()
    sys.exit(0 if success else 1)