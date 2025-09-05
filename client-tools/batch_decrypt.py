#!/usr/bin/env python3
"""
Batch media decryption utility for folder-level decryption operations.

This tool decrypts entire folders of encrypted media files recursively while 
preserving directory structure and maintaining all security features of the 
single-file decryption tool.

Author: Lorenzo Albanese (alblor)
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
import concurrent.futures
from datetime import datetime
import fnmatch

# Import from the existing single-file decryptor
from decrypt_media import MediaDecryptor


class BatchDecryptor(MediaDecryptor):
    """Batch media file decryption with directory recursion and verification."""
    
    def __init__(self, chunk_size: int = 64 * 1024, max_workers: int = 1):
        super().__init__(chunk_size)
        self.max_workers = max_workers
        self.processed_files = 0
        self.failed_files = []
        self.skipped_files = []
        self.start_time = None
        
    def get_file_size(self, file_path: Path) -> int:
        """Get file size in bytes."""
        try:
            return file_path.stat().st_size
        except (OSError, IOError):
            return 0
    
    def format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                if unit == 'B':
                    return f"{size_bytes} {unit}"
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def parse_size(self, size_str: str) -> int:
        """Parse human readable size to bytes."""
        if not size_str:
            return 0
        
        size_str = size_str.upper().strip()
        multipliers = {
            'B': 1, 'BYTES': 1,
            'K': 1024, 'KB': 1024, 'KIB': 1024,
            'M': 1024**2, 'MB': 1024**2, 'MIB': 1024**2,
            'G': 1024**3, 'GB': 1024**3, 'GIB': 1024**3,
            'T': 1024**4, 'TB': 1024**4, 'TIB': 1024**4
        }
        
        # Extract number and unit
        import re
        match = re.match(r'^(\d+(?:\.\d+)?)\s*([A-Z]*)$', size_str)
        if not match:
            raise ValueError(f"Invalid size format: {size_str}")
        
        number, unit = match.groups()
        number = float(number)
        unit = unit or 'B'
        
        if unit not in multipliers:
            raise ValueError(f"Unknown size unit: {unit}")
        
        return int(number * multipliers[unit])
    
    def is_encrypted_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        Check if a file is a valid encrypted media file.
        
        Returns:
            Tuple of (is_encrypted: bool, reason: str)
        """
        # Quick check - must have .enc extension
        if not file_path.name.lower().endswith('.enc'):
            return False, "not an .enc file"
        
        # Check file exists and is readable
        if not file_path.is_file():
            return False, "not a regular file"
        
        if not os.access(file_path, os.R_OK):
            return False, "not readable"
        
        # Use the parent class method to verify structure
        try:
            verification = self.verify_encrypted_file(str(file_path))
            if verification['valid']:
                return True, "valid encrypted media file"
            else:
                return False, f"invalid format: {verification['reason']}"
        except Exception as e:
            return False, f"verification error: {e}"
    
    def should_process_file(self, file_path: Path, min_size: int = 0, max_size: int = 0,
                          exclude_patterns: List[str] = None, include_hidden: bool = False) -> Tuple[bool, str]:
        """
        Check if an encrypted file should be processed based on filters.
        
        Returns:
            Tuple of (should_process: bool, reason: str)
        """
        # First check if it's an encrypted file
        is_enc, reason = self.is_encrypted_file(file_path)
        if not is_enc:
            return False, reason
        
        # Check hidden files
        if not include_hidden and file_path.name.startswith('.'):
            return False, "hidden file (use --include-hidden to process)"
        
        # Check file size
        try:
            file_size = file_path.stat().st_size
        except (OSError, IOError) as e:
            return False, f"cannot get file size: {e}"
        
        if min_size > 0 and file_size < min_size:
            return False, f"file too small ({self.format_size(file_size)} < {self.format_size(min_size)})"
        
        if max_size > 0 and file_size > max_size:
            return False, f"file too large ({self.format_size(file_size)} > {self.format_size(max_size)})"
        
        # Check exclude patterns
        if exclude_patterns:
            relative_path = str(file_path)
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                    return False, f"matches exclude pattern: {pattern}"
        
        return True, "passes all filters"
    
    def scan_directory(self, input_dir: Path, recursive: bool = True,
                      min_size: int = 0, max_size: int = 0,
                      exclude_patterns: List[str] = None,
                      include_hidden: bool = False, max_depth: int = -1) -> List[Path]:
        """
        Scan directory for encrypted files to decrypt.
        
        Args:
            input_dir: Input directory path
            recursive: Scan subdirectories
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes (0 = no limit)
            exclude_patterns: List of glob patterns to exclude
            include_hidden: Include hidden files
            max_depth: Maximum recursion depth (-1 = unlimited)
            
        Returns:
            List of encrypted file paths to process
        """
        files_to_process = []
        
        def scan_recursive(current_dir: Path, current_depth: int = 0):
            if max_depth >= 0 and current_depth > max_depth:
                return
            
            try:
                entries = list(current_dir.iterdir())
            except (PermissionError, OSError) as e:
                print(f"⚠️ Warning: Cannot access directory {current_dir}: {e}")
                return
            
            for entry in entries:
                if entry.is_file():
                    should_process, reason = self.should_process_file(
                        entry, min_size, max_size, exclude_patterns, include_hidden
                    )
                    if should_process:
                        files_to_process.append(entry)
                    else:
                        self.skipped_files.append((entry, reason))
                
                elif entry.is_dir() and recursive:
                    # Skip hidden directories unless explicitly allowed
                    if not include_hidden and entry.name.startswith('.'):
                        continue
                    scan_recursive(entry, current_depth + 1)
        
        scan_recursive(input_dir)
        return files_to_process
    
    def create_output_path(self, encrypted_file: Path, input_base: Path, output_base: Path) -> Path:
        """Create output file path by removing .enc extension and maintaining directory structure."""
        # Get relative path from input base to encrypted file
        try:
            relative_path = encrypted_file.relative_to(input_base)
        except ValueError:
            # Fallback if paths are not related
            relative_path = encrypted_file.name
        
        # Remove .enc extension to restore original filename
        if str(relative_path).lower().endswith('.enc'):
            relative_path = Path(str(relative_path)[:-4])  # Remove last 4 characters (.enc)
        
        # Create output path
        output_file = output_base / relative_path
        
        # Create output directory if needed
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        return output_file
    
    def decrypt_single_file(self, encrypted_file: Path, output_file: Path,
                          password: str, resume: bool = False, verbose: bool = False) -> Dict:
        """
        Decrypt a single file with error handling.
        
        Returns:
            Dictionary with decryption result and metadata
        """
        result = {
            'encrypted_file': str(encrypted_file),
            'output_file': str(output_file),
            'success': False,
            'error': None,
            'skipped': False,
            'start_time': time.time()
        }
        
        try:
            # Check if output exists and resume is enabled
            if resume and output_file.exists():
                if verbose:
                    print(f"⏭️  Skipping {encrypted_file.name} (already decrypted)")
                result['skipped'] = True
                result['success'] = True
                return result
            
            # Perform decryption
            decryption_result = self.decrypt_file(str(encrypted_file), str(output_file), password)
            
            result.update(decryption_result)
            result['success'] = True
            result['processing_time'] = time.time() - result['start_time']
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            result['processing_time'] = time.time() - result['start_time']
            
            # Clean up partial output file on failure
            if output_file.exists():
                try:
                    output_file.unlink()
                except OSError:
                    pass
            
            return result
    
    def decrypt_batch(self, files_to_process: List[Path], input_base: Path,
                     output_base: Path, password: str, resume: bool = False,
                     parallel: bool = False, verbose: bool = False,
                     progress: bool = True, verify_integrity: bool = True) -> Dict:
        """
        Decrypt a batch of encrypted files.
        
        Args:
            files_to_process: List of encrypted files to decrypt
            input_base: Base input directory
            output_base: Base output directory
            password: Decryption password
            resume: Skip already decrypted files
            parallel: Use parallel processing
            verbose: Verbose output
            progress: Show progress information
            verify_integrity: Verify file integrity after decryption
            
        Returns:
            Batch processing results summary
        """
        self.start_time = time.time()
        self.processed_files = 0
        self.failed_files = []
        
        total_files = len(files_to_process)
        successful_decryptions = []
        
        if progress:
            print(f"🔓 Starting batch decryption of {total_files} files...")
            if parallel and self.max_workers > 1:
                print(f"⚡ Using parallel processing with {self.max_workers} workers")
            if verify_integrity:
                print("🔍 Integrity verification enabled")
        
        def process_file_wrapper(encrypted_file: Path) -> Dict:
            output_file = self.create_output_path(encrypted_file, input_base, output_base)
            return self.decrypt_single_file(encrypted_file, output_file, password, resume, verbose)
        
        # Choose processing method
        if parallel and self.max_workers > 1:
            # Parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_file = {
                    executor.submit(process_file_wrapper, file_path): file_path 
                    for file_path in files_to_process
                }
                
                # Process completed tasks
                for future in concurrent.futures.as_completed(future_to_file):
                    result = future.result()
                    self.processed_files += 1
                    
                    if result['success']:
                        successful_decryptions.append(result)
                        if progress:
                            if result['skipped']:
                                status = "⏭️  SKIP"
                            else:
                                status = "✅ DONE"
                            print(f"{status} [{self.processed_files}/{total_files}] {Path(result['encrypted_file']).name}")
                    else:
                        self.failed_files.append(result)
                        if progress:
                            print(f"❌ FAIL [{self.processed_files}/{total_files}] {Path(result['encrypted_file']).name}: {result['error']}")
        else:
            # Sequential processing
            for file_path in files_to_process:
                result = process_file_wrapper(file_path)
                self.processed_files += 1
                
                if result['success']:
                    successful_decryptions.append(result)
                    if progress:
                        if result['skipped']:
                            status = "⏭️  SKIP"
                        else:
                            status = "✅ DONE"
                        print(f"{status} [{self.processed_files}/{total_files}] {file_path.name}")
                else:
                    self.failed_files.append(result)
                    if progress:
                        print(f"❌ FAIL [{self.processed_files}/{total_files}] {file_path.name}: {result['error']}")
        
        # Additional integrity verification if requested
        if verify_integrity and successful_decryptions:
            if progress:
                print("🔍 Performing final integrity verification...")
            
            integrity_failures = []
            for result in successful_decryptions:
                if not result.get('skipped', False):
                    output_path = Path(result['output_file'])
                    if not output_path.exists():
                        integrity_failures.append({
                            'file': result['output_file'],
                            'error': 'Output file does not exist after decryption'
                        })
                    elif output_path.stat().st_size == 0:
                        integrity_failures.append({
                            'file': result['output_file'],
                            'error': 'Output file is empty'
                        })
            
            if integrity_failures:
                print(f"⚠️ Warning: {len(integrity_failures)} files failed integrity verification")
        
        # Generate summary
        total_time = time.time() - self.start_time
        return {
            'total_files': total_files,
            'successful': len(successful_decryptions),
            'failed': len(self.failed_files),
            'skipped': sum(1 for r in successful_decryptions if r.get('skipped', False)),
            'total_time': total_time,
            'successful_decryptions': successful_decryptions,
            'failed_files': self.failed_files,
            'skipped_files': self.skipped_files,
            'integrity_verified': verify_integrity
        }
    
    def generate_manifest(self, batch_result: Dict, output_dir: Path) -> Path:
        """Generate a manifest file with decryption details."""
        manifest_path = output_dir / 'batch_decryption_manifest.json'
        
        manifest = {
            'batch_info': {
                'timestamp': datetime.now().isoformat(),
                'operation': 'batch_decryption',
                'algorithm': 'AES-256-GCM',
                'verification': 'PBKDF2-SHA256',
                'total_files': batch_result['total_files'],
                'successful': batch_result['successful'],
                'failed': batch_result['failed'],
                'skipped': batch_result['skipped'],
                'processing_time_seconds': batch_result['total_time'],
                'integrity_verified': batch_result.get('integrity_verified', False)
            },
            'successful_files': [
                {
                    'encrypted_file': r['encrypted_file'],
                    'decrypted_file': r['decrypted_file'],
                    'original_size': r.get('original_size', 0),
                    'decrypted_size': r.get('decrypted_size', 0),
                    'processing_time': r.get('processing_time', 0),
                    'verification': r.get('verification', 'passed')
                }
                for r in batch_result['successful_decryptions'] 
                if not r.get('skipped', False)
            ],
            'failed_files': [
                {
                    'encrypted_file': r['encrypted_file'],
                    'error': r['error']
                }
                for r in batch_result['failed_files']
            ],
            'skipped_files_filters': [
                {
                    'file': str(f[0]),
                    'reason': f[1]
                }
                for f in batch_result['skipped_files']
            ]
        }
        
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest_path
    
    def read_encryption_manifest(self, manifest_path: Path) -> Optional[Dict]:
        """Read an encryption manifest to get expected files list."""
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    def validate_against_manifest(self, batch_result: Dict, manifest_path: Path) -> Dict:
        """Validate decryption results against original encryption manifest."""
        manifest = self.read_encryption_manifest(manifest_path)
        if not manifest:
            return {'validation_performed': False, 'reason': 'Could not read manifest'}
        
        validation_results = {
            'validation_performed': True,
            'manifest_files': len(manifest.get('successful_files', [])),
            'decrypted_files': len(batch_result['successful_decryptions']),
            'missing_files': [],
            'extra_files': [],
            'size_mismatches': []
        }
        
        # Create lookup dictionaries
        manifest_files = {
            Path(f['encrypted_file']).name: f 
            for f in manifest.get('successful_files', [])
        }
        
        decrypted_files = {
            Path(r['encrypted_file']).name: r 
            for r in batch_result['successful_decryptions']
            if not r.get('skipped', False)
        }
        
        # Check for missing files (in manifest but not decrypted)
        for manifest_name in manifest_files:
            if manifest_name not in decrypted_files:
                validation_results['missing_files'].append(manifest_name)
        
        # Check for extra files (decrypted but not in manifest)
        for decrypted_name in decrypted_files:
            if decrypted_name not in manifest_files:
                validation_results['extra_files'].append(decrypted_name)
        
        # Check for size mismatches
        for name in set(manifest_files.keys()) & set(decrypted_files.keys()):
            manifest_size = manifest_files[name].get('original_size', 0)
            decrypted_size = decrypted_files[name].get('decrypted_size', 0)
            if manifest_size > 0 and manifest_size != decrypted_size:
                validation_results['size_mismatches'].append({
                    'file': name,
                    'expected_size': manifest_size,
                    'actual_size': decrypted_size
                })
        
        return validation_results


def main():
    """Command-line interface for batch media decryption."""
    parser = argparse.ArgumentParser(
        description="Batch decrypt encrypted media files in folders with full security preservation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt entire folder recursively
  python batch_decrypt.py /encrypted /restored --recursive
  
  # Filter by size and exclude patterns
  python batch_decrypt.py /encrypted /restored --min-size 10MB --exclude "temp/*"
  
  # Parallel processing with progress
  python batch_decrypt.py /encrypted /restored --recursive --parallel 4 --verbose
  
  # Resume interrupted batch (skip existing files)
  python batch_decrypt.py /encrypted /restored --recursive --resume
  
  # Dry run to see what would be processed
  python batch_decrypt.py /encrypted /restored --recursive --dry-run
  
  # Verify against original encryption manifest
  python batch_decrypt.py /encrypted /restored --recursive --validate /encrypted/batch_encryption_manifest.json

Environment Variables:
  MEDIA_ENCRYPTION_PASSWORD - Set decryption password (for automation)

Security Notes:
  - Uses same AES-256-GCM decryption as single-file tool
  - Password never appears in command line or process lists
  - Individual file authentication tag verification
  - Optional integrity verification and manifest validation
        """
    )
    
    parser.add_argument('input_dir', help='Input directory containing encrypted files')
    parser.add_argument('output_dir', help='Output directory for decrypted files')
    
    # Processing options
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Process subdirectories recursively')
    parser.add_argument('--min-size', help='Minimum file size (e.g., 1MB, 500KB)')
    parser.add_argument('--max-size', help='Maximum file size (e.g., 10GB, 500MB)')
    parser.add_argument('--exclude', help='Comma-separated glob patterns to exclude')
    parser.add_argument('--include-hidden', action='store_true',
                       help='Include hidden files and directories')
    parser.add_argument('--max-depth', type=int, default=-1,
                       help='Maximum recursion depth (-1 for unlimited)')
    
    # Processing behavior
    parser.add_argument('--parallel', type=int, nargs='?', const=4, default=1,
                       help='Enable parallel processing with N workers (default: 4)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume interrupted batch (skip existing decrypted files)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without decrypting')
    
    # Verification options
    parser.add_argument('--verify-integrity', action='store_true', default=True,
                       help='Perform integrity verification (default: enabled)')
    parser.add_argument('--no-verify-integrity', action='store_true',
                       help='Skip integrity verification')
    parser.add_argument('--validate', help='Validate against encryption manifest file')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--progress', action='store_true', default=True,
                       help='Show progress information (default: enabled)')
    parser.add_argument('--no-progress', action='store_true',
                       help='Disable progress information')
    parser.add_argument('--manifest', action='store_true', default=True,
                       help='Generate manifest file (default: enabled)')
    parser.add_argument('--no-manifest', action='store_true',
                       help='Skip manifest file generation')
    
    args = parser.parse_args()
    
    # Validate paths
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    
    if not input_dir.exists():
        print(f"❌ Error: Input directory does not exist: {input_dir}", file=sys.stderr)
        sys.exit(1)
    
    if not input_dir.is_dir():
        print(f"❌ Error: Input path is not a directory: {input_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Parse options
    min_size = 0
    if args.min_size:
        try:
            min_size = BatchDecryptor().parse_size(args.min_size)
        except ValueError as e:
            print(f"❌ Error: Invalid min-size: {e}", file=sys.stderr)
            sys.exit(1)
    
    max_size = 0
    if args.max_size:
        try:
            max_size = BatchDecryptor().parse_size(args.max_size)
        except ValueError as e:
            print(f"❌ Error: Invalid max-size: {e}", file=sys.stderr)
            sys.exit(1)
    
    exclude_patterns = None
    if args.exclude:
        exclude_patterns = [pattern.strip() for pattern in args.exclude.split(',')]
    
    # Configure options
    show_progress = args.progress and not args.no_progress
    generate_manifest = args.manifest and not args.no_manifest
    verify_integrity = args.verify_integrity and not args.no_verify_integrity
    
    # Initialize decryptor
    max_workers = max(1, args.parallel) if args.parallel > 1 else 1
    decryptor = BatchDecryptor(max_workers=max_workers)
    
    try:
        # Scan for encrypted files to process
        if args.verbose:
            print(f"📁 Scanning directory: {input_dir}")
            print("🔍 Looking for .enc files...")
            if min_size > 0:
                print(f"📏 Minimum size: {decryptor.format_size(min_size)}")
            if max_size > 0:
                print(f"📏 Maximum size: {decryptor.format_size(max_size)}")
            if exclude_patterns:
                print(f"🚫 Exclude patterns: {', '.join(exclude_patterns)}")
        
        files_to_process = decryptor.scan_directory(
            input_dir,
            recursive=args.recursive,
            min_size=min_size,
            max_size=max_size,
            exclude_patterns=exclude_patterns,
            include_hidden=args.include_hidden,
            max_depth=args.max_depth
        )
        
        if not files_to_process:
            print("⚠️  No encrypted files found matching the specified criteria")
            if decryptor.skipped_files:
                print(f"   {len(decryptor.skipped_files)} files were skipped due to filters")
                if args.verbose:
                    print("   Skipped files:")
                    for file_path, reason in decryptor.skipped_files[:10]:  # Show first 10
                        print(f"     - {file_path.name}: {reason}")
                    if len(decryptor.skipped_files) > 10:
                        print(f"     ... and {len(decryptor.skipped_files) - 10} more")
            sys.exit(0)
        
        # Calculate total size
        total_size = sum(decryptor.get_file_size(f) for f in files_to_process)
        
        print(f"📊 Found {len(files_to_process)} encrypted files to decrypt ({decryptor.format_size(total_size)})")
        if decryptor.skipped_files:
            print(f"   {len(decryptor.skipped_files)} files skipped by filters")
        
        # Dry run mode
        if args.dry_run:
            print("\n🔍 DRY RUN - Files that would be decrypted:")
            for i, file_path in enumerate(files_to_process[:20], 1):  # Show first 20
                rel_path = file_path.relative_to(input_dir) if input_dir in file_path.parents else file_path.name
                file_size = decryptor.get_file_size(file_path)
                # Show what the decrypted filename would be
                decrypted_name = str(rel_path)
                if decrypted_name.lower().endswith('.enc'):
                    decrypted_name = decrypted_name[:-4]
                print(f"  {i:3d}. {rel_path} → {decrypted_name} ({decryptor.format_size(file_size)})")
            
            if len(files_to_process) > 20:
                print(f"      ... and {len(files_to_process) - 20} more files")
            
            print(f"\n📊 Total: {len(files_to_process)} files, {decryptor.format_size(total_size)}")
            print("🏃‍♂️ Run without --dry-run to perform actual decryption")
            return
        
        # Confirm large batches
        if len(files_to_process) > 100:
            print(f"\n⚠️  Large batch detected: {len(files_to_process)} files")
            response = input("Continue with decryption? [y/N]: ")
            if response.lower() not in ('y', 'yes'):
                print("❌ Operation cancelled by user")
                sys.exit(0)
        
        # Get password securely
        import getpass
        password = os.environ.get('MEDIA_ENCRYPTION_PASSWORD')
        if password:
            print("🔐 Using password from environment variable (MEDIA_ENCRYPTION_PASSWORD)")
        else:
            password = getpass.getpass("🔐 Enter decryption password for batch: ")
        
        if not password:
            print("❌ Error: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Perform batch decryption
        batch_result = decryptor.decrypt_batch(
            files_to_process,
            input_dir,
            output_dir,
            password,
            resume=args.resume,
            parallel=max_workers > 1,
            verbose=args.verbose,
            progress=show_progress,
            verify_integrity=verify_integrity
        )
        
        # Clear password from memory
        password = "X" * len(password) if password else None
        del password
        
        # Validate against encryption manifest if requested
        validation_results = None
        if args.validate:
            manifest_path = Path(args.validate)
            if manifest_path.exists():
                validation_results = decryptor.validate_against_manifest(batch_result, manifest_path)
                if args.verbose:
                    print(f"📋 Validated against manifest: {manifest_path}")
            else:
                print(f"⚠️ Warning: Manifest file not found: {manifest_path}")
        
        # Generate manifest
        if generate_manifest:
            manifest_path = decryptor.generate_manifest(batch_result, output_dir)
            if args.verbose:
                print(f"📋 Manifest generated: {manifest_path}")
        
        # Print summary
        print(f"\n🎉 Batch decryption completed!")
        print(f"   📁 Input directory: {input_dir}")
        print(f"   📁 Output directory: {output_dir}")
        print(f"   ✅ Successfully decrypted: {batch_result['successful']} files")
        
        if batch_result['skipped'] > 0:
            print(f"   ⏭️  Skipped (already decrypted): {batch_result['skipped']} files")
        
        if batch_result['failed'] > 0:
            print(f"   ❌ Failed: {batch_result['failed']} files")
            if args.verbose:
                print("   Failed files:")
                for failed in batch_result['failed_files']:
                    print(f"     - {Path(failed['encrypted_file']).name}: {failed['error']}")
        
        # Show validation results if performed
        if validation_results and validation_results.get('validation_performed'):
            print(f"   📋 Manifest validation:")
            print(f"      Expected files: {validation_results['manifest_files']}")
            print(f"      Processed files: {validation_results['decrypted_files']}")
            
            if validation_results['missing_files']:
                print(f"      ⚠️ Missing files: {len(validation_results['missing_files'])}")
            
            if validation_results['extra_files']:
                print(f"      ℹ️ Extra files: {len(validation_results['extra_files'])}")
            
            if validation_results['size_mismatches']:
                print(f"      ⚠️ Size mismatches: {len(validation_results['size_mismatches'])}")
        
        total_minutes = batch_result['total_time'] / 60
        print(f"   ⏱️  Total time: {total_minutes:.1f} minutes")
        
        if batch_result['successful'] > 0:
            avg_time = batch_result['total_time'] / batch_result['successful']
            print(f"   ⚡ Average per file: {avg_time:.1f} seconds")
        
        # Exit with error code if any files failed
        if batch_result['failed'] > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n⏸️ Batch decryption interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()