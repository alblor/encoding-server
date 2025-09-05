#!/usr/bin/env python3
"""
Batch media encryption utility for folder-level encryption operations.

This tool encrypts entire folders of media files recursively while preserving
directory structure and maintaining all security features of the single-file
encryption tool.

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

# Import from the existing single-file encryptor
from encrypt_media import MediaEncryptor


class BatchEncryptor(MediaEncryptor):
    """Batch media file encryption with directory recursion and filtering."""
    
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
    
    def should_process_file(self, file_path: Path, extensions: Set[str] = None,
                          min_size: int = 0, max_size: int = 0,
                          exclude_patterns: List[str] = None,
                          include_hidden: bool = False) -> Tuple[bool, str]:
        """
        Check if a file should be processed based on filters.
        
        Returns:
            Tuple of (should_process: bool, reason: str)
        """
        # Check if file exists and is readable
        if not file_path.is_file():
            return False, "not a regular file"
        
        if not os.access(file_path, os.R_OK):
            return False, "not readable"
        
        # Check hidden files
        if not include_hidden and file_path.name.startswith('.'):
            return False, "hidden file (use --include-hidden to process)"
        
        # Check extensions
        if extensions:
            file_ext = file_path.suffix.lower().lstrip('.')
            if file_ext not in extensions:
                return False, f"extension '{file_ext}' not in allowed list"
        
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
                      extensions: Set[str] = None, min_size: int = 0,
                      max_size: int = 0, exclude_patterns: List[str] = None,
                      include_hidden: bool = False, max_depth: int = -1) -> List[Path]:
        """
        Scan directory for files to encrypt.
        
        Args:
            input_dir: Input directory path
            recursive: Scan subdirectories
            extensions: Set of allowed file extensions (without dots)
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes (0 = no limit)
            exclude_patterns: List of glob patterns to exclude
            include_hidden: Include hidden files
            max_depth: Maximum recursion depth (-1 = unlimited)
            
        Returns:
            List of file paths to process
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
                        entry, extensions, min_size, max_size, exclude_patterns, include_hidden
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
    
    def create_output_path(self, input_file: Path, input_base: Path, output_base: Path) -> Path:
        """Create output file path maintaining directory structure."""
        # Get relative path from input base to input file
        try:
            relative_path = input_file.relative_to(input_base)
        except ValueError:
            # Fallback if paths are not related
            relative_path = input_file.name
        
        # Create output path with .enc extension
        output_file = output_base / (str(relative_path) + '.enc')
        
        # Create output directory if needed
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        return output_file
    
    def encrypt_single_file(self, input_file: Path, output_file: Path, 
                          password: str, resume: bool = False, verbose: bool = False) -> Dict:
        """
        Encrypt a single file with error handling.
        
        Returns:
            Dictionary with encryption result and metadata
        """
        result = {
            'input_file': str(input_file),
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
                    print(f"⏭️  Skipping {input_file.name} (already encrypted)")
                result['skipped'] = True
                result['success'] = True
                return result
            
            # Perform encryption
            encryption_result = self.encrypt_file(str(input_file), str(output_file), password)
            
            result.update(encryption_result)
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
    
    def encrypt_batch(self, files_to_process: List[Path], input_base: Path,
                     output_base: Path, password: str, resume: bool = False,
                     parallel: bool = False, verbose: bool = False,
                     progress: bool = True) -> Dict:
        """
        Encrypt a batch of files.
        
        Args:
            files_to_process: List of files to encrypt
            input_base: Base input directory
            output_base: Base output directory
            password: Encryption password
            resume: Skip already encrypted files
            parallel: Use parallel processing
            verbose: Verbose output
            progress: Show progress information
            
        Returns:
            Batch processing results summary
        """
        self.start_time = time.time()
        self.processed_files = 0
        self.failed_files = []
        
        total_files = len(files_to_process)
        successful_encryptions = []
        
        if progress:
            print(f"🔐 Starting batch encryption of {total_files} files...")
            if parallel and self.max_workers > 1:
                print(f"⚡ Using parallel processing with {self.max_workers} workers")
        
        def process_file_wrapper(input_file: Path) -> Dict:
            output_file = self.create_output_path(input_file, input_base, output_base)
            return self.encrypt_single_file(input_file, output_file, password, resume, verbose)
        
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
                        successful_encryptions.append(result)
                        if progress:
                            if result['skipped']:
                                status = "⏭️  SKIP"
                            else:
                                status = "✅ DONE"
                            print(f"{status} [{self.processed_files}/{total_files}] {Path(result['input_file']).name}")
                    else:
                        self.failed_files.append(result)
                        if progress:
                            print(f"❌ FAIL [{self.processed_files}/{total_files}] {Path(result['input_file']).name}: {result['error']}")
        else:
            # Sequential processing
            for file_path in files_to_process:
                result = process_file_wrapper(file_path)
                self.processed_files += 1
                
                if result['success']:
                    successful_encryptions.append(result)
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
        
        # Generate summary
        total_time = time.time() - self.start_time
        return {
            'total_files': total_files,
            'successful': len(successful_encryptions),
            'failed': len(self.failed_files),
            'skipped': sum(1 for r in successful_encryptions if r.get('skipped', False)),
            'total_time': total_time,
            'successful_encryptions': successful_encryptions,
            'failed_files': self.failed_files,
            'skipped_files': self.skipped_files
        }
    
    def generate_manifest(self, batch_result: Dict, output_dir: Path) -> Path:
        """Generate a manifest file with encryption details."""
        manifest_path = output_dir / 'batch_encryption_manifest.json'
        
        manifest = {
            'batch_info': {
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM',
                'kdf': 'PBKDF2-SHA256',
                'iterations': 100000,
                'total_files': batch_result['total_files'],
                'successful': batch_result['successful'],
                'failed': batch_result['failed'],
                'skipped': batch_result['skipped'],
                'processing_time_seconds': batch_result['total_time']
            },
            'successful_files': [
                {
                    'input_file': r['input_file'],
                    'encrypted_file': r['encrypted_file'],
                    'original_size': r.get('original_size', 0),
                    'encrypted_size': r.get('encrypted_size', 0),
                    'processing_time': r.get('processing_time', 0)
                }
                for r in batch_result['successful_encryptions'] 
                if not r.get('skipped', False)
            ],
            'failed_files': [
                {
                    'input_file': r['input_file'],
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


def main():
    """Command-line interface for batch media encryption."""
    parser = argparse.ArgumentParser(
        description="Batch encrypt media files in folders with full security preservation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt entire folder recursively
  python batch_encrypt.py /media/videos /encrypted --recursive
  
  # Filter by extensions and size
  python batch_encrypt.py /media /encrypted --extensions mp4,mkv,avi --min-size 10MB
  
  # Parallel processing with progress
  python batch_encrypt.py /media /encrypted --recursive --parallel 4 --verbose
  
  # Resume interrupted batch (skip existing .enc files)
  python batch_encrypt.py /media /encrypted --recursive --resume
  
  # Dry run to see what would be processed
  python batch_encrypt.py /media /encrypted --recursive --dry-run
  
  # Exclude certain patterns
  python batch_encrypt.py /media /encrypted --recursive --exclude "*.tmp,temp/*,**/cache/**"

Environment Variables:
  MEDIA_ENCRYPTION_PASSWORD - Set encryption password (for automation)

Security Notes:
  - Uses same AES-256-GCM encryption as single-file tool
  - Password never appears in command line or process lists
  - All files encrypted with same password for batch convenience
  - Individual file integrity verification with authentication tags
        """
    )
    
    parser.add_argument('input_dir', help='Input directory to encrypt')
    parser.add_argument('output_dir', help='Output directory for encrypted files')
    
    # Processing options
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Process subdirectories recursively')
    parser.add_argument('--extensions', help='Comma-separated list of file extensions to process (e.g., mp4,mkv,avi)')
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
                       help='Resume interrupted batch (skip existing .enc files)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without encrypting')
    
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
    extensions = None
    if args.extensions:
        extensions = set(ext.strip().lower().lstrip('.') for ext in args.extensions.split(','))
    
    min_size = 0
    if args.min_size:
        try:
            min_size = BatchEncryptor().parse_size(args.min_size)
        except ValueError as e:
            print(f"❌ Error: Invalid min-size: {e}", file=sys.stderr)
            sys.exit(1)
    
    max_size = 0
    if args.max_size:
        try:
            max_size = BatchEncryptor().parse_size(args.max_size)
        except ValueError as e:
            print(f"❌ Error: Invalid max-size: {e}", file=sys.stderr)
            sys.exit(1)
    
    exclude_patterns = None
    if args.exclude:
        exclude_patterns = [pattern.strip() for pattern in args.exclude.split(',')]
    
    # Configure output
    show_progress = args.progress and not args.no_progress
    generate_manifest = args.manifest and not args.no_manifest
    
    # Initialize encryptor
    max_workers = max(1, args.parallel) if args.parallel > 1 else 1
    encryptor = BatchEncryptor(max_workers=max_workers)
    
    try:
        # Scan for files to process
        if args.verbose:
            print(f"📁 Scanning directory: {input_dir}")
            if extensions:
                print(f"🔍 Extensions filter: {', '.join(sorted(extensions))}")
            if min_size > 0:
                print(f"📏 Minimum size: {encryptor.format_size(min_size)}")
            if max_size > 0:
                print(f"📏 Maximum size: {encryptor.format_size(max_size)}")
            if exclude_patterns:
                print(f"🚫 Exclude patterns: {', '.join(exclude_patterns)}")
        
        files_to_process = encryptor.scan_directory(
            input_dir,
            recursive=args.recursive,
            extensions=extensions,
            min_size=min_size,
            max_size=max_size,
            exclude_patterns=exclude_patterns,
            include_hidden=args.include_hidden,
            max_depth=args.max_depth
        )
        
        if not files_to_process:
            print("⚠️  No files found matching the specified criteria")
            if encryptor.skipped_files:
                print(f"   {len(encryptor.skipped_files)} files were skipped due to filters")
                if args.verbose:
                    print("   Skipped files:")
                    for file_path, reason in encryptor.skipped_files[:10]:  # Show first 10
                        print(f"     - {file_path.name}: {reason}")
                    if len(encryptor.skipped_files) > 10:
                        print(f"     ... and {len(encryptor.skipped_files) - 10} more")
            sys.exit(0)
        
        # Calculate total size
        total_size = sum(encryptor.get_file_size(f) for f in files_to_process)
        
        print(f"📊 Found {len(files_to_process)} files to encrypt ({encryptor.format_size(total_size)})")
        if encryptor.skipped_files:
            print(f"   {len(encryptor.skipped_files)} files skipped by filters")
        
        # Dry run mode
        if args.dry_run:
            print("\n🔍 DRY RUN - Files that would be encrypted:")
            for i, file_path in enumerate(files_to_process[:20], 1):  # Show first 20
                rel_path = file_path.relative_to(input_dir) if input_dir in file_path.parents else file_path.name
                file_size = encryptor.get_file_size(file_path)
                print(f"  {i:3d}. {rel_path} ({encryptor.format_size(file_size)})")
            
            if len(files_to_process) > 20:
                print(f"      ... and {len(files_to_process) - 20} more files")
            
            print(f"\n📊 Total: {len(files_to_process)} files, {encryptor.format_size(total_size)}")
            print("🏃‍♂️ Run without --dry-run to perform actual encryption")
            return
        
        # Confirm large batches
        if len(files_to_process) > 100:
            print(f"\n⚠️  Large batch detected: {len(files_to_process)} files")
            response = input("Continue with encryption? [y/N]: ")
            if response.lower() not in ('y', 'yes'):
                print("❌ Operation cancelled by user")
                sys.exit(0)
        
        # Get password securely
        import getpass
        password = os.environ.get('MEDIA_ENCRYPTION_PASSWORD')
        if password:
            print("🔐 Using password from environment variable (MEDIA_ENCRYPTION_PASSWORD)")
        else:
            password = getpass.getpass("🔐 Enter encryption password for batch: ")
            confirm_password = getpass.getpass("🔐 Confirm password: ")
            
            if password != confirm_password:
                print("❌ Error: Passwords do not match", file=sys.stderr)
                sys.exit(1)
            
            # Clear confirmation password
            confirm_password = None
        
        if not password:
            print("❌ Error: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Perform batch encryption
        batch_result = encryptor.encrypt_batch(
            files_to_process,
            input_dir,
            output_dir,
            password,
            resume=args.resume,
            parallel=max_workers > 1,
            verbose=args.verbose,
            progress=show_progress
        )
        
        # Clear password from memory
        password = "X" * len(password) if password else None
        del password
        
        # Generate manifest
        if generate_manifest:
            manifest_path = encryptor.generate_manifest(batch_result, output_dir)
            if args.verbose:
                print(f"📋 Manifest generated: {manifest_path}")
        
        # Print summary
        print(f"\n🎉 Batch encryption completed!")
        print(f"   📁 Input directory: {input_dir}")
        print(f"   📁 Output directory: {output_dir}")
        print(f"   ✅ Successfully encrypted: {batch_result['successful']} files")
        
        if batch_result['skipped'] > 0:
            print(f"   ⏭️  Skipped (already encrypted): {batch_result['skipped']} files")
        
        if batch_result['failed'] > 0:
            print(f"   ❌ Failed: {batch_result['failed']} files")
            if args.verbose:
                print("   Failed files:")
                for failed in batch_result['failed_files']:
                    print(f"     - {Path(failed['input_file']).name}: {failed['error']}")
        
        total_minutes = batch_result['total_time'] / 60
        print(f"   ⏱️  Total time: {total_minutes:.1f} minutes")
        
        if batch_result['successful'] > 0:
            avg_time = batch_result['total_time'] / batch_result['successful']
            print(f"   ⚡ Average per file: {avg_time:.1f} seconds")
        
        # Exit with error code if any files failed
        if batch_result['failed'] > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n⏸️ Batch encryption interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()