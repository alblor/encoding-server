#!/usr/bin/env python3
"""
Generate test data for comprehensive testing scenarios.

Creates stub files and manages test media for the secure media encoding server.
Author: Lorenzo Albanese (alblor)
"""

import os
import random
from pathlib import Path


def generate_random_file(filepath: Path, size_bytes: int):
    """Generate a random binary file of specified size."""
    with open(filepath, 'wb') as f:
        # Generate random data in chunks for memory efficiency
        chunk_size = min(8192, size_bytes)
        remaining = size_bytes
        
        while remaining > 0:
            chunk_size = min(chunk_size, remaining)
            random_bytes = bytes(random.getrandbits(8) for _ in range(chunk_size))
            f.write(random_bytes)
            remaining -= chunk_size
    
    print(f"Generated: {filepath} ({size_bytes} bytes)")


def create_fake_mp4_header(filepath: Path, size_bytes: int):
    """Create a fake MP4 file with basic header structure."""
    # Basic MP4 header structure for testing
    mp4_header = bytes([
        # ftyp box (file type)
        0x00, 0x00, 0x00, 0x20,  # box size
        0x66, 0x74, 0x79, 0x70,  # 'ftyp'
        0x69, 0x73, 0x6F, 0x6D,  # brand 'isom'
        0x00, 0x00, 0x02, 0x00,  # minor version
        0x69, 0x73, 0x6F, 0x6D,  # compatible brand 'isom'
        0x69, 0x73, 0x6F, 0x32,  # compatible brand 'iso2'
        0x61, 0x76, 0x63, 0x31,  # compatible brand 'avc1'
        0x6D, 0x70, 0x34, 0x31,  # compatible brand 'mp41'
    ])
    
    with open(filepath, 'wb') as f:
        f.write(mp4_header)
        # Fill the rest with random data to reach desired size
        remaining = size_bytes - len(mp4_header)
        if remaining > 0:
            random_data = bytes(random.getrandbits(8) for _ in range(remaining))
            f.write(random_data)
    
    print(f"Generated fake MP4: {filepath} ({size_bytes} bytes)")


def main():
    """Generate all test data files."""
    script_dir = Path(__file__).parent
    tests_dir = script_dir.parent
    
    # Create stub test files directory
    stubs_dir = tests_dir / "data" / "stubs"
    media_dir = tests_dir / "data" / "media"
    
    stubs_dir.mkdir(parents=True, exist_ok=True)
    media_dir.mkdir(parents=True, exist_ok=True)
    
    print("Generating test stub files...")
    
    # Generate various sizes of random test files
    test_files = [
        ("small_1kb.bin", 1024),
        ("medium_10kb.bin", 10 * 1024),
        ("large_1mb.bin", 1024 * 1024),
        ("tiny_100b.bin", 100),
    ]
    
    for filename, size in test_files:
        filepath = stubs_dir / filename
        generate_random_file(filepath, size)
    
    print("\nGenerating fake MP4 test media files...")
    
    # Generate fake MP4 files for testing (if they don't exist)
    mp4_files = [
        ("test-media-1.mp4", 50 * 1024),    # 50KB
        ("test-media-2.mp4", 100 * 1024),   # 100KB
        ("test-media-3.mp4", 200 * 1024),   # 200KB
    ]
    
    for filename, size in mp4_files:
        filepath = media_dir / filename
        if not filepath.exists():
            create_fake_mp4_header(filepath, size)
        else:
            print(f"Using existing: {filepath}")
    
    print(f"\nTest data generation complete!")
    print(f"Stub files: {stubs_dir}")
    print(f"Media files: {media_dir}")


if __name__ == "__main__":
    main()