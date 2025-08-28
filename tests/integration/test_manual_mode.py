#!/usr/bin/env python3
"""
Manual mode simulation testing with test-media files.

Tests the complete manual encryption workflow:
client encrypt → upload encrypted → process → download encrypted → client decrypt
Author: Lorenzo Albanese (alblor)
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List

import requests


class ManualModeTester:
    """Test manual encryption mode with test media files."""
    
    def __init__(self, tests_dir: Path):
        self.tests_dir = tests_dir
        self.media_dir = tests_dir / "data" / "media"
        self.results_dir = tests_dir / "results"
        self.client_tools_dir = Path(__file__).parent.parent.parent / "client-tools"
        self.api_url = "https://localhost:8443"
        
        # Ensure results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def get_test_media_files(self) -> List[Path]:
        """Get all test-media-N.mp4 files sorted by number."""
        media_files = list(self.media_dir.glob("test-media-*.mp4"))
        # Sort by number in filename
        return sorted(media_files, key=lambda x: int(x.stem.split('-')[-1]))
    
    def test_manual_mode_workflow(self, media_file: Path, ffmpeg_params: Dict) -> Dict:
        """Test complete manual mode workflow with a media file."""
        test_name = f"manual_{media_file.stem}_{ffmpeg_params.get('preset', 'default')}"
        print(f"  Testing: {test_name}")
        
        try:
            # Step 1: Client-side encryption
            password = f"test_password_{media_file.stem}"
            encrypted_file = self.results_dir / f"{media_file.stem}_encrypted.enc"
            
            encrypt_cmd = [
                "python", str(self.client_tools_dir / "encrypt_media.py"),
                str(media_file),
                "--output", str(encrypted_file),
                "--password", password
            ]
            
            print(f"    Step 1: Encrypting {media_file.name}...")
            start_time = time.time()
            encrypt_result = subprocess.run(encrypt_cmd, capture_output=True, text=True)
            encrypt_time = time.time() - start_time
            
            if encrypt_result.returncode != 0:
                raise Exception(f"Client encryption failed: {encrypt_result.stderr}")
            
            if not encrypted_file.exists():
                raise Exception("Encrypted file not created")
            
            original_size = media_file.stat().st_size
            encrypted_size = encrypted_file.stat().st_size
            
            # Step 2: Upload encrypted file to server (manual mode)
            print(f"    Step 2: Uploading encrypted file to server...")
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            files = {"file": (encrypted_file.name, encrypted_data, "application/octet-stream")}
            data = {
                "params": json.dumps(ffmpeg_params),
                "encryption_mode": "manual",
                "decryption_password": password
            }
            
            upload_start = time.time()
            response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data, verify=False)
            upload_time = time.time() - upload_start
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.text}")
            
            job_data = response.json()
            job_id = job_data["job_id"]
            
            # Step 3: Wait for processing completion
            print(f"    Step 3: Waiting for processing (Job ID: {job_id})...")
            max_wait = 60  # seconds for media processing
            poll_start = time.time()
            
            while time.time() - poll_start < max_wait:
                status_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}", verify=False)
                if status_response.status_code != 200:
                    raise Exception(f"Status check failed: {status_response.text}")
                
                status_data = status_response.json()
                progress = status_data.get('progress', 0)
                
                if status_data["status"] == "completed":
                    break
                elif status_data["status"] == "failed":
                    raise Exception(f"Job failed: {status_data.get('message', 'Unknown error')}")
                
                print(f"      Progress: {progress}%")
                time.sleep(1)
            else:
                raise Exception("Job timeout - did not complete within 60 seconds")
            
            process_time = time.time() - poll_start
            
            # Step 4: Download encrypted result
            print(f"    Step 4: Downloading encrypted result...")
            result_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}/result", verify=False)
            if result_response.status_code != 200:
                raise Exception(f"Result retrieval failed: {result_response.text}")
            
            # Save encrypted result
            encrypted_result_file = self.results_dir / f"{media_file.stem}_processed_encrypted.enc"
            with open(encrypted_result_file, 'wb') as f:
                f.write(result_response.content)
            
            encrypted_result_size = len(result_response.content)
            
            # Step 5: Client-side decryption of result
            print(f"    Step 5: Decrypting processed result...")
            final_result_file = self.results_dir / f"{media_file.stem}_manual_result.mp4"
            
            decrypt_cmd = [
                "python", str(self.client_tools_dir / "decrypt_media.py"),
                str(encrypted_result_file),
                "--output", str(final_result_file),
                "--password", password
            ]
            
            decrypt_start = time.time()
            decrypt_result = subprocess.run(decrypt_cmd, capture_output=True, text=True)
            decrypt_time = time.time() - decrypt_start
            
            if decrypt_result.returncode != 0:
                raise Exception(f"Client decryption failed: {decrypt_result.stderr}")
            
            if not final_result_file.exists():
                raise Exception("Final decrypted result not created")
            
            final_size = final_result_file.stat().st_size
            
            return {
                "test": test_name,
                "status": "PASSED",
                "original_size": original_size,
                "encrypted_size": encrypted_size,
                "encrypted_result_size": encrypted_result_size,
                "final_size": final_size,
                "times": {
                    "encrypt": round(encrypt_time, 3),
                    "upload": round(upload_time, 3),
                    "process": round(process_time, 3),
                    "decrypt": round(decrypt_time, 3),
                    "total": round(encrypt_time + upload_time + process_time + decrypt_time, 3)
                },
                "job_id": job_id,
                "ffmpeg_params": ffmpeg_params
            }
            
        except Exception as e:
            return {
                "test": test_name,
                "status": "FAILED",
                "error": str(e),
                "ffmpeg_params": ffmpeg_params
            }
    
    def run_manual_mode_tests(self) -> Dict:
        """Run manual mode tests with different FFmpeg parameters."""
        print("🎬 Testing Manual Mode - Client-Controlled Encryption")
        results = {"passed": 0, "failed": 0, "details": []}
        
        media_files = self.get_test_media_files()
        if not media_files:
            print("  ⚠️  No test-media files found!")
            return results
        
        # Different FFmpeg parameter sets to test
        test_scenarios = [
            {
                "name": "copy_codecs",
                "params": {"video_codec": "copy", "audio_codec": "copy"}
            },
            {
                "name": "h264_preset_fast",
                "params": {"video_codec": "libx264", "audio_codec": "aac", "preset": "fast"}
            },
            {
                "name": "h264_preset_medium",
                "params": {"video_codec": "libx264", "audio_codec": "copy", "preset": "medium"}
            }
        ]
        
        for media_file in media_files:
            print(f"\n📹 Testing with {media_file.name}")
            
            for scenario in test_scenarios:
                result = self.test_manual_mode_workflow(media_file, scenario["params"])
                
                if result["status"] == "PASSED":
                    results["passed"] += 1
                    times = result["times"]
                    print(f"    ✅ PASSED - Total time: {times['total']}s "
                          f"(encrypt: {times['encrypt']}s, process: {times['process']}s, decrypt: {times['decrypt']}s)")
                else:
                    results["failed"] += 1
                    print(f"    ❌ FAILED - {result['error']}")
                
                results["details"].append(result)
        
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all manual mode tests."""
        print("🚀 Starting Manual Mode Tests")
        print("=" * 50)
        
        results = self.run_manual_mode_tests()
        
        # Summary
        print(f"\n📊 Manual Mode Test Summary")
        print("=" * 50)
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total: {results['passed'] + results['failed']}")
        
        # Save detailed results
        results_file = self.results_dir / "manual_mode_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return results


def main():
    """Run manual mode tests."""
    tests_dir = Path(__file__).parent.parent
    tester = ManualModeTester(tests_dir)
    
    # Check if API is available
    try:
        response = requests.get(f"{tester.api_url}/health", timeout=5, verify=False)
        if response.status_code != 200:
            raise Exception("API health check failed")
    except Exception as e:
        print(f"❌ API not available at {tester.api_url}")
        print(f"   Please ensure the server is running with: make up")
        print(f"   Error: {e}")
        return 1
    
    # Check if media files exist
    media_files = tester.get_test_media_files()
    if not media_files:
        print("❌ No test-media files found!")
        print("   Please run: make test-prepare")
        return 1
    
    print(f"Found {len(media_files)} test media files: {[f.name for f in media_files]}")
    
    # Run tests
    results = tester.run_all_tests()
    
    # Return appropriate exit code
    return 1 if results["failed"] > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())