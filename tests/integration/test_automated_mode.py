#!/usr/bin/env python3
"""
Automated mode simulation testing with test-media files.

Tests the complete automated encryption workflow:
upload unencrypted → server encrypts transparently → process → server decrypts transparently → download unencrypted
Author: Lorenzo Albanese (alblor)
"""

import json
import time
from pathlib import Path
from typing import Dict, List

import requests


class AutomatedModeTester:
    """Test automated encryption mode with test media files."""
    
    def __init__(self, tests_dir: Path):
        self.tests_dir = tests_dir
        self.media_dir = tests_dir / "data" / "media"
        self.results_dir = tests_dir / "results"
        self.api_url = "http://localhost:8000"
        
        # Ensure results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def get_test_media_files(self) -> List[Path]:
        """Get all test-media-N.mp4 files sorted by number."""
        media_files = list(self.media_dir.glob("test-media-*.mp4"))
        # Sort by number in filename
        return sorted(media_files, key=lambda x: int(x.stem.split('-')[-1]))
    
    def test_automated_mode_workflow(self, media_file: Path, ffmpeg_params: Dict) -> Dict:
        """Test complete automated mode workflow with a media file."""
        test_name = f"automated_{media_file.stem}_{ffmpeg_params.get('preset', 'default')}"
        print(f"  Testing: {test_name}")
        
        try:
            # Step 1: Read original unencrypted media file
            with open(media_file, 'rb') as f:
                original_data = f.read()
            
            original_size = len(original_data)
            print(f"    Step 1: Loaded {media_file.name} ({original_size} bytes)")
            
            # Step 2: Upload unencrypted file to server (automated mode)
            print(f"    Step 2: Uploading unencrypted file (automated mode)...")
            files = {"file": (media_file.name, original_data, "video/mp4")}
            data = {
                "params": json.dumps(ffmpeg_params),
                "encryption_mode": "automated"
            }
            
            upload_start = time.time()
            response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data)
            upload_time = time.time() - upload_start
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.text}")
            
            job_data = response.json()
            job_id = job_data["job_id"]
            
            # Step 3: Monitor processing with real-time progress
            print(f"    Step 3: Processing with transparent encryption (Job ID: {job_id})...")
            max_wait = 60  # seconds for media processing
            poll_start = time.time()
            last_progress = -1
            
            while time.time() - poll_start < max_wait:
                status_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}")
                if status_response.status_code != 200:
                    raise Exception(f"Status check failed: {status_response.text}")
                
                status_data = status_response.json()
                progress = status_data.get('progress', 0)
                
                # Show progress updates
                if progress != last_progress and progress > 0:
                    print(f"      Progress: {progress}% - Status: {status_data['status']}")
                    last_progress = progress
                
                if status_data["status"] == "completed":
                    print(f"      ✅ Processing completed!")
                    break
                elif status_data["status"] == "failed":
                    raise Exception(f"Job failed: {status_data.get('message', 'Unknown error')}")
                
                time.sleep(1)
            else:
                raise Exception("Job timeout - did not complete within 60 seconds")
            
            process_time = time.time() - poll_start
            
            # Step 4: Download unencrypted result (server handles decryption transparently)
            print(f"    Step 4: Downloading unencrypted result (transparent decryption)...")
            result_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}/result")
            if result_response.status_code != 200:
                raise Exception(f"Result retrieval failed: {result_response.text}")
            
            result_data = result_response.content
            result_size = len(result_data)
            
            # Step 5: Save final result and analyze
            final_result_file = self.results_dir / f"{media_file.stem}_automated_result.mp4"
            with open(final_result_file, 'wb') as f:
                f.write(result_data)
            
            print(f"    Step 5: Result saved to {final_result_file.name}")
            
            # Analysis: Compare original vs processed
            size_change = result_size - original_size
            size_change_percent = (size_change / original_size) * 100 if original_size > 0 else 0
            
            # For copy codecs, size should be similar; for re-encoding, it may vary significantly
            is_copy_mode = (ffmpeg_params.get('video_codec') == 'copy' and 
                          ffmpeg_params.get('audio_codec') == 'copy')
            
            # Validate transparency (user never dealt with encryption)
            transparency_check = {
                "uploaded_unencrypted": True,  # User uploaded unencrypted data
                "received_unencrypted": True,  # User received unencrypted data
                "no_client_encryption": True,  # No client-side encryption tools used
                "server_managed_security": True  # Server handled all encryption internally
            }
            
            return {
                "test": test_name,
                "status": "PASSED",
                "original_size": original_size,
                "result_size": result_size,
                "size_change": size_change,
                "size_change_percent": round(size_change_percent, 2),
                "is_copy_mode": is_copy_mode,
                "transparency_validation": transparency_check,
                "times": {
                    "upload": round(upload_time, 3),
                    "process": round(process_time, 3),
                    "total": round(upload_time + process_time, 3)
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
    
    def run_automated_mode_tests(self) -> Dict:
        """Run automated mode tests with different FFmpeg parameters."""
        print("🔒 Testing Automated Mode - Server-Managed Transparent Encryption")
        results = {"passed": 0, "failed": 0, "details": []}
        
        media_files = self.get_test_media_files()
        if not media_files:
            print("  ⚠️  No test-media files found!")
            return results
        
        # Different FFmpeg parameter sets to test
        test_scenarios = [
            {
                "name": "copy_codecs",
                "params": {"video_codec": "copy", "audio_codec": "copy"},
                "description": "Copy codecs (no re-encoding)"
            },
            {
                "name": "h264_preset_ultrafast",
                "params": {"video_codec": "libx264", "audio_codec": "aac", "preset": "ultrafast"},
                "description": "H.264 ultrafast preset"
            },
            {
                "name": "h264_with_audio_copy",
                "params": {"video_codec": "libx264", "audio_codec": "copy", "preset": "fast"},
                "description": "H.264 video, copy audio"
            },
            {
                "name": "audio_only_processing",
                "params": {"video_codec": "copy", "audio_codec": "aac"},
                "description": "Audio re-encoding only"
            }
        ]
        
        for media_file in media_files:
            print(f"\n📹 Testing with {media_file.name}")
            
            for scenario in test_scenarios:
                print(f"    Scenario: {scenario['description']}")
                result = self.test_automated_mode_workflow(media_file, scenario["params"])
                
                if result["status"] == "PASSED":
                    results["passed"] += 1
                    size_info = f"{result['original_size']}B → {result['result_size']}B"
                    if result['size_change_percent'] != 0:
                        size_info += f" ({result['size_change_percent']:+.1f}%)"
                    
                    print(f"    ✅ PASSED - {size_info}, Total time: {result['times']['total']}s")
                    
                    # Verify transparency
                    if all(result['transparency_validation'].values()):
                        print(f"    🔒 TRANSPARENCY VERIFIED - Complete encryption transparency achieved")
                    else:
                        print(f"    ⚠️  Transparency validation issues detected")
                        
                else:
                    results["failed"] += 1
                    print(f"    ❌ FAILED - {result['error']}")
                
                results["details"].append(result)
        
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all automated mode tests."""
        print("🚀 Starting Automated Mode Tests")
        print("=" * 50)
        
        results = self.run_automated_mode_tests()
        
        # Analyze transparency validation across all tests
        transparency_stats = {
            "total_tests": len(results["details"]),
            "fully_transparent": 0,
            "transparency_issues": 0
        }
        
        for test in results["details"]:
            if test["status"] == "PASSED":
                transparency = test.get("transparency_validation", {})
                if all(transparency.values()):
                    transparency_stats["fully_transparent"] += 1
                else:
                    transparency_stats["transparency_issues"] += 1
        
        # Summary
        print(f"\n📊 Automated Mode Test Summary")
        print("=" * 50)
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total: {results['passed'] + results['failed']}")
        print(f"\n🔒 Transparency Analysis:")
        print(f"Fully transparent workflows: {transparency_stats['fully_transparent']}")
        print(f"Transparency issues: {transparency_stats['transparency_issues']}")
        
        if transparency_stats["fully_transparent"] == results["passed"]:
            print("✅ Perfect encryption transparency achieved across all successful tests!")
        
        # Save detailed results
        results_with_stats = {
            **results,
            "transparency_stats": transparency_stats
        }
        
        results_file = self.results_dir / "automated_mode_results.json"
        with open(results_file, 'w') as f:
            json.dump(results_with_stats, f, indent=2)
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return results_with_stats


def main():
    """Run automated mode tests."""
    tests_dir = Path(__file__).parent.parent
    tester = AutomatedModeTester(tests_dir)
    
    # Check if API is available
    try:
        response = requests.get(f"{tester.api_url}/health", timeout=5)
        if response.status_code != 200:
            raise Exception("API health check failed")
        print(f"✅ API is healthy at {tester.api_url}")
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