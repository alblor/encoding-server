#!/usr/bin/env python3
"""
Progress Tracking Validation Test

Tests real-time FFmpeg progress tracking functionality with detailed validation.
Verifies that progress updates are captured correctly during media processing.

Author: Lorenzo Albanese (alblor)
"""

import json
import time
from pathlib import Path
from typing import Dict, List

import requests


class ProgressTrackingTester:
    """Test real-time progress tracking functionality."""
    
    def __init__(self, tests_dir: Path):
        self.tests_dir = tests_dir
        self.media_dir = tests_dir / "data" / "media"
        self.results_dir = tests_dir / "results"
        self.api_url = "https://localhost:8443"
        
        # Ensure results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def get_test_media_files(self) -> List[Path]:
        """Get all test-media-N.mp4 files sorted by number."""
        media_files = list(self.media_dir.glob("test-media-*.mp4"))
        return sorted(media_files, key=lambda x: int(x.stem.split('-')[-1]))
    
    def test_progress_tracking(self, media_file: Path, ffmpeg_params: Dict) -> Dict:
        """Test progress tracking with detailed validation."""
        test_name = f"progress_{media_file.stem}_{ffmpeg_params.get('preset', 'default')}"
        print(f"  Testing: {test_name}")
        
        try:
            # Step 1: Submit job
            print(f"    Step 1: Submitting job for {media_file.name}...")
            with open(media_file, 'rb') as f:
                media_data = f.read()
            
            files = {"file": (media_file.name, media_data, "video/mp4")}
            data = {
                "params": json.dumps(ffmpeg_params),
                "encryption_mode": "automated"
            }
            
            start_time = time.time()
            response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data, verify=False)
            submit_time = time.time() - start_time
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.text}")
            
            job_data = response.json()
            job_id = job_data["job_id"]
            original_size = len(media_data)
            
            print(f"    Step 2: Monitoring progress for Job ID: {job_id}...")
            
            # Step 2: Monitor progress with detailed tracking
            progress_history = []
            max_wait = 60  # seconds for media processing
            poll_start = time.time()
            last_progress = -1
            
            while time.time() - poll_start < max_wait:
                status_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}", verify=False)
                if status_response.status_code != 200:
                    raise Exception(f"Status check failed: {status_response.text}")
                
                status_data = status_response.json()
                current_progress = status_data.get('progress', 0)
                status = status_data.get('status', 'unknown')
                
                # Record progress if it changed
                if current_progress != last_progress:
                    progress_entry = {
                        "timestamp": time.time() - poll_start,
                        "progress": current_progress,
                        "status": status
                    }
                    progress_history.append(progress_entry)
                    print(f"      Progress: {current_progress}% - Status: {status}")
                    last_progress = current_progress
                
                if status == "completed":
                    print(f"      ✅ Processing completed!")
                    break
                elif status == "failed":
                    raise Exception(f"Job failed: {status_data.get('message', 'Unknown error')}")
                
                time.sleep(0.5)  # Poll every 500ms for granular tracking
            else:
                raise Exception("Job timeout - did not complete within 60 seconds")
            
            process_time = time.time() - poll_start
            
            # Step 3: Validate progress tracking quality
            print(f"    Step 3: Validating progress tracking quality...")
            
            # Progress validation metrics
            total_updates = len(progress_history)
            if total_updates < 2:
                raise Exception(f"Insufficient progress updates: {total_updates} (expected at least 2)")
            
            # Check progress monotonicity (should generally increase)
            non_monotonic_count = 0
            for i in range(1, len(progress_history)):
                if progress_history[i]["progress"] < progress_history[i-1]["progress"]:
                    non_monotonic_count += 1
            
            # Check final progress reached high percentage
            final_progress = progress_history[-1]["progress"]
            if final_progress < 90:
                print(f"      ⚠️ Warning: Final progress only {final_progress}% (expected >90%)")
            
            # Check progress granularity (time between updates)
            if total_updates > 1:
                time_between_updates = []
                for i in range(1, len(progress_history)):
                    time_diff = progress_history[i]["timestamp"] - progress_history[i-1]["timestamp"]
                    time_between_updates.append(time_diff)
                avg_update_interval = sum(time_between_updates) / len(time_between_updates)
            else:
                avg_update_interval = process_time
            
            # Step 4: Retrieve result for size validation
            print(f"    Step 4: Retrieving result...")
            result_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}/result", verify=False)
            if result_response.status_code != 200:
                raise Exception(f"Result retrieval failed: {result_response.text}")
            
            final_size = len(result_response.content)
            
            # Save result for verification
            result_file = self.results_dir / f"{media_file.stem}_progress_result.mp4"
            with open(result_file, 'wb') as f:
                f.write(result_response.content)
            
            return {
                "test": test_name,
                "status": "PASSED",
                "job_id": job_id,
                "original_size": original_size,
                "final_size": final_size,
                "times": {
                    "submit": round(submit_time, 3),
                    "process": round(process_time, 3),
                    "total": round(submit_time + process_time, 3)
                },
                "progress_tracking": {
                    "total_updates": total_updates,
                    "final_progress": final_progress,
                    "non_monotonic_count": non_monotonic_count,
                    "avg_update_interval": round(avg_update_interval, 3),
                    "progress_history": progress_history
                },
                "ffmpeg_params": ffmpeg_params,
                "validation": {
                    "sufficient_updates": total_updates >= 2,
                    "reached_high_progress": final_progress >= 90,
                    "mostly_monotonic": non_monotonic_count <= 1,
                    "reasonable_granularity": avg_update_interval <= 5.0  # Updates every 5 seconds or better
                }
            }
            
        except Exception as e:
            return {
                "test": test_name,
                "status": "FAILED",
                "error": str(e),
                "ffmpeg_params": ffmpeg_params
            }
    
    def run_progress_tracking_tests(self) -> Dict:
        """Run comprehensive progress tracking tests."""
        print("🎬 Testing Progress Tracking - Real-Time FFmpeg Monitoring")
        results = {"passed": 0, "failed": 0, "details": []}
        
        media_files = self.get_test_media_files()
        if not media_files:
            print("  ⚠️  No test-media files found!")
            return results
        
        # Different FFmpeg scenarios to test progress tracking
        test_scenarios = [
            {
                "name": "copy_codecs",
                "params": {"video_codec": "copy", "audio_codec": "copy"},
                "description": "Copy codecs (fastest, minimal progress updates)"
            },
            {
                "name": "h264_medium",
                "params": {"video_codec": "libx264", "audio_codec": "aac", "preset": "medium"},
                "description": "H.264 medium preset (moderate encoding, good progress granularity)"
            },
            {
                "name": "h264_slow",
                "params": {"video_codec": "libx264", "audio_codec": "copy", "preset": "slow"},
                "description": "H.264 slow preset (longer encoding, maximum progress detail)"
            }
        ]
        
        for media_file in media_files[:2]:  # Test with first 2 media files
            print(f"\n📹 Testing with {media_file.name}")
            
            for scenario in test_scenarios:
                print(f"  Scenario: {scenario['description']}")
                result = self.test_progress_tracking(media_file, scenario["params"])
                
                if result["status"] == "PASSED":
                    results["passed"] += 1
                    tracking = result["progress_tracking"]
                    validation = result["validation"]
                    
                    print(f"    ✅ PASSED - {tracking['total_updates']} progress updates")
                    print(f"       Final: {tracking['final_progress']}%, Avg interval: {tracking['avg_update_interval']}s")
                    print(f"       Validation: Updates✅ Progress✅ Monotonic✅ Granular✅" if all(validation.values()) 
                          else f"       Validation: Some checks failed")
                else:
                    results["failed"] += 1
                    print(f"    ❌ FAILED - {result['error']}")
                
                results["details"].append(result)
        
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all progress tracking tests."""
        print("🚀 Starting Progress Tracking Tests")
        print("=" * 50)
        
        results = self.run_progress_tracking_tests()
        
        # Summary
        print(f"\n📊 Progress Tracking Test Summary")
        print("=" * 50)
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total: {results['passed'] + results['failed']}")
        
        # Detailed validation analysis
        if results["details"]:
            passed_tests = [r for r in results["details"] if r["status"] == "PASSED"]
            if passed_tests:
                print(f"\n📈 Progress Tracking Quality Analysis:")
                total_updates = sum(r["progress_tracking"]["total_updates"] for r in passed_tests)
                avg_final_progress = sum(r["progress_tracking"]["final_progress"] for r in passed_tests) / len(passed_tests)
                print(f"Average progress updates per job: {total_updates / len(passed_tests):.1f}")
                print(f"Average final progress reached: {avg_final_progress:.1f}%")
        
        # Save detailed results
        results_file = self.results_dir / "progress_tracking_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return results


def main():
    """Run progress tracking tests."""
    tests_dir = Path(__file__).parent.parent
    tester = ProgressTrackingTester(tests_dir)
    
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