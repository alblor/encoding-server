#!/usr/bin/env python3
"""
Comprehensive job cancellation testing.

Tests graceful job cancellation at different processing stages with complete
resource cleanup validation and security guarantee verification.

Author: Lorenzo Albanese (alblor)
"""

import json
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Any

import requests


class JobCancellationTester:
    """Test job cancellation functionality with comprehensive validation."""
    
    def __init__(self, tests_dir: Path):
        self.tests_dir = tests_dir
        self.media_dir = tests_dir / "data" / "media"
        self.results_dir = tests_dir / "results"
        self.api_url = "https://localhost:8443"
        
        # Ensure results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Track jobs created during testing for cleanup
        self.test_jobs = []
        
        # Test scenarios with different timing requirements (optimized for AV1 encoding)
        self.scenarios = [
            {
                "name": "cancel_queued_job",
                "description": "Cancel job immediately after submission (queued state)",
                "delay_before_cancel": 0.5,  # Cancel almost immediately but allow queuing
                "expected_previous_status": "queued"
            },
            {
                "name": "cancel_early_processing", 
                "description": "Cancel job in early processing stage",
                "delay_before_cancel": 4.0,  # Cancel after AV1 processing starts
                "expected_previous_status": "processing"
            },
            {
                "name": "cancel_mid_processing",
                "description": "Cancel job during active FFmpeg processing",
                "delay_before_cancel": 8.0,  # Cancel during active AV1 encoding
                "expected_previous_status": "processing"
            }
        ]
    
    def test_cancel_nonexistent_job(self) -> Dict:
        """Test cancelling a job that doesn't exist."""
        try:
            fake_job_id = "00000000-0000-0000-0000-000000000000"
            response = requests.post(f"{self.api_url}/v1/jobs/{fake_job_id}/cancel", verify=False)
            
            if response.status_code != 404:
                raise Exception(f"Expected 404, got {response.status_code}: {response.text}")
            
            data = response.json()
            error_msg = data.get("detail", {}).get("error", {}).get("message")
            if not error_msg:
                raise Exception("Missing error message in 404 response")
            
            return {
                "test": "cancel_nonexistent_job",
                "status": "passed",
                "response_code": response.status_code,
                "error_type": data.get("error", {}).get("type"),
                "message": "Correctly rejected cancellation of non-existent job"
            }
            
        except Exception as e:
            return {
                "test": "cancel_nonexistent_job",
                "status": "failed",
                "error": str(e),
                "message": "Failed to properly handle non-existent job cancellation"
            }
    
    def test_cancel_completed_job(self) -> Dict:
        """Test trying to cancel an already completed job."""
        try:
            # Submit a very fast job that will complete quickly
            media_file = self.media_dir / "test-media-1.mp4"
            if not media_file.exists():
                raise Exception(f"Test media file not found: {media_file}")
            
            # Submit job with copy codec for fast completion
            with open(media_file, 'rb') as f:
                files = {'file': f}
                data = {
                    'params': json.dumps({"video_codec": "copy", "audio_codec": "copy"}),
                    'encryption_mode': 'automated'
                }
                response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data, verify=False)
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.status_code}")
            
            job_id = response.json()["job_id"]
            self.test_jobs.append(job_id)
            
            # Wait for job to complete (should be fast with copy)
            max_wait = 30
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                status_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}", verify=False)
                if status_response.status_code == 200:
                    status = status_response.json()["status"]
                    if status == "completed":
                        break
                    elif status == "failed":
                        raise Exception("Job failed unexpectedly")
                time.sleep(1)
            else:
                raise Exception("Job did not complete within time limit")
            
            # Now try to cancel the completed job
            cancel_response = requests.post(f"{self.api_url}/v1/jobs/{job_id}/cancel", verify=False)
            
            if cancel_response.status_code != 400:
                raise Exception(f"Expected 400, got {cancel_response.status_code}: {cancel_response.text}")
            
            data = cancel_response.json()
            error_msg = data.get("detail", {}).get("error", {}).get("message", "")
            if "already completed" not in error_msg.lower():
                raise Exception(f"Wrong error message: {error_msg}")
            
            return {
                "test": "cancel_completed_job",
                "status": "passed",
                "job_id": job_id,
                "response_code": cancel_response.status_code,
                "message": "Correctly rejected cancellation of completed job"
            }
            
        except Exception as e:
            return {
                "test": "cancel_completed_job",
                "status": "failed",
                "error": str(e),
                "message": "Failed to properly handle completed job cancellation"
            }
    
    def test_cancellation_scenario(self, scenario: Dict) -> Dict:
        """Test a specific cancellation scenario."""
        scenario_name = scenario["name"]
        
        try:
            # Submit job for processing
            media_file = self.media_dir / "test-media-2.mp4"  # Use larger file
            if not media_file.exists():
                raise Exception(f"Test media file not found: {media_file}")
            
            with open(media_file, 'rb') as f:
                files = {'file': f}
                data = {
                    'params': json.dumps({
                        "custom_params": [
                            "-vf", "scale=-2:720:flags=lanczos",  # Smaller scale for tests
                            "-c:v", "libaom-av1", 
                            "-crf", "35",  # Higher CRF for faster but still slow encoding
                            "-b:v", "0",
                            "-pix_fmt", "yuv420p",  # 8-bit for speed
                            "-row-mt", "1",
                            "-cpu-used", "4",  # Slower preset for longer processing
                            "-lag-in-frames", "25",
                            "-g", "120",
                            "-c:a", "libopus",
                            "-b:a", "96k"
                        ]
                    }),
                    'encryption_mode': 'automated'
                }
                response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data, verify=False)
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.status_code}")
            
            job_data = response.json()
            job_id = job_data["job_id"]
            self.test_jobs.append(job_id)
            
            # Wait for specified delay before cancellation
            if scenario["delay_before_cancel"] > 0:
                time.sleep(scenario["delay_before_cancel"])
            
            # Check job status before cancellation
            pre_cancel_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}", verify=False)
            if pre_cancel_response.status_code != 200:
                raise Exception("Failed to get job status before cancellation")
            
            pre_cancel_status = pre_cancel_response.json()["status"]
            
            # Perform cancellation
            cancel_start_time = time.time()
            cancel_response = requests.post(f"{self.api_url}/v1/jobs/{job_id}/cancel", verify=False)
            cancel_duration = time.time() - cancel_start_time
            
            if cancel_response.status_code not in [200, 400]:
                # 400 might occur if job completed during delay
                if cancel_response.status_code == 400:
                    error_msg = cancel_response.json().get("detail", {}).get("error", {}).get("message", "")
                    if "already completed" in error_msg.lower():
                        return {
                            "test": scenario_name,
                            "status": "skipped", 
                            "job_id": job_id,
                            "message": "Job completed before cancellation could be tested",
                            "pre_cancel_status": pre_cancel_status
                        }
                    else:
                        raise Exception(f"Unexpected 400 error: {error_msg}")
                else:
                    raise Exception(f"Cancellation failed: {cancel_response.status_code} - {cancel_response.text}")
            
            cancel_data = cancel_response.json()
            
            # Validate cancellation response
            expected_fields = ["success", "job_id", "status", "cancelled_at", "previous_status", "cleanup_performed"]
            missing_fields = [field for field in expected_fields if field not in cancel_data]
            if missing_fields:
                raise Exception(f"Missing fields in cancellation response: {missing_fields}")
            
            if cancel_data["status"] != "cancelled":
                raise Exception(f"Expected status 'cancelled', got: {cancel_data['status']}")
            
            if cancel_data["job_id"] != job_id:
                raise Exception(f"Job ID mismatch in response: {cancel_data['job_id']}")
            
            # Validate cleanup was performed
            cleanup_performed = cancel_data.get("cleanup_performed", [])
            if not isinstance(cleanup_performed, list):
                raise Exception("cleanup_performed should be a list")
            
            # Check job status after cancellation
            time.sleep(0.5)  # Brief pause to ensure status update
            post_cancel_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}", verify=False)
            if post_cancel_response.status_code != 200:
                raise Exception("Failed to get job status after cancellation")
            
            final_status = post_cancel_response.json()["status"]
            if final_status != "cancelled":
                raise Exception(f"Job status should be 'cancelled', got: {final_status}")
            
            # Verify result is not downloadable
            result_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}/result", verify=False)
            if result_response.status_code != 400:
                raise Exception(f"Expected 400 for cancelled job result, got: {result_response.status_code}")
            
            return {
                "test": scenario_name,
                "status": "passed",
                "job_id": job_id,
                "pre_cancel_status": pre_cancel_status,
                "final_status": final_status,
                "cancellation_duration": round(cancel_duration, 3),
                "cleanup_performed": cleanup_performed,
                "message": f"Successfully cancelled {scenario['description']}",
                "validation": {
                    "status_correct": final_status == "cancelled",
                    "result_not_downloadable": result_response.status_code == 400,
                    "cleanup_reported": len(cleanup_performed) > 0
                }
            }
            
        except Exception as e:
            return {
                "test": scenario_name,
                "status": "failed", 
                "error": str(e),
                "message": f"Failed to test {scenario['description']}"
            }
    
    def test_double_cancellation(self) -> Dict:
        """Test cancelling the same job twice."""
        try:
            # Submit job
            media_file = self.media_dir / "test-media-1.mp4"
            if not media_file.exists():
                raise Exception(f"Test media file not found: {media_file}")
            
            with open(media_file, 'rb') as f:
                files = {'file': f}
                data = {
                    'params': json.dumps({
                        "custom_params": [
                            "-vf", "scale=-2:720:flags=lanczos",  # Smaller scale for tests
                            "-c:v", "libaom-av1", 
                            "-crf", "35",  # Higher CRF for faster but still slow encoding
                            "-b:v", "0",
                            "-pix_fmt", "yuv420p",  # 8-bit for speed
                            "-row-mt", "1",
                            "-cpu-used", "4",  # Slower preset for longer processing
                            "-lag-in-frames", "25",
                            "-g", "120",
                            "-c:a", "libopus",
                            "-b:a", "96k"
                        ]
                    }),
                    'encryption_mode': 'automated'
                }
                response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data, verify=False)
            
            if response.status_code != 200:
                raise Exception(f"Job submission failed: {response.status_code}")
            
            job_id = response.json()["job_id"]
            self.test_jobs.append(job_id)
            
            # Wait for job to start processing (AV1 takes time to initialize)
            time.sleep(3)  # Ensure job is processing when we cancel
            
            # First cancellation
            first_cancel = requests.post(f"{self.api_url}/v1/jobs/{job_id}/cancel", verify=False)
            if first_cancel.status_code == 400:
                # Check if it's already completed
                error_msg = first_cancel.json().get("detail", {}).get("error", {}).get("message", "")
                if "already completed" not in error_msg.lower():
                    raise Exception(f"First cancellation failed: {first_cancel.status_code}")
            elif first_cancel.status_code != 200:
                raise Exception(f"First cancellation failed: {first_cancel.status_code}")
            
            # Wait to ensure first cancellation is fully processed
            time.sleep(3)  # Ensure first cancellation completes fully with cleanup
            
            # Second cancellation (should fail with appropriate error)
            second_cancel = requests.post(f"{self.api_url}/v1/jobs/{job_id}/cancel", verify=False)
            
            if second_cancel.status_code != 400:
                raise Exception(f"Expected 400 for double cancellation, got: {second_cancel.status_code}")
            
            error_data = second_cancel.json()
            error_msg = error_data.get("detail", {}).get("error", {}).get("message", "")
            if "already cancelled" not in error_msg.lower():
                raise Exception(f"Wrong error message for double cancellation: {error_msg}")
            
            return {
                "test": "double_cancellation",
                "status": "passed",
                "job_id": job_id,
                "first_cancel_code": first_cancel.status_code,
                "second_cancel_code": second_cancel.status_code,
                "message": "Correctly handled double cancellation attempt"
            }
            
        except Exception as e:
            return {
                "test": "double_cancellation",
                "status": "failed",
                "error": str(e),
                "message": "Failed to properly handle double cancellation"
            }
    
    def cleanup_test_jobs(self) -> Dict:
        """Clean up any remaining test jobs."""
        cleanup_results = []
        
        for job_id in self.test_jobs:
            try:
                # Try to cancel in case it's still running
                cancel_response = requests.post(f"{self.api_url}/v1/jobs/{job_id}/cancel", verify=False)
                cleanup_results.append({
                    "job_id": job_id,
                    "cleanup_attempted": True,
                    "response_code": cancel_response.status_code
                })
            except Exception as e:
                cleanup_results.append({
                    "job_id": job_id,
                    "cleanup_attempted": True,
                    "error": str(e)
                })
        
        return {
            "cleanup_performed": len(cleanup_results),
            "jobs_cleaned": cleanup_results
        }
    
    def run_all_tests(self) -> Dict:
        """Run all cancellation tests."""
        print("\n🎯 Starting comprehensive job cancellation tests...")
        print("=" * 70)
        
        all_results = []
        passed = 0
        failed = 0
        skipped = 0
        
        # Test 1: Cancel non-existent job
        print("📋 Test 1: Cancel non-existent job")
        result = self.test_cancel_nonexistent_job()
        all_results.append(result)
        print(f"   Result: {result['status'].upper()}")
        if result['status'] == 'passed':
            passed += 1
        elif result['status'] == 'failed':
            failed += 1
            print(f"   Error: {result.get('error', 'Unknown error')}")
        
        # Test 2: Cancel completed job
        print("\n📋 Test 2: Cancel completed job")
        result = self.test_cancel_completed_job()
        all_results.append(result)
        print(f"   Result: {result['status'].upper()}")
        if result['status'] == 'passed':
            passed += 1
        elif result['status'] == 'failed':
            failed += 1
            print(f"   Error: {result.get('error', 'Unknown error')}")
        
        # Test 3-5: Cancellation scenarios
        for i, scenario in enumerate(self.scenarios, 3):
            print(f"\n📋 Test {i}: {scenario['description']}")
            result = self.test_cancellation_scenario(scenario)
            all_results.append(result)
            print(f"   Result: {result['status'].upper()}")
            
            if result['status'] == 'passed':
                passed += 1
                cleanup = result.get('cleanup_performed', [])
                print(f"   Cleanup performed: {', '.join(cleanup) if cleanup else 'None reported'}")
            elif result['status'] == 'failed':
                failed += 1
                print(f"   Error: {result.get('error', 'Unknown error')}")
            elif result['status'] == 'skipped':
                skipped += 1
                print(f"   Reason: {result.get('message', 'Unknown reason')}")
        
        # Test 6: Double cancellation
        print(f"\n📋 Test {len(self.scenarios) + 3}: Double cancellation attempt")
        result = self.test_double_cancellation()
        all_results.append(result)
        print(f"   Result: {result['status'].upper()}")
        if result['status'] == 'passed':
            passed += 1
        elif result['status'] == 'failed':
            failed += 1
            print(f"   Error: {result.get('error', 'Unknown error')}")
        
        # Cleanup
        print("\n🧹 Cleaning up test jobs...")
        cleanup_result = self.cleanup_test_jobs()
        
        # Final results
        total_tests = len(all_results)
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0
        
        summary = {
            "test_suite": "job_cancellation",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "success_rate": round(success_rate, 1),
            "test_results": all_results,
            "cleanup": cleanup_result
        }
        
        print("\n" + "=" * 70)
        print(f"🎯 Job Cancellation Tests Complete")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed}")
        print(f"   Failed: {failed}")
        print(f"   Skipped: {skipped}")
        print(f"   Success Rate: {success_rate:.1f}%")
        print("=" * 70)
        
        # Save results
        results_file = self.results_dir / "job_cancellation_results.json"
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return summary


def main():
    """Main test execution."""
    tests_dir = Path(__file__).parent.parent
    tester = JobCancellationTester(tests_dir)
    
    try:
        results = tester.run_all_tests()
        
        # Exit with appropriate code
        if results["failed"] > 0:
            exit(1)
        else:
            exit(0)
            
    except KeyboardInterrupt:
        print("\n⚠️ Tests interrupted by user")
        tester.cleanup_test_jobs()
        exit(130)
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        tester.cleanup_test_jobs()
        exit(1)


if __name__ == "__main__":
    main()