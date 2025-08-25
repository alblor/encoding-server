#!/usr/bin/env python3
"""
Comprehensive API endpoint simulation testing.

Tests all 11 API endpoints with actual media content to simulate complete user sessions.
Author: Lorenzo Albanese (alblor)
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any

import requests


class APIEndpointTester:
    """Test all API endpoints with comprehensive user session simulation."""
    
    def __init__(self, tests_dir: Path):
        self.tests_dir = tests_dir
        self.media_dir = tests_dir / "data" / "media"
        self.stubs_dir = tests_dir / "data" / "stubs"
        self.results_dir = tests_dir / "results"
        self.api_url = "http://localhost:8000"
        
        # Ensure results directory exists
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Track jobs created during testing for cleanup
        self.created_jobs = []
    
    def test_service_info_endpoint(self) -> Dict:
        """Test the root service information endpoint."""
        try:
            response = requests.get(f"{self.api_url}/")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            # Validate expected fields
            required_fields = ["service", "author", "encryption_modes", "api_version"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                raise Exception(f"Missing required fields: {missing_fields}")
            
            if "automated" not in data["encryption_modes"] or "manual" not in data["encryption_modes"]:
                raise Exception("Missing required encryption modes")
            
            return {
                "endpoint": "GET /",
                "status": "PASSED",
                "response_data": data,
                "validation": "Service info contains all required fields"
            }
            
        except Exception as e:
            return {
                "endpoint": "GET /",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_health_endpoint(self) -> Dict:
        """Test the health check endpoint."""
        try:
            response = requests.get(f"{self.api_url}/health")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            # Validate health check structure
            if data.get("status") != "healthy":
                raise Exception(f"Service not healthy: {data.get('status')}")
            
            if "timestamp" not in data:
                raise Exception("Missing timestamp in health response")
            
            if "services" not in data or "ffmpeg" not in data["services"]:
                raise Exception("Missing services status in health check")
            
            return {
                "endpoint": "GET /health",
                "status": "PASSED",
                "response_data": data,
                "validation": "Health check shows healthy status with services"
            }
            
        except Exception as e:
            return {
                "endpoint": "GET /health",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_presets_endpoint(self) -> Dict:
        """Test the encoding presets endpoint."""
        try:
            response = requests.get(f"{self.api_url}/v1/presets")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            # Validate presets structure
            if "presets" not in data:
                raise Exception("Missing presets field in response")
            
            expected_presets = ["h264_high_quality", "h264_web_optimized"]
            missing_presets = [preset for preset in expected_presets if preset not in data["presets"]]
            
            if missing_presets:
                raise Exception(f"Missing expected presets: {missing_presets}")
            
            return {
                "endpoint": "GET /v1/presets",
                "status": "PASSED",
                "response_data": data,
                "validation": f"Found {len(data['presets'])} presets including required ones"
            }
            
        except Exception as e:
            return {
                "endpoint": "GET /v1/presets",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_keypair_generation_endpoint(self) -> Dict:
        """Test the ECDH keypair generation endpoint."""
        try:
            response = requests.post(f"{self.api_url}/v1/encryption/keypair")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            # Validate keypair structure
            required_fields = ["private_key", "public_key", "algorithm"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                raise Exception(f"Missing required fields: {missing_fields}")
            
            # Validate key formats
            if "BEGIN PRIVATE KEY" not in data["private_key"]:
                raise Exception("Invalid private key format")
            
            if "BEGIN PUBLIC KEY" not in data["public_key"]:
                raise Exception("Invalid public key format")
            
            return {
                "endpoint": "POST /v1/encryption/keypair",
                "status": "PASSED",
                "response_data": {k: v[:50] + "..." if len(v) > 50 else v for k, v in data.items()},
                "validation": "Generated valid ECDH keypair with proper format"
            }
            
        except Exception as e:
            return {
                "endpoint": "POST /v1/encryption/keypair",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_job_submission_endpoint(self, test_file: Path, encryption_mode: str) -> Dict:
        """Test job submission endpoint with actual file."""
        endpoint_name = f"POST /v1/jobs ({encryption_mode} mode)"
        
        try:
            with open(test_file, 'rb') as f:
                file_data = f.read()
            
            files = {"file": (test_file.name, file_data, "video/mp4")}
            data = {
                "params": json.dumps({"video_codec": "copy", "audio_codec": "copy"}),
                "encryption_mode": encryption_mode
            }
            
            response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data)
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            job_data = response.json()
            
            # Validate job submission response
            required_fields = ["job_id", "status", "message"]
            missing_fields = [field for field in required_fields if field not in job_data]
            
            if missing_fields:
                raise Exception(f"Missing required fields: {missing_fields}")
            
            job_id = job_data["job_id"]
            self.created_jobs.append(job_id)
            
            return {
                "endpoint": endpoint_name,
                "status": "PASSED",
                "response_data": job_data,
                "validation": f"Successfully submitted job {job_id} with {len(file_data)} bytes",
                "job_id": job_id
            }
            
        except Exception as e:
            return {
                "endpoint": endpoint_name,
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_job_status_endpoint(self, job_id: str) -> Dict:
        """Test job status retrieval endpoint."""
        try:
            response = requests.get(f"{self.api_url}/v1/jobs/{job_id}")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            job_data = response.json()
            
            # Validate job status structure
            required_fields = ["id", "status", "created_at", "encryption_mode"]
            missing_fields = [field for field in required_fields if field not in job_data]
            
            if missing_fields:
                raise Exception(f"Missing required fields: {missing_fields}")
            
            if job_data["id"] != job_id:
                raise Exception(f"Job ID mismatch: expected {job_id}, got {job_data['id']}")
            
            return {
                "endpoint": f"GET /v1/jobs/{job_id}",
                "status": "PASSED",
                "response_data": job_data,
                "validation": f"Retrieved job status: {job_data['status']} (progress: {job_data.get('progress', 0)}%)"
            }
            
        except Exception as e:
            return {
                "endpoint": f"GET /v1/jobs/{job_id}",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_job_result_endpoint(self, job_id: str) -> Dict:
        """Test job result retrieval endpoint."""
        try:
            # Wait for job completion first
            max_wait = 30
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                status_response = requests.get(f"{self.api_url}/v1/jobs/{job_id}")
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    if status_data["status"] == "completed":
                        break
                    elif status_data["status"] == "failed":
                        raise Exception(f"Job failed: {status_data.get('message', 'Unknown error')}")
                
                time.sleep(1)
            else:
                raise Exception("Job did not complete within timeout")
            
            # Get result
            response = requests.get(f"{self.api_url}/v1/jobs/{job_id}/result")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            result_data = response.content
            result_size = len(result_data)
            
            # Save result for analysis
            result_file = self.results_dir / f"api_test_result_{job_id}.mp4"
            with open(result_file, 'wb') as f:
                f.write(result_data)
            
            return {
                "endpoint": f"GET /v1/jobs/{job_id}/result",
                "status": "PASSED",
                "validation": f"Retrieved result: {result_size} bytes, saved to {result_file.name}",
                "result_size": result_size,
                "result_file": str(result_file)
            }
            
        except Exception as e:
            return {
                "endpoint": f"GET /v1/jobs/{job_id}/result",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_jobs_list_endpoint(self) -> Dict:
        """Test job listing endpoint."""
        try:
            response = requests.get(f"{self.api_url}/v1/jobs")
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")
            
            data = response.json()
            
            # Validate jobs list structure
            required_fields = ["jobs", "total_jobs"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                raise Exception(f"Missing required fields: {missing_fields}")
            
            if not isinstance(data["jobs"], list):
                raise Exception("Jobs field should be a list")
            
            if len(data["jobs"]) != data["total_jobs"]:
                raise Exception(f"Jobs count mismatch: list has {len(data['jobs'])}, total_jobs says {data['total_jobs']}")
            
            return {
                "endpoint": "GET /v1/jobs",
                "status": "PASSED",
                "response_data": {"total_jobs": data["total_jobs"], "jobs_count": len(data["jobs"])},
                "validation": f"Listed {data['total_jobs']} jobs successfully"
            }
            
        except Exception as e:
            return {
                "endpoint": "GET /v1/jobs",
                "status": "FAILED",
                "error": str(e)
            }
    
    def test_error_handling_endpoints(self) -> List[Dict]:
        """Test error handling with invalid requests."""
        error_tests = []
        
        # Test 1: Invalid job ID
        try:
            response = requests.get(f"{self.api_url}/v1/jobs/nonexistent-job-id")
            if response.status_code != 404:
                raise Exception(f"Expected 404, got {response.status_code}")
            
            error_data = response.json()
            if "error" not in error_data:
                raise Exception("Error response missing error field")
            
            error_tests.append({
                "endpoint": "GET /v1/jobs/nonexistent-job-id",
                "status": "PASSED",
                "validation": "Correctly returned 404 for nonexistent job"
            })
            
        except Exception as e:
            error_tests.append({
                "endpoint": "GET /v1/jobs/nonexistent-job-id",
                "status": "FAILED",
                "error": str(e)
            })
        
        # Test 2: Invalid encryption mode
        try:
            files = {"file": ("test.mp4", b"fake_data", "video/mp4")}
            data = {
                "params": json.dumps({"video_codec": "libx264"}),
                "encryption_mode": "invalid_mode"
            }
            
            response = requests.post(f"{self.api_url}/v1/jobs", files=files, data=data)
            if response.status_code != 400:
                raise Exception(f"Expected 400, got {response.status_code}")
            
            error_data = response.json()
            if "error" not in error_data:
                raise Exception("Error response missing error field")
            
            error_tests.append({
                "endpoint": "POST /v1/jobs (invalid encryption mode)",
                "status": "PASSED",
                "validation": "Correctly returned 400 for invalid encryption mode"
            })
            
        except Exception as e:
            error_tests.append({
                "endpoint": "POST /v1/jobs (invalid encryption mode)",
                "status": "FAILED",
                "error": str(e)
            })
        
        return error_tests
    
    def run_comprehensive_api_tests(self) -> Dict:
        """Run comprehensive tests of all API endpoints."""
        print("🌐 Testing All API Endpoints - Complete User Session Simulation")
        results = {"passed": 0, "failed": 0, "details": []}
        
        # Get test files
        media_files = list(self.media_dir.glob("test-media-*.mp4"))
        if not media_files:
            print("  ⚠️  No test-media files found!")
            return results
        
        test_file = media_files[0]  # Use first available media file
        
        # Test sequence simulating complete user session
        test_sequence = [
            ("Service Info", lambda: self.test_service_info_endpoint()),
            ("Health Check", lambda: self.test_health_endpoint()),
            ("Encoding Presets", lambda: self.test_presets_endpoint()),
            ("Keypair Generation", lambda: self.test_keypair_generation_endpoint()),
            ("Job Submission (Automated)", lambda: self.test_job_submission_endpoint(test_file, "automated")),
            ("Job Submission (Manual)", lambda: self.test_job_submission_endpoint(test_file, "manual")),
        ]
        
        # Track jobs for status and result testing
        submitted_jobs = []
        
        # Run basic endpoint tests
        for test_name, test_func in test_sequence:
            print(f"  Testing: {test_name}")
            result = test_func()
            
            if result["status"] == "PASSED":
                results["passed"] += 1
                print(f"    ✅ PASSED - {result.get('validation', 'Success')}")
                
                # Track submitted jobs
                if "job_id" in result:
                    submitted_jobs.append(result["job_id"])
                    
            else:
                results["failed"] += 1
                print(f"    ❌ FAILED - {result['error']}")
            
            results["details"].append(result)
        
        # Test job status and results for submitted jobs
        for job_id in submitted_jobs:
            print(f"  Testing: Job Status for {job_id}")
            status_result = self.test_job_status_endpoint(job_id)
            
            if status_result["status"] == "PASSED":
                results["passed"] += 1
                print(f"    ✅ PASSED - {status_result['validation']}")
            else:
                results["failed"] += 1
                print(f"    ❌ FAILED - {status_result['error']}")
            
            results["details"].append(status_result)
            
            # Test job result retrieval
            print(f"  Testing: Job Result for {job_id}")
            result_result = self.test_job_result_endpoint(job_id)
            
            if result_result["status"] == "PASSED":
                results["passed"] += 1
                print(f"    ✅ PASSED - {result_result['validation']}")
            else:
                results["failed"] += 1
                print(f"    ❌ FAILED - {result_result['error']}")
            
            results["details"].append(result_result)
        
        # Test jobs list
        print(f"  Testing: Jobs List")
        list_result = self.test_jobs_list_endpoint()
        
        if list_result["status"] == "PASSED":
            results["passed"] += 1
            print(f"    ✅ PASSED - {list_result['validation']}")
        else:
            results["failed"] += 1
            print(f"    ❌ FAILED - {list_result['error']}")
        
        results["details"].append(list_result)
        
        # Test error handling
        print(f"  Testing: Error Handling")
        error_tests = self.test_error_handling_endpoints()
        
        for error_test in error_tests:
            if error_test["status"] == "PASSED":
                results["passed"] += 1
                print(f"    ✅ PASSED - {error_test['validation']}")
            else:
                results["failed"] += 1
                print(f"    ❌ FAILED - {error_test['error']}")
            
            results["details"].append(error_test)
        
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all API endpoint tests."""
        print("🚀 Starting Comprehensive API Endpoint Tests")
        print("=" * 50)
        
        results = self.run_comprehensive_api_tests()
        
        # Endpoint coverage analysis
        tested_endpoints = set()
        for test in results["details"]:
            endpoint = test["endpoint"].split(" (")[0]  # Remove mode suffixes
            tested_endpoints.add(endpoint)
        
        expected_endpoints = {
            "GET /", "GET /health", "GET /v1/presets", "POST /v1/encryption/keypair",
            "POST /v1/jobs", "GET /v1/jobs", "GET /v1/jobs/{id}", "GET /v1/jobs/{id}/result"
        }
        
        coverage = len(tested_endpoints.intersection(expected_endpoints)) / len(expected_endpoints) * 100
        
        # Summary
        print(f"\n📊 API Endpoint Test Summary")
        print("=" * 50)
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        print(f"Total Tests: {results['passed'] + results['failed']}")
        print(f"Endpoint Coverage: {coverage:.1f}% ({len(tested_endpoints)} endpoints tested)")
        
        if self.created_jobs:
            print(f"Jobs Created During Testing: {len(self.created_jobs)}")
        
        # Save detailed results
        results_with_coverage = {
            **results,
            "endpoint_coverage": {
                "percentage": coverage,
                "tested_endpoints": sorted(list(tested_endpoints)),
                "expected_endpoints": sorted(list(expected_endpoints))
            },
            "created_jobs": self.created_jobs
        }
        
        results_file = self.results_dir / "api_endpoints_results.json"
        with open(results_file, 'w') as f:
            json.dump(results_with_coverage, f, indent=2)
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        return results_with_coverage


def main():
    """Run API endpoint tests."""
    tests_dir = Path(__file__).parent.parent
    tester = APIEndpointTester(tests_dir)
    
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
    media_files = list(tester.media_dir.glob("test-media-*.mp4"))
    if not media_files:
        print("❌ No test-media files found!")
        print("   Please run: make test-prepare")
        return 1
    
    print(f"Found {len(media_files)} test media files for API testing")
    
    # Run tests
    results = tester.run_all_tests()
    
    # Return appropriate exit code
    return 1 if results["failed"] > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())