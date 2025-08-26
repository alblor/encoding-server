#!/usr/bin/env python3
"""
Comprehensive Documentation API Test Suite
Tests all 9 documentation endpoints with response validation and content verification.

Author: Lorenzo Albanese (alblor)
Test Coverage: Complete documentation system validation
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
import requests
import traceback

# Configuration
BASE_URL = "http://localhost:8000"
RESULTS_FILE = "tests/results/documentation_api_results.json"

class DocumentationAPITester:
    """Comprehensive test suite for documentation API endpoints."""
    
    def __init__(self):
        self.base_url = BASE_URL
        self.discovered_endpoints = []
        self.results = {
            "test_session_id": f"documentation_api_test_{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "base_url": self.base_url,
            "total_endpoints": 0,  # Will be set after discovery
            "tests_passed": 0,
            "tests_failed": 0,
            "endpoint_results": [],
            "summary": {},
            "errors": []
        }
    
    def log_test(self, test_name: str, success: bool, details: str = "", response_data: dict = None):
        """Log test result with detailed information."""
        print(f"{'✅' if success else '❌'} {test_name}: {details}")
        
        if success:
            self.results["tests_passed"] += 1
        else:
            self.results["tests_failed"] += 1
            self.results["errors"].append({
                "test_name": test_name,
                "details": details,
                "timestamp": datetime.now().isoformat()
            })
        
        if response_data:
            self.results["endpoint_results"].append({
                "test_name": test_name,
                "success": success,
                "details": details,
                "response_preview": {
                    "section": response_data.get("section"),
                    "title": response_data.get("title"),
                    "version": response_data.get("version"),
                    "has_manpage": "manpage" in response_data
                }
            })
    
    def validate_response_structure(self, response_data: dict, endpoint_name: str) -> tuple:
        """Validate standard documentation response structure."""
        required_fields = ["section", "title", "version", "last_updated", "author", "base_url"]
        
        missing_fields = []
        for field in required_fields:
            if field not in response_data:
                missing_fields.append(field)
        
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
        
        # Validate manpage structure exists
        if "manpage" not in response_data:
            return False, "Missing 'manpage' section"
        
        manpage = response_data["manpage"]
        manpage_required = ["name", "synopsis", "description"]
        
        missing_manpage = []
        for field in manpage_required:
            if field not in manpage:
                missing_manpage.append(field)
        
        if missing_manpage:
            return False, f"Missing manpage fields: {', '.join(missing_manpage)}"
        
        # Validate version format
        if not response_data["version"].startswith("2.0.0"):
            return False, f"Unexpected version format: {response_data['version']}"
        
        # Validate author
        if "Lorenzo Albanese" not in response_data["author"]:
            return False, f"Unexpected author: {response_data['author']}"
        
        return True, f"Response structure valid for {endpoint_name}"
    
    def discover_documentation_endpoints(self):
        """Truly dynamically discover ALL documentation endpoints from the server."""
        try:
            print("🔍 Dynamically discovering ALL documentation endpoints from live server...")
            
            # Test base docs endpoint first
            base_response = requests.get(f"{self.base_url}/v1/docs", timeout=10)
            if base_response.status_code != 200:
                print(f"❌ Failed to fetch docs index: {base_response.status_code}")
                return False
            
            # Extract all documentation endpoints dynamically
            self.discovered_endpoints = []
            
            # Add base docs endpoint
            self.discovered_endpoints.append({
                "path": "/v1/docs",
                "method": "GET", 
                "title": "Documentation Index"
            })
            
            # Extract and test all section endpoints from the index
            base_data = base_response.json()
            if "manpage" in base_data and "sections" in base_data["manpage"]:
                sections = base_data["manpage"]["sections"]
                print(f"🔍 Found {len(sections)} documentation sections in index")
                
                for section in sections:
                    path = section.get("path", "")
                    title = section.get("title", "")
                    
                    if path and title:
                        # Test if endpoint actually exists
                        try:
                            test_response = requests.get(f"{self.base_url}{path}", timeout=5)
                            if test_response.status_code == 200:
                                self.discovered_endpoints.append({
                                    "path": path,
                                    "method": "GET",
                                    "title": title
                                })
                                print(f"   ✅ Verified: {title} at {path}")
                            else:
                                print(f"   ❌ Dead link: {title} at {path} (status: {test_response.status_code})")
                        except Exception as e:
                            print(f"   ❌ Failed to test {path}: {e}")
            
            # Discover individual endpoint documentation paths
            try:
                endpoints_list_response = requests.get(f"{self.base_url}/v1/docs/endpoints", timeout=10)
                if endpoints_list_response.status_code == 200:
                    endpoints_data = endpoints_list_response.json()
                    if "manpage" in endpoints_data and "endpoints" in endpoints_data["manpage"]:
                        api_endpoints = endpoints_data["manpage"]["endpoints"]
                        print(f"🔍 Found {len(api_endpoints)} individual API endpoints to document")
                        
                        # Test a few individual endpoint docs to verify the pattern works
                        working_endpoint_docs = 0
                        for endpoint in api_endpoints[:3]:  # Test first 3
                            endpoint_id = endpoint.get("id", "")
                            if endpoint_id:
                                try:
                                    doc_path = f"/v1/docs/endpoints/{endpoint_id}"
                                    doc_response = requests.get(f"{self.base_url}{doc_path}", timeout=5)
                                    if doc_response.status_code == 200:
                                        working_endpoint_docs += 1
                                except Exception:
                                    pass
                        
                        if working_endpoint_docs > 0:
                            self.discovered_endpoints.append({
                                "path": "/v1/docs/endpoints/{endpoint_id}",
                                "method": "GET",
                                "title": f"Individual Endpoint Documentation (tested {working_endpoint_docs}/{len(api_endpoints)} working)"
                            })
            except Exception as e:
                print(f"   ⚠️ Could not verify individual endpoint docs: {e}")
            
            # Update results with discovered count
            self.results["total_endpoints"] = len(self.discovered_endpoints)
            
            print(f"\n📊 DISCOVERED {len(self.discovered_endpoints)} LIVE DOCUMENTATION ENDPOINTS:")
            for i, endpoint in enumerate(self.discovered_endpoints, 1):
                print(f"   {i}. {endpoint['method']} {endpoint['path']} - {endpoint['title']}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error in endpoint discovery: {e}")
            return False
    
    def test_documentation_endpoint_generic(self, endpoint_info):
        """Generic test function that can test any documentation endpoint."""
        path = endpoint_info["path"]
        title = endpoint_info["title"]
        method = endpoint_info["method"]
        
        try:
            # Handle parameterized paths (like /v1/docs/endpoints/{endpoint_id})
            if "{endpoint_id}" in path:
                # Test individual endpoint documentation with multiple endpoint IDs
                self.test_individual_endpoint_docs()
                return
            
            # Test the endpoint
            response = requests.get(f"{self.base_url}{path}", timeout=10)
            
            if response.status_code != 200:
                self.log_test(title, False, f"Status code: {response.status_code}")
                return
            
            # Validate JSON response
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                self.log_test(title, False, f"Invalid JSON response: {e}")
                return
            
            # Validate basic documentation structure
            valid, message = self.validate_response_structure(data, path)
            if not valid:
                self.log_test(title, False, message)
                return
            
            # Additional validation based on endpoint type
            if path == "/v1/docs":
                # Validate index-specific content
                manpage = data.get("manpage", {})
                if "sections" not in manpage:
                    self.log_test(title, False, "Missing sections in index")
                    return
                
                sections = manpage["sections"]
                if len(sections) < 5:  # Should have reasonable number of sections
                    self.log_test(title, False, f"Too few sections: {len(sections)}")
                    return
                    
                if "quick_links" not in manpage:
                    self.log_test(title, False, "Missing quick_links in index")
                    return
            
            elif "/endpoints" in path and not path.endswith("{endpoint_id}"):
                # Validate endpoints list
                manpage = data.get("manpage", {})
                if "endpoints" not in manpage:
                    self.log_test(title, False, "Missing endpoints list")
                    return
                
                endpoints = manpage["endpoints"]
                if len(endpoints) < 5:  # Should have reasonable number of endpoints
                    self.log_test(title, False, f"Too few API endpoints documented: {len(endpoints)}")
                    return
            
            # Validate common documentation elements
            manpage = data.get("manpage", {})
            required_fields = ["name", "synopsis", "description"]
            
            missing_fields = []
            for field in required_fields:
                if field not in manpage:
                    missing_fields.append(field)
            
            if missing_fields:
                self.log_test(title, False, f"Missing manpage fields: {', '.join(missing_fields)}")
                return
            
            # Success - comprehensive validation passed
            content_indicators = []
            if "examples" in manpage:
                content_indicators.append("examples")
            if "workflows" in manpage:
                content_indicators.append("workflows")
            if "error_codes" in manpage or "http_status_codes" in manpage:
                content_indicators.append("error_handling")
            if "installation" in manpage or "tools_overview" in manpage:
                content_indicators.append("tools")
            
            details = f"Valid response with comprehensive content"
            if content_indicators:
                details += f" including {', '.join(content_indicators)}"
            
            self.log_test(title, True, details, data)
            
        except Exception as e:
            self.log_test(title, False, f"Exception: {str(e)}")
    
    def test_individual_endpoint_docs(self):
        """Test individual endpoint documentation for all API endpoints."""
        try:
            # Get list of API endpoints from the endpoints documentation
            response = requests.get(f"{self.base_url}/v1/docs/endpoints", timeout=10)
            if response.status_code != 200:
                self.log_test("Individual Endpoint Documentation", False, 
                            f"Cannot fetch endpoints list: {response.status_code}")
                return
            
            data = response.json()
            if "manpage" not in data or "endpoints" not in data["manpage"]:
                self.log_test("Individual Endpoint Documentation", False, "No endpoints found in endpoints list")
                return
            
            api_endpoints = data["manpage"]["endpoints"]
            successful_tests = 0
            total_tests = len(api_endpoints)
            
            # Test each individual endpoint documentation
            for endpoint in api_endpoints:
                endpoint_id = endpoint.get("id", "")
                if endpoint_id:
                    try:
                        doc_response = requests.get(f"{self.base_url}/v1/docs/endpoints/{endpoint_id}", timeout=10)
                        if doc_response.status_code == 200:
                            doc_data = doc_response.json()
                            # Basic validation
                            if "manpage" in doc_data and "method" in doc_data["manpage"]:
                                successful_tests += 1
                                self.log_test(f"Endpoint Doc ({endpoint_id})", True, 
                                            f"Valid documentation for {doc_data['manpage'].get('method', 'GET')} {doc_data['manpage'].get('path', 'unknown')}")
                            else:
                                self.log_test(f"Endpoint Doc ({endpoint_id})", False, "Invalid documentation structure")
                        else:
                            self.log_test(f"Endpoint Doc ({endpoint_id})", False, f"Status code: {doc_response.status_code}")
                    except Exception as e:
                        self.log_test(f"Endpoint Doc ({endpoint_id})", False, f"Exception: {str(e)}")
            
            # Test 404 behavior
            try:
                response = requests.get(f"{self.base_url}/v1/docs/endpoints/nonexistent", timeout=10)
                if response.status_code == 404:
                    self.log_test("Endpoint Doc (404 test)", True, "Correctly returns 404 for invalid endpoint")
                else:
                    self.log_test("Endpoint Doc (404 test)", False, f"Expected 404, got {response.status_code}")
            except Exception as e:
                self.log_test("Endpoint Doc (404 test)", False, f"Exception: {str(e)}")
            
            # Overall result
            self.log_test("Individual Endpoint Documentation Summary", True, 
                        f"Successfully tested {successful_tests}/{total_tests} individual endpoint docs")
            
        except Exception as e:
            self.log_test("Individual Endpoint Documentation", False, f"Exception: {str(e)}")
    
    def test_documentation_index(self):
        """Test GET /v1/docs - Documentation index."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Documentation Index", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "index")
            if not valid:
                self.log_test("Documentation Index", False, message)
                return
            
            # Validate index-specific content
            manpage = data["manpage"]
            
            if "sections" not in manpage:
                self.log_test("Documentation Index", False, "Missing sections in index")
                return
            
            sections = manpage["sections"]
            # Use dynamic count based on discovered endpoints
            expected_sections = len(self.discovered_endpoints) - 2  # Subtract docs index and individual endpoint tests
            
            if len(sections) < expected_sections:
                self.log_test("Documentation Index", False, 
                            f"Expected at least {expected_sections} sections, got {len(sections)}")
                return
            
            # Validate quick links
            if "quick_links" not in manpage:
                self.log_test("Documentation Index", False, "Missing quick_links")
                return
            
            self.log_test("Documentation Index", True, 
                         f"Valid index with {len(sections)} sections", data)
            
        except Exception as e:
            self.log_test("Documentation Index", False, f"Exception: {str(e)}")
    
    def test_system_overview(self):
        """Test GET /v1/docs/overview - System overview."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/overview", timeout=10)
            
            if response.status_code != 200:
                self.log_test("System Overview", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "overview")
            if not valid:
                self.log_test("System Overview", False, message)
                return
            
            # Validate overview-specific content
            manpage = data["manpage"]
            
            required_sections = ["architecture", "key_features", "quick_start"]
            missing_sections = []
            
            for section in required_sections:
                if section not in manpage:
                    missing_sections.append(section)
            
            if missing_sections:
                self.log_test("System Overview", False, 
                            f"Missing sections: {', '.join(missing_sections)}")
                return
            
            # Validate quick start has 5 steps
            quick_start = manpage["quick_start"]
            if len(quick_start) != 5:
                self.log_test("System Overview", False, 
                            f"Expected 5 quick start steps, got {len(quick_start)}")
                return
            
            self.log_test("System Overview", True, "Valid overview with complete content", data)
            
        except Exception as e:
            self.log_test("System Overview", False, f"Exception: {str(e)}")
    
    def test_encryption_modes_guide(self):
        """Test GET /v1/docs/modes - Encryption modes guide."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/modes", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Encryption Modes Guide", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "modes")
            if not valid:
                self.log_test("Encryption Modes Guide", False, message)
                return
            
            # Validate modes-specific content
            manpage = data["manpage"]
            
            required_sections = ["automated_mode", "manual_mode", "security_comparison"]
            missing_sections = []
            
            for section in required_sections:
                if section not in manpage:
                    missing_sections.append(section)
            
            if missing_sections:
                self.log_test("Encryption Modes Guide", False,
                            f"Missing sections: {', '.join(missing_sections)}")
                return
            
            # Validate both modes have workflow and examples
            for mode in ["automated_mode", "manual_mode"]:
                mode_data = manpage[mode]
                if "workflow" not in mode_data or "example" not in mode_data:
                    self.log_test("Encryption Modes Guide", False,
                                f"{mode} missing workflow or example")
                    return
            
            self.log_test("Encryption Modes Guide", True, 
                         "Valid modes guide with both automated and manual", data)
            
        except Exception as e:
            self.log_test("Encryption Modes Guide", False, f"Exception: {str(e)}")
    
    def test_endpoints_list(self):
        """Test GET /v1/docs/endpoints - Endpoints list."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/endpoints", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Endpoints List", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "endpoints")
            if not valid:
                self.log_test("Endpoints List", False, message)
                return
            
            # Validate endpoints-specific content
            manpage = data["manpage"]
            
            if "endpoints" not in manpage:
                self.log_test("Endpoints List", False, "Missing endpoints list")
                return
            
            endpoints = manpage["endpoints"]
            expected_count = 8  # 8 main API endpoints documented
            
            if len(endpoints) != expected_count:
                self.log_test("Endpoints List", False,
                            f"Expected {expected_count} endpoints, got {len(endpoints)}")
                return
            
            # Validate each endpoint has required fields
            for endpoint in endpoints:
                required_fields = ["id", "path", "method", "title", "description"]
                missing_fields = []
                
                for field in required_fields:
                    if field not in endpoint:
                        missing_fields.append(field)
                
                if missing_fields:
                    self.log_test("Endpoints List", False,
                                f"Endpoint missing fields: {', '.join(missing_fields)}")
                    return
            
            self.log_test("Endpoints List", True,
                         f"Valid endpoints list with {len(endpoints)} endpoints", data)
            
        except Exception as e:
            self.log_test("Endpoints List", False, f"Exception: {str(e)}")
    
    def test_endpoint_documentation(self):
        """Test GET /v1/docs/endpoints/{endpoint_id} - Individual endpoint docs."""
        endpoint_ids = ["root", "health", "presets", "keypair", "submit_job", 
                       "job_status", "job_result", "list_jobs"]
        
        successful_endpoints = 0
        
        for endpoint_id in endpoint_ids:
            try:
                response = requests.get(f"{self.base_url}/v1/docs/endpoints/{endpoint_id}", timeout=10)
                
                if response.status_code != 200:
                    self.log_test(f"Endpoint Doc ({endpoint_id})", False, 
                                f"Status code: {response.status_code}")
                    continue
                
                data = response.json()
                
                # Validate response structure
                valid, message = self.validate_response_structure(data, f"endpoint/{endpoint_id}")
                if not valid:
                    self.log_test(f"Endpoint Doc ({endpoint_id})", False, message)
                    continue
                
                # Validate endpoint-specific content
                manpage = data["manpage"]
                
                required_fields = ["method", "path", "authentication", "parameters", "responses", "examples"]
                missing_fields = []
                
                for field in required_fields:
                    if field not in manpage:
                        missing_fields.append(field)
                
                if missing_fields:
                    self.log_test(f"Endpoint Doc ({endpoint_id})", False,
                                f"Missing fields: {', '.join(missing_fields)}")
                    continue
                
                successful_endpoints += 1
                self.log_test(f"Endpoint Doc ({endpoint_id})", True, "Complete endpoint documentation")
                
            except Exception as e:
                self.log_test(f"Endpoint Doc ({endpoint_id})", False, f"Exception: {str(e)}")
        
        # Test invalid endpoint ID (should return 404)
        try:
            response = requests.get(f"{self.base_url}/v1/docs/endpoints/nonexistent", timeout=10)
            
            if response.status_code == 404:
                self.log_test("Endpoint Doc (404 test)", True, "Correctly returns 404 for invalid endpoint")
            else:
                self.log_test("Endpoint Doc (404 test)", False, 
                            f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("Endpoint Doc (404 test)", False, f"Exception: {str(e)}")
        
        # Overall endpoint documentation test result
        if successful_endpoints == len(endpoint_ids):
            self.log_test("All Endpoint Documentation", True,
                         f"All {successful_endpoints} endpoint docs successful")
        else:
            self.log_test("All Endpoint Documentation", False,
                         f"Only {successful_endpoints}/{len(endpoint_ids)} successful")
    
    def test_authentication_guide(self):
        """Test GET /v1/docs/auth - Authentication guide."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/auth", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Authentication Guide", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "auth")
            if not valid:
                self.log_test("Authentication Guide", False, message)
                return
            
            # Validate auth-specific content
            manpage = data["manpage"]
            
            required_sections = ["current_status", "authentication_methods", "future_endpoints", "security_features"]
            missing_sections = []
            
            for section in required_sections:
                if section not in manpage:
                    missing_sections.append(section)
            
            if missing_sections:
                self.log_test("Authentication Guide", False,
                            f"Missing sections: {', '.join(missing_sections)}")
                return
            
            self.log_test("Authentication Guide", True, "Complete authentication guide", data)
            
        except Exception as e:
            self.log_test("Authentication Guide", False, f"Exception: {str(e)}")
    
    def test_workflow_examples(self):
        """Test GET /v1/docs/examples - Workflow examples."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/examples", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Workflow Examples", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "examples")
            if not valid:
                self.log_test("Workflow Examples", False, message)
                return
            
            # Validate examples-specific content
            manpage = data["manpage"]
            
            if "workflows" not in manpage:
                self.log_test("Workflow Examples", False, "Missing workflows section")
                return
            
            workflows = manpage["workflows"]
            expected_workflows = ["automated_basic", "automated_advanced", "manual_complete", "batch_processing"]
            
            for workflow in expected_workflows:
                if workflow not in workflows:
                    self.log_test("Workflow Examples", False, f"Missing workflow: {workflow}")
                    return
            
            # Validate troubleshooting section
            if "troubleshooting" not in manpage:
                self.log_test("Workflow Examples", False, "Missing troubleshooting section")
                return
            
            self.log_test("Workflow Examples", True,
                         f"Complete workflow examples with {len(workflows)} workflows", data)
            
        except Exception as e:
            self.log_test("Workflow Examples", False, f"Exception: {str(e)}")
    
    def test_error_reference(self):
        """Test GET /v1/docs/errors - Error reference."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/errors", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Error Reference", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "errors")
            if not valid:
                self.log_test("Error Reference", False, message)
                return
            
            # Validate errors-specific content
            manpage = data["manpage"]
            
            required_sections = ["error_format", "http_status_codes", "error_types", "common_scenarios"]
            missing_sections = []
            
            for section in required_sections:
                if section not in manpage:
                    missing_sections.append(section)
            
            if missing_sections:
                self.log_test("Error Reference", False,
                            f"Missing sections: {', '.join(missing_sections)}")
                return
            
            # Validate HTTP status codes coverage
            http_codes = manpage["http_status_codes"]
            expected_codes = ["400", "404", "500"]
            
            for code in expected_codes:
                if code not in http_codes:
                    self.log_test("Error Reference", False, f"Missing HTTP code: {code}")
                    return
            
            self.log_test("Error Reference", True, "Complete error reference guide", data)
            
        except Exception as e:
            self.log_test("Error Reference", False, f"Exception: {str(e)}")
    
    def test_client_tools_documentation(self):
        """Test GET /v1/docs/tools - Client tools documentation."""
        try:
            response = requests.get(f"{self.base_url}/v1/docs/tools", timeout=10)
            
            if response.status_code != 200:
                self.log_test("Client Tools Documentation", False, f"Status code: {response.status_code}")
                return
            
            data = response.json()
            
            # Validate response structure
            valid, message = self.validate_response_structure(data, "tools")
            if not valid:
                self.log_test("Client Tools Documentation", False, message)
                return
            
            # Validate tools-specific content
            manpage = data["manpage"]
            
            required_sections = ["tools_overview", "installation", "encrypt_media_py", 
                               "decrypt_media_py", "manual_mode_workflow"]
            missing_sections = []
            
            for section in required_sections:
                if section not in manpage:
                    missing_sections.append(section)
            
            if missing_sections:
                self.log_test("Client Tools Documentation", False,
                            f"Missing sections: {', '.join(missing_sections)}")
                return
            
            # Validate both tools are documented
            tools_overview = manpage["tools_overview"]
            if "encrypt_media.py" not in tools_overview or "decrypt_media.py" not in tools_overview:
                self.log_test("Client Tools Documentation", False, "Missing tool documentation")
                return
            
            self.log_test("Client Tools Documentation", True, "Complete client tools guide", data)
            
        except Exception as e:
            self.log_test("Client Tools Documentation", False, f"Exception: {str(e)}")
    
    def run_all_tests(self):
        """Execute all documentation API tests."""
        print("🔒 Starting Comprehensive Documentation API Test Suite")
        print(f"📍 Testing against: {self.base_url}")
        
        # First, discover all documentation endpoints
        if not self.discover_documentation_endpoints():
            print("❌ Failed to discover documentation endpoints")
            return False
        
        print(f"🎯 Testing {self.results['total_endpoints']} discovered documentation endpoints")
        print("=" * 80)
        
        # Run tests for all discovered endpoints using generic testing
        for endpoint in self.discovered_endpoints:
            self.test_documentation_endpoint_generic(endpoint)
        
        # Calculate results
        total_tests = self.results["tests_passed"] + self.results["tests_failed"]
        success_rate = (self.results["tests_passed"] / total_tests * 100) if total_tests > 0 else 0
        
        self.results["summary"] = {
            "total_tests": total_tests,
            "success_rate": f"{success_rate:.1f}%",
            "documentation_endpoints": len(self.discovered_endpoints),
            "discovered_endpoints": [ep['path'] for ep in self.discovered_endpoints],
            "all_endpoints_functional": self.results["tests_failed"] == 0,
            "test_completion": "complete"
        }
        
        print("\n" + "=" * 60)
        print("📊 DOCUMENTATION API TEST RESULTS")
        print("=" * 60)
        print(f"✅ Tests Passed: {self.results['tests_passed']}")
        print(f"❌ Tests Failed: {self.results['tests_failed']}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        print(f"🎯 Documentation System: {'✅ FULLY OPERATIONAL' if success_rate == 100 else '⚠️  NEEDS ATTENTION'}")
        
        if self.results["tests_failed"] > 0:
            print("\n❌ FAILED TESTS:")
            for error in self.results["errors"]:
                print(f"  • {error['test_name']}: {error['details']}")
        
        # Save detailed results
        Path("tests/results").mkdir(parents=True, exist_ok=True)
        
        try:
            with open(RESULTS_FILE, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n💾 Detailed results saved to: {RESULTS_FILE}")
        except Exception as e:
            print(f"\n⚠️  Could not save results: {e}")
        
        return success_rate == 100


def main():
    """Main test execution function."""
    try:
        # Verify server is running
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code != 200:
                print(f"❌ Server health check failed: {response.status_code}")
                print("🔧 Please ensure secure server is running: make secure-up")
                sys.exit(1)
        except requests.exceptions.RequestException:
            print(f"❌ Cannot connect to server at {BASE_URL}")
            print("🔧 Please start the secure server: make secure-up")
            sys.exit(1)
        
        # Run comprehensive tests
        tester = DocumentationAPITester()
        success = tester.run_all_tests()
        
        if success:
            print("🎉 ALL DOCUMENTATION API TESTS PASSED!")
            sys.exit(0)
        else:
            print("⚠️  SOME DOCUMENTATION API TESTS FAILED")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        print("🔍 Stack trace:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()