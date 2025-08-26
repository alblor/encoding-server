"""
Comprehensive API Documentation System
Provides manpage-style documentation for all endpoints and system features.

Author: Lorenzo Albanese (alblor)
Architecture: Frontend-ready structured documentation with real examples
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import json


class DocumentationManager:
    """
    Comprehensive documentation manager providing manpage-style API documentation.
    Supports frontend integration with structured JSON responses containing
    detailed endpoint information, examples, and workflow guides.
    """
    
    def __init__(self):
        """Initialize documentation manager with comprehensive content."""
        self.version = "2.0.0-secure"
        self.base_url = "http://localhost:8000"  # Will be configurable in production
        self.author = "Lorenzo Albanese (alblor)"
        
    def _create_response_template(self, section: str, title: str) -> Dict[str, Any]:
        """Create standardized response template for all documentation."""
        return {
            "section": section,
            "title": title,
            "version": self.version,
            "last_updated": datetime.utcnow().isoformat(),
            "author": self.author,
            "base_url": self.base_url
        }
    
    def get_documentation_index(self) -> Dict[str, Any]:
        """Get documentation index and navigation structure."""
        response = self._create_response_template("index", "API Documentation Index")
        
        response["manpage"] = {
            "name": "Ultra-Secure Media Encoding Server API",
            "synopsis": "Comprehensive API documentation for zero-trust media processing",
            "description": (
                "The Ultra-Secure Media Encoding Server provides a comprehensive REST API "
                "for secure media processing with dual-mode encryption support. This documentation "
                "provides complete endpoint reference, workflow examples, and integration guides."
            ),
            "sections": [
                {
                    "path": "/v1/docs/overview",
                    "title": "System Overview & Quick Start",
                    "description": "Architecture overview and quick start guide"
                },
                {
                    "path": "/v1/docs/modes", 
                    "title": "Dual-Mode Encryption Guide",
                    "description": "Automated vs Manual encryption modes"
                },
                {
                    "path": "/v1/docs/endpoints",
                    "title": "API Endpoints Reference",
                    "description": "Complete endpoint documentation"
                },
                {
                    "path": "/v1/docs/auth",
                    "title": "Authentication Guide", 
                    "description": "JWT tokens and API key management"
                },
                {
                    "path": "/v1/docs/examples",
                    "title": "Workflow Examples",
                    "description": "Complete workflow examples with curl commands"
                },
                {
                    "path": "/v1/docs/errors",
                    "title": "Error Reference",
                    "description": "Error codes and troubleshooting"
                },
                {
                    "path": "/v1/docs/tools",
                    "title": "Client Tools Documentation",
                    "description": "encrypt_media.py and decrypt_media.py usage"
                }
            ],
            "quick_links": {
                "health_check": f"{self.base_url}/health",
                "service_info": f"{self.base_url}/",
                "encoding_presets": f"{self.base_url}/v1/presets",
                "job_submission": f"{self.base_url}/v1/jobs"
            }
        }
        
        return response
    
    def get_system_overview(self) -> Dict[str, Any]:
        """Get system overview and quick start guide."""
        response = self._create_response_template("overview", "System Overview & Quick Start")
        
        response["manpage"] = {
            "name": "System Architecture Overview",
            "synopsis": "Zero-trust media encoding with encrypted virtual memory",
            "description": (
                "The Ultra-Secure Media Encoding Server implements a revolutionary approach to "
                "secure media processing through dual-mode encryption and zero-trust architecture. "
                "The system processes media entirely in RAM (files <4GB) or encrypted virtual swap "
                "(files >4GB) with complete memory isolation and automatic cleanup."
            ),
            "architecture": {
                "security_model": "Zero-trust with encrypted virtual memory",
                "encryption_modes": ["automated", "manual"],
                "memory_system": "RAM-only processing with encrypted swap emulation",
                "container_base": "Alpine Linux (ultra-secure)",
                "api_framework": "FastAPI with comprehensive validation"
            },
            "key_features": [
                "Dual-mode encryption (automated transparency + manual control)",
                "Zero-trust security model with complete memory isolation", 
                "FFmpeg integration with parameter validation and sandboxing",
                "Real-time job processing with async queue management",
                "Comprehensive error handling and security audit trails"
            ],
            "quick_start": {
                "1_health_check": {
                    "description": "Verify service availability",
                    "command": f"curl -X GET {self.base_url}/health",
                    "expected_response": {"status": "healthy"}
                },
                "2_get_presets": {
                    "description": "View available encoding presets",
                    "command": f"curl -X GET {self.base_url}/v1/presets"
                },
                "3_submit_job": {
                    "description": "Submit a simple encoding job",
                    "command": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@input.mp4" \\\n'
                        '  -F "params={\\"video_codec\\":\\"libx264\\",\\"audio_codec\\":\\"aac\\"}" \\\n'
                        '  -F "encryption_mode=automated"'
                    )
                },
                "4_check_status": {
                    "description": "Check job processing status",
                    "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}"
                },
                "5_download_result": {
                    "description": "Download processed media file",
                    "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}/result -o result.mp4"
                }
            }
        }
        
        return response
    
    def get_encryption_modes_guide(self) -> Dict[str, Any]:
        """Get comprehensive dual-mode encryption guide."""
        response = self._create_response_template("modes", "Dual-Mode Encryption Guide")
        
        response["manpage"] = {
            "name": "Dual-Mode Encryption System",
            "synopsis": "Automated transparency vs Manual client control",
            "description": (
                "The system supports two distinct encryption modes designed for different use cases. "
                "Automated mode provides complete encryption transparency to users, while manual mode "
                "offers direct client control over cryptographic operations."
            ),
            "automated_mode": {
                "description": (
                    "Users interact exclusively with unencrypted data while the server handles all "
                    "encryption operations transparently. Upload unencrypted files, receive unencrypted "
                    "results - zero cryptographic complexity for end users."
                ),
                "use_cases": [
                    "Commercial media distribution workflows",
                    "User-friendly applications requiring transparency",
                    "Systems where encryption should be invisible to users"
                ],
                "workflow": {
                    "1": "Upload unencrypted media file",
                    "2": "Server automatically encrypts for processing",
                    "3": "Processing occurs on encrypted data",
                    "4": "Server automatically decrypts result",
                    "5": "Download unencrypted processed file"
                },
                "example": {
                    "command": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@video.mp4" \\\n'
                        '  -F "params={\\"video_codec\\":\\"libx264\\"}" \\\n'
                        '  -F "encryption_mode=automated"'
                    ),
                    "note": "No encryption parameters required - completely transparent"
                }
            },
            "manual_mode": {
                "description": (
                    "Clients manage encryption using provided utilities (encrypt_media.py). "
                    "Upload pre-encrypted files, receive encrypted results for client-side decryption. "
                    "Complete client control over cryptographic operations."
                ),
                "use_cases": [
                    "High-security environments requiring client key management",
                    "Compliance scenarios with specific encryption requirements",
                    "Systems requiring cryptographic audit trails"
                ],
                "workflow": {
                    "1": "Client encrypts media file using encrypt_media.py",
                    "2": "Upload encrypted file with decryption password",
                    "3": "Server decrypts, processes, and re-encrypts",
                    "4": "Download encrypted result",
                    "5": "Client decrypts using decrypt_media.py"
                },
                "example": {
                    "preparation": "python encrypt_media.py input.mp4 encrypted_input.enc mypassword",
                    "submission": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@encrypted_input.enc" \\\n'
                        '  -F "params={\\"video_codec\\":\\"libx264\\"}" \\\n'
                        '  -F "encryption_mode=manual" \\\n'
                        '  -F "decryption_password=mypassword"'
                    ),
                    "retrieval": "python decrypt_media.py encrypted_result.enc output.mp4 mypassword"
                }
            },
            "security_comparison": {
                "automated": {
                    "encryption": "AES-256-GCM with server-managed keys",
                    "key_management": "Server-controlled with secure derivation",
                    "user_complexity": "Zero - completely transparent",
                    "use_case": "Commercial applications, user-friendly systems"
                },
                "manual": {
                    "encryption": "AES-256-GCM with client-provided passwords",
                    "key_management": "Client-controlled with password-based derivation",
                    "user_complexity": "High - requires cryptographic operations",
                    "use_case": "High-security, compliance-driven environments"
                }
            }
        }
        
        return response
    
    def get_endpoints_list(self) -> Dict[str, Any]:
        """Get list of all documented API endpoints."""
        response = self._create_response_template("endpoints", "API Endpoints Reference")
        
        response["manpage"] = {
            "name": "Complete API Endpoints Reference",
            "synopsis": "All available endpoints with detailed specifications",
            "description": (
                "Comprehensive reference for all API endpoints including parameters, "
                "responses, and usage examples. Each endpoint includes complete "
                "documentation with real-world examples."
            ),
            "endpoints": [
                {
                    "id": "root",
                    "path": "/",
                    "method": "GET",
                    "title": "Service Information",
                    "description": "Get service version and feature information"
                },
                {
                    "id": "health",
                    "path": "/health", 
                    "method": "GET",
                    "title": "Health Check",
                    "description": "Service health and system status verification"
                },
                {
                    "id": "presets",
                    "path": "/v1/presets",
                    "method": "GET", 
                    "title": "Encoding Presets",
                    "description": "Available FFmpeg encoding presets and parameters"
                },
                {
                    "id": "keypair",
                    "path": "/v1/encryption/keypair",
                    "method": "POST",
                    "title": "Generate Keypair", 
                    "description": "Generate ECDH keypair for manual encryption mode"
                },
                {
                    "id": "submit_job",
                    "path": "/v1/jobs",
                    "method": "POST",
                    "title": "Submit Processing Job",
                    "description": "Submit media file for processing with encryption mode"
                },
                {
                    "id": "job_status",
                    "path": "/v1/jobs/{job_id}",
                    "method": "GET",
                    "title": "Get Job Status",
                    "description": "Retrieve job processing status and progress"
                },
                {
                    "id": "job_result",
                    "path": "/v1/jobs/{job_id}/result", 
                    "method": "GET",
                    "title": "Download Job Result",
                    "description": "Download processed media file with automatic decryption"
                },
                {
                    "id": "list_jobs",
                    "path": "/v1/jobs",
                    "method": "GET", 
                    "title": "List All Jobs",
                    "description": "List all processing jobs with basic information"
                }
            ],
            "usage": {
                "endpoint_details": f"{self.base_url}/v1/docs/endpoints/{{endpoint_id}}",
                "example": f"{self.base_url}/v1/docs/endpoints/submit_job"
            }
        }
        
        return response
    
    def get_endpoint_documentation(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed documentation for a specific endpoint."""
        endpoints = {
            "root": self._get_root_endpoint_docs(),
            "health": self._get_health_endpoint_docs(),
            "presets": self._get_presets_endpoint_docs(),
            "keypair": self._get_keypair_endpoint_docs(),
            "submit_job": self._get_submit_job_endpoint_docs(),
            "job_status": self._get_job_status_endpoint_docs(),
            "job_result": self._get_job_result_endpoint_docs(),
            "list_jobs": self._get_list_jobs_endpoint_docs()
        }
        
        return endpoints.get(endpoint_id)
    
    def _get_root_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET / endpoint."""
        response = self._create_response_template("endpoint", "Service Information Endpoint")
        
        response["manpage"] = {
            "name": "GET /",
            "synopsis": "Get service version and feature information",
            "description": (
                "Returns basic service information including version, author, security level, "
                "available features, and system capabilities. This endpoint provides a quick "
                "overview of the service configuration and available functionality."
            ),
            "method": "GET",
            "path": "/",
            "authentication": "None required",
            "parameters": [],
            "responses": {
                "200": {
                    "description": "Service information retrieved successfully",
                    "content": {
                        "service": "Ultra-Secure Media Encoding Server",
                        "version": "2.0.0-secure",
                        "author": "Lorenzo Albanese (alblor)",
                        "security_level": "zero-trust",
                        "encryption_modes": ["automated", "manual"],
                        "memory_system": "encrypted-virtual-swap",
                        "api_version": "v1",
                        "features": [
                            "RAM-only processing (<4GB)",
                            "Encrypted swap emulation (>4GB)",
                            "Zero-trace cleanup",
                            "Alpine Linux base",
                            "Maximum container security"
                        ]
                    }
                }
            },
            "examples": [
                {
                    "title": "Get service information",
                    "request": f"curl -X GET {self.base_url}/",
                    "response_preview": {
                        "service": "Ultra-Secure Media Encoding Server",
                        "version": "2.0.0-secure",
                        "author": "Lorenzo Albanese (alblor)"
                    }
                }
            ]
        }
        
        return response
    
    def _get_health_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET /health endpoint."""
        response = self._create_response_template("endpoint", "Health Check Endpoint")
        
        response["manpage"] = {
            "name": "GET /health",
            "synopsis": "Service health and system status verification",
            "description": (
                "Performs comprehensive health check including secure memory system availability, "
                "service components status, and system readiness verification. This endpoint is "
                "essential for monitoring and load balancer health checks."
            ),
            "method": "GET",
            "path": "/health",
            "authentication": "None required",
            "parameters": [],
            "responses": {
                "200": {
                    "description": "Service is healthy and operational",
                    "content": {
                        "status": "healthy",
                        "timestamp": "2025-08-25T12:00:00.000Z",
                        "security_mode": "zero-trust",
                        "memory_system": "available",
                        "services": {
                            "ffmpeg": "available",
                            "encryption": "active", 
                            "secure_memory": "available"
                        }
                    }
                }
            },
            "examples": [
                {
                    "title": "Check service health",
                    "request": f"curl -X GET {self.base_url}/health",
                    "response_preview": {
                        "status": "healthy",
                        "security_mode": "zero-trust"
                    }
                }
            ]
        }
        
        return response
    
    def _get_presets_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET /v1/presets endpoint."""
        response = self._create_response_template("endpoint", "Encoding Presets Endpoint")
        
        response["manpage"] = {
            "name": "GET /v1/presets",
            "synopsis": "Get available FFmpeg encoding presets and parameters",
            "description": (
                "Returns all available encoding presets with their FFmpeg parameters. "
                "These presets provide common encoding configurations for different use cases "
                "including quality optimization and web streaming compatibility."
            ),
            "method": "GET", 
            "path": "/v1/presets",
            "authentication": "None required",
            "parameters": [],
            "responses": {
                "200": {
                    "description": "Encoding presets retrieved successfully",
                    "content": {
                        "presets": {
                            "h264_high_quality": {
                                "description": "H.264 high quality encoding",
                                "video_codec": "libx264",
                                "audio_codec": "aac",
                                "custom_params": ["-preset", "slow", "-crf", "18"]
                            },
                            "h264_web_optimized": {
                                "description": "H.264 optimized for web streaming",
                                "video_codec": "libx264",
                                "audio_codec": "aac", 
                                "custom_params": ["-preset", "fast", "-crf", "23"]
                            },
                            "copy_codecs": {
                                "description": "Copy existing codecs (fastest)",
                                "video_codec": "copy",
                                "audio_codec": "copy"
                            }
                        }
                    }
                }
            },
            "examples": [
                {
                    "title": "Get all encoding presets",
                    "request": f"curl -X GET {self.base_url}/v1/presets",
                    "usage_note": "Use preset parameters in job submission params field"
                }
            ]
        }
        
        return response
    
    def _get_keypair_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for POST /v1/encryption/keypair endpoint."""
        response = self._create_response_template("endpoint", "Generate Keypair Endpoint")
        
        response["manpage"] = {
            "name": "POST /v1/encryption/keypair",
            "synopsis": "Generate ECDH keypair for manual encryption mode",
            "description": (
                "Generates an ECDH P-256 keypair for manual encryption mode. "
                "The keypair can be used with client tools for advanced cryptographic "
                "operations requiring client-controlled key management."
            ),
            "method": "POST",
            "path": "/v1/encryption/keypair",
            "authentication": "None required (Note: Will require API key in production)",
            "parameters": [],
            "responses": {
                "200": {
                    "description": "Keypair generated successfully",
                    "content": {
                        "private_key": "-----BEGIN EC PRIVATE KEY-----\n...",
                        "public_key": "-----BEGIN PUBLIC KEY-----\n...",
                        "algorithm": "ECDH-P256",
                        "created_at": "2025-08-25T12:00:00.000Z"
                    }
                },
                "500": {
                    "description": "Keypair generation failed",
                    "content": {
                        "detail": "Failed to generate keypair"
                    }
                }
            },
            "examples": [
                {
                    "title": "Generate new keypair",
                    "request": f"curl -X POST {self.base_url}/v1/encryption/keypair",
                    "note": "Store private key securely - it cannot be recovered"
                }
            ],
            "security_notes": [
                "Private keys are generated server-side but not stored",
                "Client is responsible for secure private key storage",
                "Used primarily for advanced manual encryption workflows"
            ]
        }
        
        return response
    
    def _get_submit_job_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for POST /v1/jobs endpoint."""
        response = self._create_response_template("endpoint", "Submit Processing Job Endpoint")
        
        response["manpage"] = {
            "name": "POST /v1/jobs",
            "synopsis": "Submit media file for processing with encryption mode selection",
            "description": (
                "Submit a media file for processing with FFmpeg parameters and encryption mode. "
                "Supports both automated mode (transparent encryption) and manual mode "
                "(client-controlled encryption). This is the primary endpoint for job submission."
            ),
            "method": "POST",
            "path": "/v1/jobs",
            "authentication": "None required (Note: Will require API key in production)",
            "content_type": "multipart/form-data",
            "parameters": [
                {
                    "name": "file",
                    "type": "file",
                    "required": True,
                    "description": "Media file to process (unencrypted for automated mode, encrypted for manual mode)"
                },
                {
                    "name": "params",
                    "type": "string (JSON)",
                    "required": True,
                    "description": "FFmpeg parameters as JSON object",
                    "example": '{"video_codec":"libx264","audio_codec":"aac","custom_params":["-crf","23"]}'
                },
                {
                    "name": "encryption_mode", 
                    "type": "string",
                    "required": False,
                    "default": "automated",
                    "values": ["automated", "manual"],
                    "description": "Encryption mode selection"
                },
                {
                    "name": "decryption_password",
                    "type": "string",
                    "required": False,
                    "description": "Required for manual mode - password for encrypted input file"
                }
            ],
            "responses": {
                "200": {
                    "description": "Job submitted successfully",
                    "content": {
                        "job_id": "550e8400-e29b-41d4-a716-446655440000",
                        "status": "queued",
                        "message": "Job submitted for secure processing",
                        "encryption_mode": "automated",
                        "file_size": 1048576,
                        "submitted_at": "2025-08-25T12:00:00.000Z"
                    }
                },
                "400": {
                    "description": "Validation error",
                    "examples": [
                        "Invalid encryption mode",
                        "Manual mode requires decryption_password",
                        "Invalid JSON parameters",
                        "Empty file provided"
                    ]
                }
            },
            "examples": [
                {
                    "title": "Automated Mode - Simple H.264 encoding",
                    "request": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@input.mp4" \\\n'
                        '  -F "params={\\"video_codec\\":\\"libx264\\",\\"audio_codec\\":\\"aac\\"}" \\\n'
                        '  -F "encryption_mode=automated"'
                    ),
                    "description": "Upload unencrypted file, get unencrypted result"
                },
                {
                    "title": "Automated Mode - High quality preset",
                    "request": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@input.mp4" \\\n'
                        '  -F "params={\\"video_codec\\":\\"libx264\\",\\"audio_codec\\":\\"aac\\",\\"custom_params\\":[\\"--preset\\",\\"slow\\",\\"-crf\\",\\"18\\"]}"'
                    ),
                    "description": "High quality encoding with custom FFmpeg parameters"
                },
                {
                    "title": "Manual Mode - Client-encrypted input",
                    "preparation": "python encrypt_media.py input.mp4 encrypted.enc mypassword",
                    "request": (
                        f'curl -X POST {self.base_url}/v1/jobs \\\n'
                        '  -F "file=@encrypted.enc" \\\n'  
                        '  -F "params={\\"video_codec\\":\\"libx264\\"}" \\\n'
                        '  -F "encryption_mode=manual" \\\n'
                        '  -F "decryption_password=mypassword"'
                    ),
                    "description": "Upload pre-encrypted file, get encrypted result"
                }
            ],
            "workflow_notes": [
                "Job processing is asynchronous - use job_id to check status",
                "Files are processed in secure memory with automatic cleanup",
                "Results are available via /v1/jobs/{job_id}/result endpoint"
            ]
        }
        
        return response
    
    def _get_job_status_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET /v1/jobs/{job_id} endpoint."""
        response = self._create_response_template("endpoint", "Get Job Status Endpoint")
        
        response["manpage"] = {
            "name": "GET /v1/jobs/{job_id}",
            "synopsis": "Retrieve job processing status and progress information",
            "description": (
                "Get detailed status information for a specific job including processing progress, "
                "current status, timestamps, and metadata. Use this endpoint to monitor job "
                "processing progress before downloading results."
            ),
            "method": "GET",
            "path": "/v1/jobs/{job_id}",
            "authentication": "None required",
            "parameters": [
                {
                    "name": "job_id",
                    "type": "string (UUID)",
                    "location": "path",
                    "required": True,
                    "description": "Unique job identifier returned from job submission"
                }
            ],
            "responses": {
                "200": {
                    "description": "Job status retrieved successfully",
                    "content": {
                        "job_id": "550e8400-e29b-41d4-a716-446655440000",
                        "status": "completed",
                        "encryption_mode": "automated",
                        "progress": 100,
                        "message": "Processing completed successfully",
                        "submitted_at": "2025-08-25T12:00:00.000Z",
                        "started_at": "2025-08-25T12:00:05.000Z",
                        "completed_at": "2025-08-25T12:01:30.000Z",
                        "file_size": 1048576,
                        "processing_time": 85.5
                    }
                },
                "404": {
                    "description": "Job not found",
                    "content": {
                        "error": {
                            "message": "Job not found",
                            "type": "not_found_error"
                        }
                    }
                }
            },
            "status_values": [
                "queued - Job submitted and waiting for processing",
                "processing - Job currently being processed",
                "completed - Job completed successfully",
                "failed - Job processing failed"
            ],
            "examples": [
                {
                    "title": "Check job status",
                    "request": f"curl -X GET {self.base_url}/v1/jobs/550e8400-e29b-41d4-a716-446655440000",
                    "note": "Monitor status until 'completed' before downloading result"
                },
                {
                    "title": "Monitor processing job",
                    "command": "watch -n 2 'curl -s http://localhost:8000/v1/jobs/JOB_ID | jq .status'",
                    "description": "Monitor job status with automatic refresh every 2 seconds"
                }
            ]
        }
        
        return response
    
    def _get_job_result_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET /v1/jobs/{job_id}/result endpoint.""" 
        response = self._create_response_template("endpoint", "Download Job Result Endpoint")
        
        response["manpage"] = {
            "name": "GET /v1/jobs/{job_id}/result",
            "synopsis": "Download processed media file with automatic decryption",
            "description": (
                "Download the processed media file for a completed job. For automated mode, "
                "the file is automatically decrypted and returned as standard media. For manual "
                "mode, returns encrypted result that must be decrypted client-side."
            ),
            "method": "GET", 
            "path": "/v1/jobs/{job_id}/result",
            "authentication": "None required",
            "parameters": [
                {
                    "name": "job_id",
                    "type": "string (UUID)",
                    "location": "path",
                    "required": True,
                    "description": "Unique job identifier for completed job"
                }
            ],
            "responses": {
                "200": {
                    "description": "Result file download",
                    "content_type": "video/mp4 (or encrypted binary for manual mode)",
                    "headers": {
                        "Content-Disposition": "attachment; filename=result_{job_id}.mp4",
                        "Content-Length": "file_size_in_bytes"
                    }
                },
                "400": {
                    "description": "Job not completed",
                    "content": {
                        "detail": "Job not completed"
                    }
                },
                "404": {
                    "description": "Job or result not found"
                }
            },
            "examples": [
                {
                    "title": "Download result file",
                    "request": f"curl -X GET {self.base_url}/v1/jobs/550e8400-e29b-41d4-a716-446655440000/result -o result.mp4",
                    "description": "Download and save result to local file"
                },
                {
                    "title": "Download with original filename",
                    "request": f'curl -X GET {self.base_url}/v1/jobs/JOB_ID/result -OJ',
                    "description": "Use server-suggested filename from Content-Disposition header"
                },
                {
                    "title": "Manual mode - download encrypted result",
                    "request": f"curl -X GET {self.base_url}/v1/jobs/JOB_ID/result -o encrypted_result.enc",
                    "post_process": "python decrypt_media.py encrypted_result.enc final_result.mp4 mypassword",
                    "description": "Manual mode requires client-side decryption"
                }
            ],
            "workflow_notes": [
                "Only available for jobs with status 'completed'",
                "Automated mode returns ready-to-use media files",
                "Manual mode returns encrypted files requiring decrypt_media.py",
                "Results are automatically cleaned up after download"
            ]
        }
        
        return response
    
    def _get_list_jobs_endpoint_docs(self) -> Dict[str, Any]:
        """Documentation for GET /v1/jobs endpoint."""
        response = self._create_response_template("endpoint", "List All Jobs Endpoint")
        
        response["manpage"] = {
            "name": "GET /v1/jobs",
            "synopsis": "List all processing jobs with basic information",
            "description": (
                "Retrieve a list of all jobs with their basic status information. "
                "Useful for job management, monitoring, and administrative tasks. "
                "Returns summary information without detailed processing data."
            ),
            "method": "GET",
            "path": "/v1/jobs", 
            "authentication": "None required",
            "parameters": [],
            "responses": {
                "200": {
                    "description": "Jobs list retrieved successfully",
                    "content": {
                        "jobs": [
                            {
                                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                                "status": "completed",
                                "encryption_mode": "automated",
                                "submitted_at": "2025-08-25T12:00:00.000Z",
                                "file_size": 1048576
                            },
                            {
                                "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                                "status": "processing", 
                                "encryption_mode": "manual",
                                "submitted_at": "2025-08-25T12:05:00.000Z",
                                "file_size": 2097152
                            }
                        ],
                        "total_jobs": 2
                    }
                }
            },
            "examples": [
                {
                    "title": "List all jobs",
                    "request": f"curl -X GET {self.base_url}/v1/jobs",
                    "description": "Get overview of all processing jobs"
                },
                {
                    "title": "Filter completed jobs",
                    "request": f"curl -X GET {self.base_url}/v1/jobs | jq '.jobs[] | select(.status==\"completed\")'",
                    "description": "Use jq to filter jobs by status"
                }
            ],
            "usage_notes": [
                "Use individual job status endpoint for detailed information",
                "Job list includes both active and completed jobs",
                "Completed jobs remain available until automatic cleanup"
            ]
        }
        
        return response
    
    def get_authentication_guide(self) -> Dict[str, Any]:
        """Get authentication and API key management guide."""
        response = self._create_response_template("auth", "Authentication Guide")
        
        response["manpage"] = {
            "name": "Authentication and API Key Management",
            "synopsis": "JWT tokens and API key authentication system",
            "description": (
                "The system supports JWT token authentication and API key management for "
                "secure access control. Currently in development mode with no authentication "
                "required, but production deployment will enforce authentication for all endpoints."
            ),
            "current_status": {
                "development_mode": "No authentication required for testing",
                "production_ready": "JWT and API key infrastructure implemented",
                "note": "Authentication will be enforced in production deployment"
            },
            "authentication_methods": {
                "jwt_tokens": {
                    "description": "JSON Web Tokens for session-based authentication",
                    "use_case": "Web applications and user sessions",
                    "implementation": "RS256 signing with configurable expiration",
                    "header": "Authorization: Bearer <jwt_token>"
                },
                "api_keys": {
                    "description": "API keys for service-to-service communication",
                    "use_case": "Automated systems and service integration", 
                    "implementation": "Credit-based usage tracking with RBAC",
                    "header": "X-API-Key: <api_key>"
                }
            },
            "future_endpoints": [
                "POST /v1/auth/register - User registration",
                "POST /v1/auth/login - User authentication", 
                "POST /v1/auth/refresh - Token refresh",
                "GET /v1/auth/profile - User profile",
                "POST /v1/keys - Generate API key",
                "GET /v1/keys - List API keys",
                "DELETE /v1/keys/{key_id} - Revoke API key"
            ],
            "security_features": {
                "rbac": "Role-based access control for different user types",
                "credits": "Usage tracking and quota enforcement",
                "audit": "Security audit trail for all authenticated operations",
                "rotation": "Key rotation and security policy enforcement"
            },
            "development_testing": {
                "note": "All endpoints currently accessible without authentication",
                "testing": "Focus on functionality without authentication complexity",
                "production": "Authentication will be enforced before production deployment"
            }
        }
        
        return response
    
    def get_workflow_examples(self) -> Dict[str, Any]:
        """Get comprehensive workflow examples with curl commands."""
        response = self._create_response_template("examples", "Complete Workflow Examples")
        
        response["manpage"] = {
            "name": "Complete Workflow Examples",
            "synopsis": "Real-world usage scenarios with curl commands",
            "description": (
                "Comprehensive examples demonstrating complete workflows for both encryption modes. "
                "Each example includes step-by-step commands, expected responses, and troubleshooting tips."
            ),
            "workflows": {
                "automated_basic": {
                    "title": "Basic Automated Mode Workflow",
                    "description": "Simple H.264 encoding with automated encryption",
                    "use_case": "Standard video conversion for web streaming",
                    "steps": [
                        {
                            "step": 1,
                            "action": "Check service health",
                            "command": f"curl -X GET {self.base_url}/health",
                            "expected": {"status": "healthy"}
                        },
                        {
                            "step": 2,
                            "action": "Submit encoding job",
                            "command": (
                                f'curl -X POST {self.base_url}/v1/jobs \\\n'
                                '  -F "file=@input.mp4" \\\n'
                                '  -F "params={\\"video_codec\\":\\"libx264\\",\\"audio_codec\\":\\"aac\\"}" \\\n'
                                '  -F "encryption_mode=automated"'
                            ),
                            "expected": {"status": "queued", "job_id": "uuid"}
                        },
                        {
                            "step": 3,
                            "action": "Monitor job status",
                            "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}",
                            "wait_for": {"status": "completed"}
                        },
                        {
                            "step": 4,
                            "action": "Download result",
                            "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}/result -o output.mp4",
                            "result": "Unencrypted MP4 file ready for use"
                        }
                    ],
                    "total_time": "Typically 1-3 minutes depending on file size",
                    "encryption": "Completely transparent to user"
                },
                "automated_advanced": {
                    "title": "Advanced Automated Mode with Custom Parameters",
                    "description": "High-quality encoding with custom FFmpeg parameters",
                    "use_case": "Professional video processing with quality control",
                    "steps": [
                        {
                            "step": 1,
                            "action": "Get available presets",
                            "command": f"curl -X GET {self.base_url}/v1/presets",
                            "note": "Review presets or create custom parameters"
                        },
                        {
                            "step": 2,
                            "action": "Submit with custom parameters",
                            "command": (
                                f'curl -X POST {self.base_url}/v1/jobs \\\n'
                                '  -F "file=@high_quality_input.mp4" \\\n'
                                '  -F "params={\\"video_codec\\":\\"libx264\\",\\"audio_codec\\":\\"aac\\",\\"custom_params\\":[\\"--preset\\",\\"slow\\",\\"-crf\\",\\"18\\",\\"-profile:v\\",\\"high\\"]}"'
                            ),
                            "note": "High quality preset with custom profile"
                        },
                        {
                            "step": 3,
                            "action": "Monitor with detailed status",
                            "command": f"watch -n 5 'curl -s {self.base_url}/v1/jobs/{{job_id}} | jq'",
                            "note": "Watch command for real-time monitoring"
                        }
                    ]
                },
                "manual_complete": {
                    "title": "Complete Manual Mode Workflow",
                    "description": "Client-controlled encryption with manual mode",
                    "use_case": "High-security environments requiring client key management",
                    "preparation": {
                        "title": "Client-side encryption setup",
                        "steps": [
                            "Ensure Python client tools are available",
                            "Verify encrypt_media.py and decrypt_media.py in client-tools/",
                            "Choose strong encryption password"
                        ]
                    },
                    "steps": [
                        {
                            "step": 1,
                            "action": "Encrypt input file",
                            "command": "python client-tools/encrypt_media.py input.mp4 encrypted_input.enc strongpassword123",
                            "result": "encrypted_input.enc file created"
                        },
                        {
                            "step": 2,
                            "action": "Submit encrypted job",
                            "command": (
                                f'curl -X POST {self.base_url}/v1/jobs \\\n'
                                '  -F "file=@encrypted_input.enc" \\\n'
                                '  -F "params={\\"video_codec\\":\\"libx264\\"}" \\\n'
                                '  -F "encryption_mode=manual" \\\n'
                                '  -F "decryption_password=strongpassword123"'
                            )
                        },
                        {
                            "step": 3,
                            "action": "Monitor job progress",
                            "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}"
                        },
                        {
                            "step": 4,
                            "action": "Download encrypted result",
                            "command": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}/result -o encrypted_result.enc"
                        },
                        {
                            "step": 5,
                            "action": "Decrypt final result",
                            "command": "python client-tools/decrypt_media.py encrypted_result.enc final_output.mp4 strongpassword123",
                            "result": "final_output.mp4 ready for use"
                        }
                    ],
                    "security_notes": [
                        "Server never stores client passwords or decrypted data",
                        "All encryption/decryption operations use client-controlled keys",
                        "Ideal for compliance and high-security requirements"
                    ]
                },
                "batch_processing": {
                    "title": "Batch Processing Multiple Files",
                    "description": "Process multiple files efficiently",
                    "bash_script": f'''#!/bin/bash
# Batch processing script
for file in *.mp4; do
    echo "Processing: $file"
    response=$(curl -s -X POST {self.base_url}/v1/jobs \\
        -F "file=@$file" \\
        -F "params={{\\"video_codec\\":\\"libx264\\"}}" \\
        -F "encryption_mode=automated")
    
    job_id=$(echo $response | jq -r '.job_id')
    echo "Job ID: $job_id"
    
    # Wait for completion
    while true; do
        status=$(curl -s {self.base_url}/v1/jobs/$job_id | jq -r '.status')
        echo "Status: $status"
        if [ "$status" = "completed" ]; then
            break
        fi
        sleep 10
    done
    
    # Download result
    curl -X GET {self.base_url}/v1/jobs/$job_id/result -o "processed_$file"
    echo "Completed: processed_$file"
done''',
                    "usage": "Save as batch_process.sh and run: chmod +x batch_process.sh && ./batch_process.sh"
                }
            },
            "troubleshooting": {
                "common_errors": [
                    "400 - Invalid encryption mode: Check encryption_mode parameter",
                    "400 - Manual mode requires password: Add decryption_password parameter",
                    "404 - Job not found: Verify job_id is correct",
                    "400 - Job not completed: Wait for processing before downloading result"
                ],
                "monitoring": f"Use {self.base_url}/health to verify service availability",
                "debugging": "Enable DEBUG mode for detailed error information"
            }
        }
        
        return response
    
    def get_error_reference(self) -> Dict[str, Any]:
        """Get comprehensive error reference and troubleshooting guide."""
        response = self._create_response_template("errors", "Error Reference & Troubleshooting")
        
        response["manpage"] = {
            "name": "Error Reference and Troubleshooting Guide",
            "synopsis": "Complete error codes, causes, and solutions",
            "description": (
                "Comprehensive reference for all API error responses including HTTP status codes, "
                "error types, common causes, and resolution steps. Essential for debugging "
                "and troubleshooting integration issues."
            ),
            "error_format": {
                "structure": {
                    "error": {
                        "message": "Human-readable error description",
                        "type": "error_category_type",
                        "timestamp": "ISO-8601 timestamp"
                    }
                },
                "example": {
                    "error": {
                        "message": "Invalid encryption mode. Must be 'automated' or 'manual'.",
                        "type": "validation_error",
                        "timestamp": "2025-08-25T12:00:00.000Z"
                    }
                }
            },
            "http_status_codes": {
                "400": {
                    "title": "Bad Request",
                    "description": "Request validation failed or invalid parameters",
                    "common_causes": [
                        "Invalid encryption mode",
                        "Missing required parameters",
                        "Invalid JSON format",
                        "Empty file upload"
                    ],
                    "resolution": "Verify request parameters and format"
                },
                "404": {
                    "title": "Not Found", 
                    "description": "Requested resource not found",
                    "common_causes": [
                        "Job ID not found",
                        "Result not available",
                        "Invalid endpoint path"
                    ],
                    "resolution": "Verify resource identifiers and endpoint paths"
                },
                "500": {
                    "title": "Internal Server Error",
                    "description": "Server processing error",
                    "common_causes": [
                        "FFmpeg processing failure",
                        "Encryption system error",
                        "Memory system unavailable"
                    ],
                    "resolution": "Check service health and retry request"
                }
            },
            "error_types": {
                "validation_error": {
                    "description": "Request parameter validation failed",
                    "examples": [
                        "Invalid encryption mode",
                        "Missing decryption password for manual mode",
                        "Invalid JSON parameters format"
                    ],
                    "resolution": "Review API documentation for correct parameter format"
                },
                "not_found_error": {
                    "description": "Requested resource not found",
                    "examples": [
                        "Job not found",
                        "Result not available"
                    ],
                    "resolution": "Verify job ID and ensure job is completed"
                },
                "processing_error": {
                    "description": "Media processing or system error",
                    "examples": [
                        "FFmpeg processing failed",
                        "File format not supported",
                        "Insufficient system resources"
                    ],
                    "resolution": "Check file format and system status"
                },
                "internal_error": {
                    "description": "Unhandled server error",
                    "resolution": "Check service health and contact support if persistent"
                }
            },
            "common_scenarios": [
                {
                    "problem": "Job submission fails with 'Invalid encryption mode'",
                    "cause": "encryption_mode parameter not set to 'automated' or 'manual'",
                    "solution": 'Set encryption_mode to either "automated" or "manual"',
                    "example": '-F "encryption_mode=automated"'
                },
                {
                    "problem": "Manual mode submission fails with 'requires decryption_password'",
                    "cause": "Manual mode requires decryption_password parameter",
                    "solution": "Add decryption_password parameter for manual mode",
                    "example": '-F "decryption_password=mypassword"'
                },
                {
                    "problem": "Result download returns 400 'Job not completed'",
                    "cause": "Attempting to download result before processing completes",
                    "solution": "Check job status until status is 'completed'",
                    "example": f"curl -X GET {self.base_url}/v1/jobs/{{job_id}}"
                },
                {
                    "problem": "Service returns 500 errors consistently", 
                    "cause": "System health issue or resource constraint",
                    "solution": "Check health endpoint and restart if necessary",
                    "example": f"curl -X GET {self.base_url}/health"
                }
            ],
            "debugging_steps": [
                "1. Check service health: GET /health",
                "2. Verify request format matches documentation",
                "3. Ensure file is valid media format",
                "4. Check job status before downloading result",
                "5. Review server logs for detailed error information"
            ],
            "support_information": {
                "health_check": f"{self.base_url}/health",
                "service_info": f"{self.base_url}/",
                "documentation": f"{self.base_url}/v1/docs",
                "author": "Lorenzo Albanese (alblor)",
                "debug_mode": "Set DEBUG=true for detailed error messages"
            }
        }
        
        return response
    
    def get_client_tools_documentation(self) -> Dict[str, Any]:
        """Get comprehensive client tools documentation."""
        response = self._create_response_template("tools", "Client Tools Documentation")
        
        response["manpage"] = {
            "name": "Client Tools Documentation",
            "synopsis": "encrypt_media.py and decrypt_media.py usage guide",
            "description": (
                "Comprehensive guide for client-side encryption tools used with manual mode. "
                "These tools provide client-controlled encryption for high-security workflows "
                "requiring cryptographic operations outside server control."
            ),
            "tools_location": "client-tools/ directory in project root",
            "tools_overview": {
                "encrypt_media.py": {
                    "purpose": "Encrypt media files for manual mode submission",
                    "algorithm": "AES-256-GCM with password-based key derivation",
                    "output": "Encrypted .enc file compatible with server",
                    "usage": "python encrypt_media.py input.mp4 output.enc password"
                },
                "decrypt_media.py": {
                    "purpose": "Decrypt server results from manual mode",
                    "algorithm": "AES-256-GCM with password-based key derivation",
                    "output": "Original media file format",
                    "usage": "python decrypt_media.py encrypted.enc output.mp4 password"
                }
            },
            "installation": {
                "requirements": [
                    "Python 3.8+",
                    "cryptography library",
                    "argparse (built-in)"
                ],
                "setup": [
                    "cd client-tools/",
                    "pip install -r requirements.txt",
                    "Verify tools: python encrypt_media.py --help"
                ]
            },
            "encrypt_media_py": {
                "synopsis": "python encrypt_media.py <input_file> <output_file> <password>",
                "description": (
                    "Encrypts media files using AES-256-GCM with password-based key derivation. "
                    "Creates encrypted files compatible with the server's manual mode processing."
                ),
                "parameters": [
                    {
                        "name": "input_file",
                        "type": "string",
                        "required": True,
                        "description": "Path to media file to encrypt"
                    },
                    {
                        "name": "output_file", 
                        "type": "string",
                        "required": True,
                        "description": "Path for encrypted output file (.enc extension recommended)"
                    },
                    {
                        "name": "password",
                        "type": "string", 
                        "required": True,
                        "description": "Encryption password (minimum 8 characters recommended)"
                    }
                ],
                "examples": [
                    {
                        "title": "Basic file encryption",
                        "command": "python encrypt_media.py video.mp4 video_encrypted.enc mypassword123",
                        "result": "Creates video_encrypted.enc file ready for server submission"
                    },
                    {
                        "title": "Batch encryption script",
                        "command": '''for file in *.mp4; do
    python encrypt_media.py "$file" "${file%.mp4}_encrypted.enc" mypassword
done''',
                        "description": "Encrypt all MP4 files in directory"
                    }
                ],
                "security_notes": [
                    "Use strong passwords (12+ characters with mixed case, numbers, symbols)",
                    "Store passwords securely - they cannot be recovered if lost",
                    "Same password required for decryption"
                ]
            },
            "decrypt_media_py": {
                "synopsis": "python decrypt_media.py <encrypted_file> <output_file> <password>",
                "description": (
                    "Decrypts files encrypted by encrypt_media.py or returned from server manual mode. "
                    "Uses the same password provided during encryption."
                ),
                "parameters": [
                    {
                        "name": "encrypted_file",
                        "type": "string",
                        "required": True,
                        "description": "Path to encrypted file (.enc)"
                    },
                    {
                        "name": "output_file",
                        "type": "string",
                        "required": True,
                        "description": "Path for decrypted media file"
                    },
                    {
                        "name": "password",
                        "type": "string",
                        "required": True,
                        "description": "Same password used for encryption"
                    }
                ],
                "examples": [
                    {
                        "title": "Decrypt server result",
                        "command": "python decrypt_media.py server_result.enc final_video.mp4 mypassword123",
                        "result": "Creates final_video.mp4 ready for use"
                    },
                    {
                        "title": "Verify decryption success",
                        "command": "python decrypt_media.py test.enc verify.mp4 password && ffplay verify.mp4",
                        "description": "Decrypt and immediately play to verify success"
                    }
                ]
            },
            "manual_mode_workflow": {
                "title": "Complete Manual Mode Workflow with Client Tools",
                "steps": [
                    {
                        "step": 1,
                        "tool": "encrypt_media.py",
                        "action": "python encrypt_media.py input.mp4 encrypted.enc password123",
                        "result": "encrypted.enc file created"
                    },
                    {
                        "step": 2,
                        "tool": "curl (server submission)",
                        "action": (
                            f'curl -X POST {self.base_url}/v1/jobs \\\n'
                            '  -F "file=@encrypted.enc" \\\n'
                            '  -F "encryption_mode=manual" \\\n'
                            '  -F "decryption_password=password123"'
                        ),
                        "result": "Job submitted, job_id returned"
                    },
                    {
                        "step": 3,
                        "tool": "curl (result download)",
                        "action": f"curl -X GET {self.base_url}/v1/jobs/JOB_ID/result -o server_result.enc",
                        "result": "Encrypted result downloaded"
                    },
                    {
                        "step": 4,
                        "tool": "decrypt_media.py",
                        "action": "python decrypt_media.py server_result.enc final_output.mp4 password123",
                        "result": "final_output.mp4 ready for use"
                    }
                ],
                "total_encryption_control": "Client controls all encryption/decryption operations"
            },
            "troubleshooting": {
                "common_issues": [
                    {
                        "problem": "ImportError: No module named 'cryptography'",
                        "solution": "pip install cryptography"
                    },
                    {
                        "problem": "Decryption fails with 'Invalid password'",
                        "solution": "Verify exact same password used for encryption"
                    },
                    {
                        "problem": "File not found error",
                        "solution": "Verify file paths are correct and files exist"
                    }
                ],
                "validation": {
                    "encrypt_test": "python encrypt_media.py test.mp4 test.enc password && python decrypt_media.py test.enc verify.mp4 password",
                    "result_verification": "Compare original and decrypted file sizes/checksums"
                }
            },
            "security_best_practices": [
                "Use unique, strong passwords for each encryption operation",
                "Store passwords in secure password managers",
                "Regularly rotate encryption passwords for sensitive data",
                "Verify decrypted files before deleting encrypted versions",
                "Use manual mode for compliance and high-security requirements"
            ]
        }
        
        return response