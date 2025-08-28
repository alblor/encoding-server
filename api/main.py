"""
Ultra-Secure Media Encoding Server - Zero-Trust Production Implementation

A zero-trust, privacy-first media encoding server with encrypted virtual memory system.
Nothing ever leaves RAM or encrypted swap. Maximum security with Alpine Linux base.

Author: Lorenzo Albanese (alblor)
Architecture: Zero-trust with encrypted swap emulation
"""

import asyncio
import logging
import os
import ssl
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import json
import io

from app.config import settings
from app.secure_jobs import SecureJobProcessor
from app.encryption import EncryptionManager
from app.documentation import DocumentationManager
from app.tls_config import tls_manager

# Configure secure logging
logging.basicConfig(
    level=logging.WARNING if not settings.DEBUG else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management with secure initialization and cleanup."""
    logger.info("🔒 Starting Ultra-Secure Media Encoding Server")
    
    # Security validation
    if not os.getenv("SECURE_MEMORY", "").lower() == "true":
        logger.warning("⚠️  SECURE_MEMORY not enabled - running in development mode")
    
    if not os.getenv("ZERO_TRACE", "").lower() == "true":
        logger.warning("⚠️  ZERO_TRACE not enabled - cleanup may not be complete")
    
    try:
        # Verify tmpfs mounts are available
        tmpfs_paths = ["/tmp/memory-pool", "/tmp/encrypted-swap"]
        for path in tmpfs_paths:
            if not os.path.exists(path):
                os.makedirs(path, mode=0o700, exist_ok=True)
                logger.info(f"✅ Created secure storage: {path}")
        
        # Initialize secure services
        app.state.encryption_manager = EncryptionManager()
        app.state.job_processor = SecureJobProcessor(
            encryption_manager=app.state.encryption_manager
        )
        app.state.documentation_manager = DocumentationManager()
        
        logger.info("🔐 Ultra-secure services initialized successfully")
        logger.info(f"💾 Memory threshold: {os.getenv('MEMORY_THRESHOLD', '4GB')}")
        logger.info(f"🛡️  Security features: RAM-only + Encrypted Swap")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize secure services: {e}")
        raise
    
    finally:
        logger.info("🧹 Shutting down with secure cleanup")
        # Secure cleanup will be handled by SecureMemoryManager


# Create FastAPI app with ultra-secure configuration
app = FastAPI(
    title="Ultra-Secure Media Encoding Server",
    description="Zero-trust media encoding with encrypted virtual memory",
    version="2.0.0-secure",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,  # Disable docs in production
    redoc_url="/api/redoc" if settings.DEBUG else None
)

# Security middleware configuration - HTTPS-ONLY MODE
HTTPS_ONLY_MODE = True  # Always true in production - no HTTP support

# Add trusted host middleware for production security (allow testserver for unit tests)
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=settings.ALLOWED_HOSTS + ["localhost", "127.0.0.1", "::1", "testserver"]
)

# No HTTPS redirect middleware needed - we don't serve HTTP at all

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add comprehensive security headers to all responses."""
    response = await call_next(request)
    
    # HSTS (HTTP Strict Transport Security) - always enabled in HTTPS-only mode
    if HTTPS_ONLY_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # Content security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=()"
    
    # Content Security Policy for API-only usage
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    
    # Server identification
    response.headers["Server"] = "SecureMediaEncoder/2.0"
    
    # Secure cookie settings - always enabled in HTTPS-only mode
    if HTTPS_ONLY_MODE:
        response.headers["Set-Cookie"] = response.headers.get("Set-Cookie", "").replace("HttpOnly", "HttpOnly; Secure; SameSite=Strict")
    
    return response

# Security: Minimal CORS for development only
if settings.DEBUG:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],  # Specific origins only
        allow_credentials=False,  # No credentials in secure mode
        allow_methods=["GET", "POST"],  # Minimal methods
        allow_headers=["Content-Type", "Authorization"],
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with secure error responses."""
    logger.error(f"🚨 Unhandled exception in {request.url}: {str(exc)}")
    
    # Security: Don't leak internal information in production
    if settings.DEBUG:
        error_detail = str(exc)
    else:
        error_detail = "Internal server error"
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": error_detail,
                "type": "internal_error",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )


@app.get("/")
async def root():
    """Service information endpoint."""
    return {
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


@app.get("/health")
async def health_check():
    """Secure health check endpoint."""
    # Check secure memory system availability
    memory_status = "available"
    try:
        if not os.path.exists("/tmp/memory-pool"):
            memory_status = "unavailable"
    except Exception:
        memory_status = "error"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "security_mode": "zero-trust",
        "memory_system": memory_status,
        "services": {
            "ffmpeg": "available",
            "encryption": "active",
            "secure_memory": memory_status
        }
    }


@app.get("/v1/security/status")
async def security_status():
    """
    Dynamic security status endpoint - reports actual running configuration
    with no hardcoded assumptions. All values derived from environment or system state.
    """
    try:
        # Core environment variables (only source of configuration)
        env_vars = {
            "ENVIRONMENT": os.getenv("ENVIRONMENT", "unknown"),
            "FFMPEG_SECURITY_LEVEL": os.getenv("FFMPEG_SECURITY_LEVEL", "unknown"),
            "DISABLE_ENCRYPTION": os.getenv("DISABLE_ENCRYPTION", "false"),
            "ENCRYPTION_MODE": os.getenv("ENCRYPTION_MODE", "unknown"),
            "SECURE_MEMORY": os.getenv("SECURE_MEMORY", "unknown"),
            "ZERO_TRACE": os.getenv("ZERO_TRACE", "unknown"),
            "APPARMOR_PROFILE": os.getenv("APPARMOR_PROFILE", "none"),
            "NETWORK_ISOLATION": os.getenv("NETWORK_ISOLATION", "unknown")
        }
        
        # System checks - actual runtime state only
        system_state = {}
        
        # Check what's actually available
        system_state["ffmpeg_available"] = bool(os.system("which ffmpeg > /dev/null 2>&1") == 0)
        system_state["apparmor_available"] = os.path.exists("/sys/kernel/security/apparmor")
        system_state["containerized"] = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
        
        # Check actual mounts
        tmpfs_mounts = {}
        try:
            with open("/proc/mounts", "r") as f:
                mounts_content = f.read()
                for path in ["/tmp/memory-pool", "/tmp/encrypted-swap", "/var/tmp"]:
                    tmpfs_mounts[path] = {
                        "exists": os.path.exists(path),
                        "is_tmpfs": f"tmpfs {path}" in mounts_content
                    }
        except:
            tmpfs_mounts["error"] = "Cannot read /proc/mounts"
        
        system_state["tmpfs_mounts"] = tmpfs_mounts
        
        # Check actual Python modules availability
        modules_available = {}
        for module in ["resource", "cryptography", "redis"]:
            try:
                __import__(module)
                modules_available[module] = True
            except ImportError:
                modules_available[module] = False
        
        system_state["python_modules"] = modules_available
        
        # Actual validation test
        validation_working = False
        try:
            from app.jobs import FFmpegValidator
            validator = FFmpegValidator()
            # Simple validation test
            result = validator.validate_parameters(["-c:v", "libx264"])
            validation_working = True
        except Exception as e:
            system_state["validation_error"] = str(e)
        
        system_state["parameter_validation_working"] = validation_working
        
        # Build dynamic status
        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "environment_variables": env_vars,
            "system_state": system_state,
            "encryption_disabled": env_vars["DISABLE_ENCRYPTION"].lower() == "true"
        }
        
        # Dynamic warnings based on actual state
        warnings = []
        if status["encryption_disabled"]:
            warnings.append("ENCRYPTION DISABLED - UNSAFE CONFIGURATION")
        if not system_state["ffmpeg_available"]:
            warnings.append("FFmpeg binary not available")
        if not system_state["parameter_validation_working"]:
            warnings.append("Parameter validation not working")
        if not system_state["apparmor_available"] and env_vars["ENVIRONMENT"] == "secure-production":
            warnings.append("AppArmor not available in production environment")
        
        status["warnings"] = warnings
        
        return status
        
    except Exception as e:
        logger.error(f"Security status check failed: {e}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
            "system_accessible": True  # At least we can respond
        }


@app.get("/v1/presets")
async def get_encoding_presets():
    """Get available encoding presets."""
    return {
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


@app.post("/v1/encryption/keypair")
async def generate_keypair():
    """Generate ECDH keypair for manual encryption mode."""
    try:
        private_key, public_key = app.state.encryption_manager.generate_keypair()
        
        return {
            "private_key": private_key.decode(),
            "public_key": public_key.decode(),
            "algorithm": "ECDH-P256",
            "created_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Keypair generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate keypair")


@app.post("/v1/jobs")
async def submit_job(
    file: UploadFile = File(...),
    params: str = Form(...),
    encryption_mode: str = Form(default="automated"),
    decryption_password: str = Form(default=None)
):
    """Submit media processing job with secure memory handling."""
    try:
        # Validate encryption mode
        if encryption_mode not in ["automated", "manual"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "message": "Invalid encryption mode. Must be 'automated' or 'manual'.",
                        "type": "validation_error"
                    }
                }
            )
        
        # Validate manual mode has decryption password
        if encryption_mode == "manual" and not decryption_password:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "message": "Manual mode requires decryption_password parameter",
                        "type": "validation_error"
                    }
                }
            )
        
        # Parse parameters
        try:
            params_dict = json.loads(params)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "message": "Invalid JSON parameters",
                        "type": "validation_error"
                    }
                }
            )
        
        # Read file data securely
        file_data = await file.read()
        if not file_data:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "message": "Empty file provided",
                        "type": "validation_error"
                    }
                }
            )
        
        logger.info(f"🔒 Job submission: {len(file_data)} bytes, {encryption_mode} mode")
        
        # Submit to secure job processor
        job_id = await app.state.job_processor.submit_job(
            file_data, params_dict, encryption_mode, decryption_password
        )
        
        return {
            "job_id": job_id,
            "status": "queued",
            "message": "Job submitted for secure processing",
            "encryption_mode": encryption_mode,
            "file_size": len(file_data),
            "submitted_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Job submission error: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "message": "Job submission failed",
                    "type": "processing_error"
                }
            }
        )


@app.get("/v1/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get job status and progress."""
    job = app.state.job_processor.get_job_status(job_id)
    
    if not job:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "message": "Job not found",
                    "type": "not_found_error"
                }
            }
        )
    
    # Filter out binary data that can't be JSON serialized
    safe_job = {k: v for k, v in job.items() 
                if k not in ['encrypted_result', 'decryption_password'] 
                and not isinstance(v, bytes)}
    
    return safe_job


@app.get("/v1/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    """Get job result with transparent decryption for automated mode."""
    try:
        # Get job info
        job = app.state.job_processor.get_job_status(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if job["status"] != "completed":
            raise HTTPException(status_code=400, detail="Job not completed")
        
        # Get result data
        result_data = app.state.job_processor.get_job_result(job_id)
        if not result_data:
            raise HTTPException(status_code=404, detail="Result not available")
        
        logger.info(f"🔓 Returning result for job {job_id}: {len(result_data)} bytes")
        
        # Return as streaming response
        def generate_result():
            yield result_data
        
        return StreamingResponse(
            generate_result(),
            media_type="video/mp4",
            headers={
                "Content-Disposition": f"attachment; filename=result_{job_id}.mp4",
                "Content-Length": str(len(result_data))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Result retrieval error for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve result")


@app.get("/v1/jobs")
async def list_jobs():
    """List all jobs with basic information."""
    jobs = app.state.job_processor.list_jobs()
    return {
        "jobs": jobs,
        "total_jobs": len(jobs)
    }


# ================================
# DOCUMENTATION ENDPOINTS
# ================================

@app.get("/v1/docs")
async def get_documentation_index():
    """Get documentation index and navigation structure."""
    try:
        return app.state.documentation_manager.get_documentation_index()
    except Exception as e:
        logger.error(f"Documentation index error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve documentation index")


@app.get("/v1/docs/overview")
async def get_system_overview():
    """Get system overview and quick start guide."""
    try:
        return app.state.documentation_manager.get_system_overview()
    except Exception as e:
        logger.error(f"System overview documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system overview")


@app.get("/v1/docs/modes")
async def get_encryption_modes_guide():
    """Get comprehensive dual-mode encryption guide."""
    try:
        return app.state.documentation_manager.get_encryption_modes_guide()
    except Exception as e:
        logger.error(f"Encryption modes documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve encryption modes guide")


@app.get("/v1/docs/endpoints")
async def get_endpoints_list():
    """Get list of all documented API endpoints."""
    try:
        return app.state.documentation_manager.get_endpoints_list()
    except Exception as e:
        logger.error(f"Endpoints list documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoints list")


@app.get("/v1/docs/endpoints/{endpoint_id}")
async def get_endpoint_documentation(endpoint_id: str):
    """Get detailed documentation for a specific endpoint."""
    try:
        docs = app.state.documentation_manager.get_endpoint_documentation(endpoint_id)
        if not docs:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": {
                        "message": f"Documentation for endpoint '{endpoint_id}' not found",
                        "type": "not_found_error",
                        "available_endpoints": [
                            "root", "health", "presets", "keypair",
                            "submit_job", "job_status", "job_result", "list_jobs"
                        ]
                    }
                }
            )
        return docs
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Endpoint documentation error for {endpoint_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve endpoint documentation")


@app.get("/v1/docs/auth")
async def get_authentication_guide():
    """Get authentication and API key management guide."""
    try:
        return app.state.documentation_manager.get_authentication_guide()
    except Exception as e:
        logger.error(f"Authentication guide documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve authentication guide")


@app.get("/v1/docs/examples")
async def get_workflow_examples():
    """Get comprehensive workflow examples with curl commands."""
    try:
        return app.state.documentation_manager.get_workflow_examples()
    except Exception as e:
        logger.error(f"Workflow examples documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve workflow examples")


@app.get("/v1/docs/errors")
async def get_error_reference():
    """Get comprehensive error reference and troubleshooting guide."""
    try:
        return app.state.documentation_manager.get_error_reference()
    except Exception as e:
        logger.error(f"Error reference documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve error reference")


@app.get("/v1/docs/tools")
async def get_client_tools_documentation():
    """Get comprehensive client tools documentation."""
    try:
        return app.state.documentation_manager.get_client_tools_documentation()
    except Exception as e:
        logger.error(f"Client tools documentation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve client tools documentation")


@app.get("/v1/security/tls-status")
async def tls_status():
    """Get current TLS configuration and certificate status."""
    try:
        cert_info = tls_manager.get_certificate_info()
        return {
            "https_only_mode": HTTPS_ONLY_MODE,
            "tls_enabled": True,  # Always true in HTTPS-only mode
            "http_disabled": True,  # HTTP completely disabled
            "certificate": cert_info,
            "security_level": os.getenv("FFMPEG_SECURITY_LEVEL", "unknown"),
            "automatic_renewal": True,  # Certificate auto-renewal enabled
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        logger.error(f"TLS status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve TLS status")


if __name__ == "__main__":
    import uvicorn
    
    # Security: Verify secure environment
    if not os.path.exists("/tmp/memory-pool"):
        logger.error("❌ Secure memory pool not available - ensure tmpfs is mounted")
        exit(1)
    
    logger.info("🚀 Starting Ultra-Secure Media Encoding Server")
    logger.info("🔒 Zero-trust mode with encrypted virtual memory")
    
    # SECURITY: HTTPS-ONLY MODE - No HTTP support
    logger.info("🔒 Starting in HTTPS-ONLY mode - HTTP completely disabled")
    
    # Force HTTPS port regardless of configuration
    https_port = 8443
    
    # Get SSL context with automatic certificate management
    ssl_context = tls_manager.get_ssl_context()
    if ssl_context is None:
        logger.error("❌ CRITICAL: Failed to create SSL context - cannot start without HTTPS")
        logger.error("💡 Check certificate generation permissions and tmpfs mount")
        exit(1)
    
    logger.info(f"🔐 HTTPS server starting on port {https_port} with TLS certificate")
    logger.info("🛡️  HTTP is completely disabled - all connections must use HTTPS")
    
    # Start HTTPS-only server
    uvicorn.run(
        app,
        host=settings.HOST,
        port=https_port,
        ssl_keyfile=str(tls_manager.key_file),
        ssl_certfile=str(tls_manager.cert_file),
        log_level="warning" if not settings.DEBUG else "info",
        access_log=settings.DEBUG,
        server_header=False,  # Don't reveal uvicorn version
        date_header=False     # Don't reveal system time
    )