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
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
import json
import io

from app.config import settings
from app.secure_jobs import SecureJobProcessor
from app.encryption import EncryptionManager

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


if __name__ == "__main__":
    import uvicorn
    
    # Security: Verify secure environment
    if not os.path.exists("/tmp/memory-pool"):
        logger.error("❌ Secure memory pool not available - ensure tmpfs is mounted")
        exit(1)
    
    logger.info("🚀 Starting Ultra-Secure Media Encoding Server")
    logger.info("🔒 Zero-trust mode with encrypted virtual memory")
    
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        log_level="warning" if not settings.DEBUG else "info",
        access_log=settings.DEBUG
    )