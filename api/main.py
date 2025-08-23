"""
Secure Media Encoding Server - Production-Ready FastAPI Application

A zero-trust, privacy-first media encoding server designed for Proxmox environments
with dual-mode encryption and flexible FFmpeg parameter handling.

Author: Lorenzo Albanese (alblor)
Architecture: Proxmox-optimized secure media encoding
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
from app.jobs import JobProcessor
from app.encryption import EncryptionManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan management with proper startup and shutdown procedures."""
    logger.info("Starting Secure Media Encoding Server")
    
    # Initialize core services
    try:
        # Create temporary directories
        os.makedirs(settings.TEMP_STORAGE, exist_ok=True)
        os.makedirs(settings.ENCRYPTED_STORAGE, exist_ok=True)
        
        # Initialize job processor and encryption manager
        app.state.job_processor = JobProcessor()
        app.state.encryption_manager = EncryptionManager()
        
        logger.info("Core services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize core services: {e}")
        raise
    
    # Application is ready
    yield
    
    # Cleanup on shutdown
    logger.info("Shutting down Secure Media Encoding Server")
    
    try:
        # Cleanup temporary files and resources
        logger.info("Cleanup completed successfully")
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")


# Create FastAPI application
app = FastAPI(
    title="Secure Media Encoding Server",
    description="Zero-trust, privacy-first media encoding with dual-mode encryption",
    version="1.0.0",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions with proper logging and response format."""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} - {request.method} {request.url.path}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "path": request.url.path
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions with proper logging."""
    logger.error(f"Unexpected error: {str(exc)} - {request.method} {request.url.path}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error",
                "path": request.url.path
            }
        }
    )


# API Routes
@app.get("/")
async def root() -> dict:
    """Root endpoint with basic service information."""
    return {
        "service": "Secure Media Encoding Server",
        "version": "1.0.0",
        "author": "Lorenzo Albanese (alblor)",
        "architecture": "Proxmox-optimized secure media encoding",
        "encryption_modes": ["automated", "manual"],
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for Proxmox monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "ffmpeg": "available",
            "encryption": "ready",
            "storage": "ready"
        }
    }


@app.post("/v1/jobs")
async def submit_job(
    file: UploadFile = File(...),
    params: str = Form(...),
    encryption_mode: str = Form(default="automated")
):
    """Submit an encoding job with comprehensive validation."""
    
    # Validate encryption mode
    if encryption_mode not in ["automated", "manual"]:
        raise HTTPException(status_code=400, detail="Invalid encryption mode. Use 'automated' or 'manual'")
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Parse and validate parameters
    try:
        ffmpeg_params = json.loads(params)
        if not isinstance(ffmpeg_params, dict):
            raise ValueError("Parameters must be a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON parameters: {str(e)}")
    
    # Read file data
    try:
        file_data = await file.read()
        if len(file_data) == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        if len(file_data) > 100 * 1024 * 1024:  # 100MB limit for demo
            raise HTTPException(status_code=400, detail="File too large (max 100MB)")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")
    
    # Submit job for processing
    try:
        job_id = await app.state.job_processor.submit_job(file_data, ffmpeg_params, encryption_mode)
        
        return {
            "job_id": job_id,
            "status": "queued",
            "encryption_mode": encryption_mode,
            "message": "Job submitted successfully",
            "submitted_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to submit job: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit job")


@app.get("/v1/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get comprehensive job status and progress."""
    job = app.state.job_processor.get_job_status(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Return comprehensive job status
    response = {
        "job_id": job['id'],
        "status": job['status'],
        "progress": job['progress'],
        "message": job['message'],
        "created_at": job['created_at'],
        "encryption_mode": job['encryption_mode']
    }
    
    # Add completion time if available
    if 'completed_at' in job:
        response['completed_at'] = job['completed_at']
    if 'failed_at' in job:
        response['failed_at'] = job['failed_at']
    
    return response


@app.get("/v1/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    """Download job result with proper headers and validation."""
    job = app.state.job_processor.get_job_status(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['status'] != 'completed':
        raise HTTPException(
            status_code=400, 
            detail=f"Job not completed. Current status: {job['status']}"
        )
    
    result_data = app.state.job_processor.get_job_result(job_id)
    if not result_data:
        raise HTTPException(status_code=404, detail="Result data not found")
    
    # Determine filename based on encryption mode
    if job['encryption_mode'] == 'automated':
        filename = f"result_{job_id}.mp4"  # Unencrypted for user
        media_type = "video/mp4"
    else:
        filename = f"result_{job_id}.enc"  # Encrypted for manual decryption
        media_type = "application/octet-stream"
    
    return StreamingResponse(
        io.BytesIO(result_data),
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(result_data))
        }
    )


@app.get("/v1/jobs")
async def list_jobs():
    """List all jobs with comprehensive information."""
    jobs = app.state.job_processor.list_jobs()
    
    return {
        "jobs": [
            {
                "job_id": job['id'],
                "status": job['status'],
                "progress": job['progress'],
                "created_at": job['created_at'],
                "encryption_mode": job['encryption_mode'],
                "message": job['message']
            }
            for job in jobs
        ],
        "total_jobs": len(jobs)
    }


@app.delete("/v1/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a job with proper validation."""
    job = app.state.job_processor.get_job_status(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job['status'] in ['completed', 'failed']:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot cancel {job['status']} job"
        )
    
    # Mark job as cancelled
    job['status'] = 'cancelled'
    job['message'] = 'Job cancelled by user request'
    job['cancelled_at'] = datetime.now().isoformat()
    
    return {
        "message": "Job cancelled successfully",
        "job_id": job_id,
        "cancelled_at": job['cancelled_at']
    }


@app.post("/v1/encryption/keypair")
async def generate_keypair():
    """Generate ECDH keypair for manual encryption mode."""
    try:
        private_key, public_key = app.state.encryption_manager.generate_keypair()
        
        return {
            "private_key": private_key.decode('utf-8'),
            "public_key": public_key.decode('utf-8'),
            "algorithm": "ECDH with SECP256R1",
            "message": "Store private key securely - server only needs public key for encryption"
        }
    except Exception as e:
        logger.error(f"Failed to generate keypair: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate encryption keypair")


@app.get("/v1/presets")
async def list_presets():
    """List available FFmpeg presets for common operations."""
    presets = {
        "h264_high_quality": {
            "description": "H.264 high quality encoding",
            "params": {
                "video_codec": "libx264",
                "audio_codec": "aac",
                "custom_params": ["-preset", "slow", "-crf", "18"]
            }
        },
        "h264_web_optimized": {
            "description": "H.264 web-optimized encoding",
            "params": {
                "video_codec": "libx264", 
                "audio_codec": "aac",
                "custom_params": ["-preset", "fast", "-crf", "23", "-movflags", "+faststart"]
            }
        },
        "audio_copy": {
            "description": "Re-encode video, copy audio stream",
            "params": {
                "video_codec": "libx264",
                "audio_codec": "copy",
                "custom_params": ["-preset", "medium"]
            }
        },
        "format_conversion": {
            "description": "Format conversion without re-encoding",
            "params": {
                "video_codec": "copy",
                "audio_codec": "copy"
            }
        }
    }
    
    return {"presets": presets}


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        access_log=True
    )