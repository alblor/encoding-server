"""
Secure Job Processing with Encrypted Virtual Memory

Integrates the SecureMemoryManager with job processing to ensure all media data
is handled through RAM-only or encrypted swap, never touching persistent storage.

Author: Lorenzo Albanese (alblor)
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any

from .secure_memory import SecureFile, secure_memory_manager
from .jobs import FFmpegValidator
from .encryption import EncryptionManager

logger = logging.getLogger(__name__)


class SecureJobProcessor:
    """
    Job processor that uses encrypted virtual memory for all media handling.
    Ensures zero-trust processing with no persistent storage traces.
    """
    
    def __init__(self, encryption_manager: EncryptionManager = None):
        self.encryption_manager = encryption_manager or EncryptionManager()
        self.ffmpeg_validator = FFmpegValidator()
        self.jobs: Dict[str, Dict] = {}
        self.job_lock = asyncio.Lock()
        
        # Zero-trust configuration
        self.memory_threshold = int(os.getenv("MEMORY_THRESHOLD", "4294967296"))  # 4GB
        self.secure_memory_enabled = os.getenv("SECURE_MEMORY", "true").lower() == "true"
        self.zero_trace_enabled = os.getenv("ZERO_TRACE", "true").lower() == "true"
        
        logger.info(f"SecureJobProcessor initialized with memory threshold: {self.memory_threshold} bytes")
        logger.info(f"Secure memory: {self.secure_memory_enabled}, Zero trace: {self.zero_trace_enabled}")
    
    async def submit_job(self, file_data: bytes, params: Dict, encryption_mode: str, decryption_password: str = None) -> str:
        """
        Submit a job for secure processing using encrypted virtual memory.
        
        Args:
            file_data: Input media file data
            params: FFmpeg processing parameters
            encryption_mode: "automated" or "manual"
            
        Returns:
            Job ID for tracking
        """
        job_id = str(uuid.uuid4())
        
        try:
            # Validate FFmpeg parameters for security
            validated_params = self.ffmpeg_validator.validate_parameters(params)
            
            # Create job record
            job_record = {
                "id": job_id,
                "status": "queued",
                "created_at": time.time(),
                "encryption_mode": encryption_mode,
                "params": validated_params,
                "progress": 0,
                "message": "Job queued for processing",
                "file_size": len(file_data),
                "memory_mode": "encrypted_swap" if len(file_data) > self.memory_threshold else "ram",
                "decryption_password": decryption_password
            }
            
            async with self.job_lock:
                self.jobs[job_id] = job_record
            
            # Start processing in background
            asyncio.create_task(self._process_job_secure(job_id, file_data, validated_params, encryption_mode, decryption_password))
            
            logger.info(f"Submitted job {job_id} for secure processing ({len(file_data)} bytes, {job_record['memory_mode']} mode)")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to submit job: {e}")
            async with self.job_lock:
                if job_id in self.jobs:
                    self.jobs[job_id]["status"] = "failed"
                    self.jobs[job_id]["message"] = str(e)
            raise
    
    async def _process_job_secure(self, job_id: str, file_data: bytes, params: Dict, encryption_mode: str, decryption_password: str = None) -> None:
        """
        Process job using secure memory management.
        All temporary files are created in encrypted virtual memory.
        """
        input_storage = None
        output_storage = None
        
        try:
            # Update job status
            await self._update_job_status(job_id, "processing", "Starting secure processing", 10)
            
            # Create secure storage for input file
            logger.info(f"Job {job_id}: Allocating secure input storage ({len(file_data)} bytes)")
            input_storage = SecureFile(size_hint=len(file_data), initial_content=file_data)
            input_file_path = input_storage.get_file_path()
            
            if not input_file_path:
                raise Exception("Failed to allocate secure input storage")
            
            await self._update_job_status(job_id, "processing", "Input file secured in memory", 25)
            
            # Handle encryption mode: decrypt manual mode data before processing
            actual_input_path = input_file_path
            if encryption_mode == "manual":
                # For manual mode, data is already encrypted - need to decrypt it first
                logger.info(f"Job {job_id}: Decrypting pre-encrypted data for processing")
                
                # Create temporary file for decrypted content
                decrypted_storage = SecureFile(size_hint=len(file_data))
                decrypted_path = decrypted_storage.get_file_path()
                
                if not decrypted_path:
                    raise Exception("Failed to allocate secure decryption storage")
                
                try:
                    # Use password-based decryption (matching client-side format)
                    if not decryption_password:
                        raise ValueError("Manual mode requires decryption password")
                    
                    # Decrypt the encrypted file data using password-based decryption
                    result = self.encryption_manager.decrypt_password_based_file(
                        str(input_file_path), str(decrypted_path), decryption_password
                    )
                    
                    actual_input_path = decrypted_path
                    logger.info(f"Job {job_id}: Successfully decrypted input file ({result['size']} bytes)")
                    
                except Exception as e:
                    logger.error(f"Job {job_id}: Password-based decryption failed: {e}")
                    # If password-based decryption fails, the manual mode cannot proceed
                    raise Exception(f"Manual mode decryption failed: {e}")
            else:
                # For automated mode, data is unencrypted - will be encrypted transparently
                logger.info(f"Job {job_id}: Processing with transparent encryption")
            
            await self._update_job_status(job_id, "processing", "Starting FFmpeg processing", 40)
            
            # Build FFmpeg command with secure file paths
            output_file_path = self._generate_secure_output_path(job_id)
            ffmpeg_cmd = self.ffmpeg_validator.build_command(
                str(actual_input_path), str(output_file_path), params
            )
            
            # Execute FFmpeg with secure memory constraints
            logger.info(f"Job {job_id}: Executing FFmpeg command")
            success = await self._execute_ffmpeg_secure(job_id, ffmpeg_cmd)
            
            if not success:
                raise Exception("FFmpeg processing failed")
            
            await self._update_job_status(job_id, "processing", "Reading processed output", 80)
            
            # Read processed output from secure storage
            if not Path(output_file_path).exists():
                raise Exception("Output file not created by FFmpeg")
            
            with open(output_file_path, 'rb') as f:
                output_data = f.read()
            
            # Handle encryption for final output
            final_output = await self._handle_output_encryption(
                job_id, output_data, encryption_mode
            )
            
            # Store result securely
            result_size = len(final_output)
            result_storage = SecureFile(size_hint=result_size, initial_content=final_output)
            
            await self._update_job_status(job_id, "processing", "Finalizing secure storage", 95)
            
            # Update job with completion info
            async with self.job_lock:
                self.jobs[job_id].update({
                    "status": "completed",
                    "progress": 100,
                    "message": "Processing completed successfully",
                    "result_storage_id": result_storage.storage_id,
                    "result_size": result_size,
                    "completed_at": time.time()
                })
            
            # Secure cleanup of temporary output file
            if Path(output_file_path).exists():
                self._secure_delete_file(output_file_path)
            
            logger.info(f"Job {job_id}: Completed successfully ({result_size} bytes output)")
            
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            await self._update_job_status(job_id, "failed", str(e), None)
        
        finally:
            # Cleanup secure storage
            if input_storage:
                input_storage.close()
            logger.info(f"Job {job_id}: Cleanup completed")
    
    async def _execute_ffmpeg_secure(self, job_id: str, cmd: List[str]) -> bool:
        """
        Execute FFmpeg with secure memory constraints and progress monitoring.
        """
        try:
            logger.info(f"Job {job_id}: Starting FFmpeg: {' '.join(cmd[:3])} ... {' '.join(cmd[-2:])}")
            
            # Create subprocess with security constraints
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/memory-pool",  # Run in secure tmpfs
                env={
                    **os.environ,
                    "TMPDIR": "/tmp/memory-pool",
                    "TEMP": "/tmp/memory-pool",
                    "TMP": "/tmp/memory-pool"
                }
            )
            
            # Monitor progress
            progress_task = asyncio.create_task(
                self._monitor_ffmpeg_progress(job_id, process)
            )
            
            # Wait for completion
            stdout, stderr = await process.communicate()
            progress_task.cancel()
            
            if process.returncode == 0:
                logger.info(f"Job {job_id}: FFmpeg completed successfully")
                return True
            else:
                logger.error(f"Job {job_id}: FFmpeg failed with code {process.returncode}")
                logger.error(f"Job {job_id}: FFmpeg stderr: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Job {job_id}: FFmpeg execution error: {e}")
            return False
    
    async def _monitor_ffmpeg_progress(self, job_id: str, process: asyncio.subprocess.Process) -> None:
        """Monitor FFmpeg progress and update job status."""
        try:
            progress = 45  # Start after initial setup
            while process.returncode is None:
                await asyncio.sleep(2)
                progress = min(progress + 5, 75)  # Increment up to 75%
                await self._update_job_status(
                    job_id, "processing", f"Processing media (FFmpeg running)", progress
                )
        except asyncio.CancelledError:
            pass  # Normal cancellation when FFmpeg completes
        except Exception as e:
            logger.warning(f"Job {job_id}: Progress monitoring error: {e}")
    
    async def _handle_output_encryption(self, job_id: str, output_data: bytes, encryption_mode: str) -> bytes:
        """Handle output encryption based on mode."""
        if encryption_mode == "automated":
            # Automated mode: encrypt output transparently for storage, but return decrypted for user
            encrypted_data, key_id = self.encryption_manager.automated_encrypt(output_data)
            
            # Store encrypted version
            async with self.job_lock:
                self.jobs[job_id]["encrypted_result"] = encrypted_data
                self.jobs[job_id]["key_id"] = key_id
            
            # Return original unencrypted data for user (transparency)
            logger.info(f"Job {job_id}: Applied transparent encryption ({len(encrypted_data)} bytes encrypted)")
            return output_data
            
        else:
            # Manual mode: encrypt output using same password format as client
            logger.info(f"Job {job_id}: Encrypting output for manual mode ({len(output_data)} bytes)")
            
            # Get password from job record
            async with self.job_lock:
                decryption_password = self.jobs[job_id].get("decryption_password")
            
            if not decryption_password:
                raise Exception("Manual mode missing decryption password for output encryption")
            
            # Create temporary files for encryption process
            temp_unencrypted = f"/tmp/memory-pool/temp_output_{job_id}.mp4"
            temp_encrypted = f"/tmp/memory-pool/temp_encrypted_{job_id}.enc"
            
            try:
                # Write unencrypted output to temporary file
                with open(temp_unencrypted, 'wb') as f:
                    f.write(output_data)
                
                # Encrypt using client-compatible format
                result = self.encryption_manager.encrypt_password_based_file(
                    temp_unencrypted, temp_encrypted, decryption_password
                )
                
                # Read encrypted result
                with open(temp_encrypted, 'rb') as f:
                    encrypted_output = f.read()
                
                logger.info(f"Job {job_id}: Successfully encrypted output ({len(output_data)} → {len(encrypted_output)} bytes)")
                return encrypted_output
                
            finally:
                # Clean up temporary files
                for temp_file in [temp_unencrypted, temp_encrypted]:
                    if os.path.exists(temp_file):
                        self._secure_delete_file(temp_file)
    
    def _generate_secure_output_path(self, job_id: str) -> str:
        """Generate secure output file path in tmpfs."""
        return f"/tmp/memory-pool/output_{job_id}.mp4"
    
    def _secure_delete_file(self, file_path: str) -> None:
        """Securely delete file with multiple overwrites."""
        if not self.zero_trace_enabled:
            return
        
        path = Path(file_path)
        if not path.exists():
            return
        
        try:
            # Get file size
            file_size = path.stat().st_size
            
            # Overwrite multiple times
            with open(path, 'r+b') as f:
                for _ in range(3):  # 3-pass secure deletion
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove file
            path.unlink()
            logger.debug(f"Securely deleted temporary file: {file_path}")
            
        except Exception as e:
            logger.warning(f"Failed to securely delete {file_path}: {e}")
    
    async def _update_job_status(self, job_id: str, status: str, message: str, progress: Optional[int]) -> None:
        """Update job status thread-safely."""
        async with self.job_lock:
            if job_id in self.jobs:
                self.jobs[job_id]["status"] = status
                self.jobs[job_id]["message"] = message
                if progress is not None:
                    self.jobs[job_id]["progress"] = progress
    
    def get_job_status(self, job_id: str) -> Optional[Dict]:
        """Get job status information."""
        return self.jobs.get(job_id)
    
    def get_job_result(self, job_id: str) -> Optional[bytes]:
        """Get job result from secure storage."""
        job = self.jobs.get(job_id)
        if not job or job["status"] != "completed":
            return None
        
        try:
            # Get result from secure storage
            storage_id = job.get("result_storage_id")
            if storage_id:
                return secure_memory_manager.read_secure_data(storage_id)
            
            # Fallback to encrypted result (for automated mode)
            encrypted_result = job.get("encrypted_result")
            if encrypted_result and job["encryption_mode"] == "automated":
                # Decrypt transparently for automated mode
                key_id = job.get("key_id")
                # In a real implementation, retrieve the key using key_id
                # For now, return the encrypted result
                return encrypted_result
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve result for job {job_id}: {e}")
            return None
    
    def list_jobs(self) -> List[Dict]:
        """List all jobs with basic information."""
        return [
            {
                "id": job["id"],
                "status": job["status"],
                "created_at": job["created_at"],
                "encryption_mode": job["encryption_mode"],
                "progress": job["progress"],
                "memory_mode": job.get("memory_mode", "unknown")
            }
            for job in self.jobs.values()
        ]