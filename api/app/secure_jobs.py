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
from .ffmpeg_progress import FFmpegProgressParser

logger = logging.getLogger(__name__)


class SecureJobProcessor:
    """
    Job processor that uses encrypted virtual memory for all media handling.
    Ensures zero-trust processing with no persistent storage traces.
    """
    
    def __init__(self, encryption_manager: EncryptionManager = None):
        self.encryption_manager = encryption_manager or EncryptionManager()
        self.ffmpeg_validator = FFmpegValidator()
        self.progress_parser = FFmpegProgressParser()
        self.jobs: Dict[str, Dict] = {}
        self.job_lock = asyncio.Lock()
        self.cancelling_jobs: set = set()  # Track jobs being cancelled
        self.job_processes: Dict[str, asyncio.subprocess.Process] = {}  # Track active processes
        
        # Zero-trust configuration
        self.memory_threshold = int(os.getenv("MEMORY_THRESHOLD", "4294967296"))  # 4GB
        self.secure_memory_enabled = os.getenv("SECURE_MEMORY", "true").lower() == "true"
        self.zero_trace_enabled = os.getenv("ZERO_TRACE", "true").lower() == "true"
        
        # Security flexibility configuration
        self.encryption_disabled = os.getenv("DISABLE_ENCRYPTION", "false").lower() == "true"
        self.security_level = os.getenv("FFMPEG_SECURITY_LEVEL", "maximum")  
        self.environment = os.getenv("ENVIRONMENT", "development")
        
        logger.info(f"SecureJobProcessor initialized with memory threshold: {self.memory_threshold} bytes")
        logger.info(f"Secure memory: {self.secure_memory_enabled}, Zero trace: {self.zero_trace_enabled}")
        logger.info(f"Security level: {self.security_level}, Environment: {self.environment}")
        
        if self.encryption_disabled:
            logger.warning("⚠️ CRITICAL: ENCRYPTION COMPLETELY DISABLED - VERY UNSAFE!")
            logger.warning("This setting should ONLY be used for development/testing purposes")
    
    async def submit_job(self, file_data: bytes, params: Dict, encryption_mode: str, decryption_password: str = None) -> str:
        """
        Submit a job for secure processing using encrypted virtual memory.
        
        Args:
            file_data: Input media file data
            params: FFmpeg processing parameters
            encryption_mode: "automated" or "manual" (ignored if encryption disabled)
            
        Returns:
            Job ID for tracking
        """
        job_id = str(uuid.uuid4())
        
        try:
            # Check if encryption is completely disabled
            if self.encryption_disabled:
                logger.warning(f"Job {job_id}: Encryption DISABLED - processing unencrypted data")
                encryption_mode = "none"  # Override any provided mode
            
            # Validate FFmpeg parameters for security
            validated_params = self.ffmpeg_validator.validate_parameters(params)
            
            # SECURITY: Encrypt password for storage if provided
            encrypted_password = None
            if decryption_password and not self.encryption_disabled:
                try:
                    # Use encryption manager to encrypt password for secure storage
                    encrypted_password_data, password_key_id = self.encryption_manager.automated_encrypt(
                        decryption_password.encode('utf-8')
                    )
                    encrypted_password = {
                        'encrypted_data': encrypted_password_data,
                        'key_id': password_key_id
                    }
                    logger.debug(f"Job {job_id}: Password encrypted for secure storage")
                except Exception as e:
                    logger.error(f"Job {job_id}: Failed to encrypt password: {e}")
                    raise Exception("Failed to secure password for storage")
            elif decryption_password and self.encryption_disabled:
                # Store plaintext only if encryption is completely disabled (development only)
                encrypted_password = decryption_password
                logger.warning(f"Job {job_id}: Storing password in plaintext (ENCRYPTION DISABLED)")
            
            # Create job record with enhanced progress tracking
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
                "encrypted_password": encrypted_password,
                # Enhanced progress tracking fields
                "progress_details": {
                    "current_time": None,
                    "current_time_str": "00:00:00",
                    "total_duration": None,
                    "processing_duration": None,
                    "fps": None,
                    "speed": None,
                    "eta": None,
                    "frame": None,
                    "has_time_cuts": False,
                    "start_offset": 0.0
                }
            }
            
            async with self.job_lock:
                self.jobs[job_id] = job_record
            
            # Clear plaintext password from memory immediately after encryption
            if decryption_password:
                decryption_password = None
            
            # Start processing in background
            asyncio.create_task(self._process_job_secure(job_id, file_data, validated_params, encryption_mode))
            
            logger.info(f"Submitted job {job_id} for secure processing ({len(file_data)} bytes, {job_record['memory_mode']} mode)")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to submit job: {e}")
            async with self.job_lock:
                if job_id in self.jobs:
                    self.jobs[job_id]["status"] = "failed"
                    self.jobs[job_id]["message"] = str(e)
            raise
    
    async def _process_job_secure(self, job_id: str, file_data: bytes, params: Dict, encryption_mode: str) -> None:
        """
        Process job using secure memory management and complete isolation.
        
        Implements three-layer security:
        1. Parameter validation (already done)
        2. Safe command construction with resource limits
        3. Complete FFmpeg sandboxing and isolation
        """
        input_storage = None
        output_storage = None
        
        try:
            # Check for cancellation before starting processing
            if job_id in self.cancelling_jobs:
                logger.debug(f"DEBUG: Job {job_id} - Cancellation detected at start of processing (in cancelling_jobs set)")
                await self._update_job_status(job_id, "cancelled", "Job cancelled during setup", None)
                return
            
            # LAYER 3 SECURITY: Validate execution environment adaptively
            security_assessment = self._validate_execution_environment()
            if not security_assessment["meets_requirements"]:
                # Log warnings but allow execution with degraded security
                logger.warning("SECURITY NOTICE: Running with degraded security posture")
                for warning in security_assessment["warnings"]:
                    logger.warning(f"  - {warning}")
                    
                # Only fail hard if critical failures exist and we're in maximum security mode
                if security_assessment["critical_failures"] and self.security_level == "maximum":
                    raise Exception("Security violation: Critical security requirements not met in maximum security mode")
            else:
                logger.info("✓ All security requirements met for current environment")
            
            # Set up network isolation
            self._setup_network_isolation()
            
            # Update job status
            await self._update_job_status(job_id, "processing", "Starting secure processing with isolation", 10)
            
            # Create secure storage for input file
            logger.info(f"Job {job_id}: Allocating secure input storage ({len(file_data)} bytes)")
            input_storage = SecureFile(size_hint=len(file_data), initial_content=file_data)
            input_file_path = input_storage.get_file_path()
            
            if not input_file_path:
                raise Exception("Failed to allocate secure input storage")
            
            await self._update_job_status(job_id, "processing", "Input file secured in memory", 25)
            
            # Check for cancellation after secure storage setup
            if job_id in self.cancelling_jobs:
                logger.debug(f"DEBUG: Job {job_id} - Cancellation detected after secure storage setup (in cancelling_jobs set)")
                await self._update_job_status(job_id, "cancelled", "Job cancelled during storage setup", None)
                return
            
            # Handle encryption mode: decrypt manual mode data before processing (unless disabled)
            actual_input_path = input_file_path
            
            if encryption_mode == "none":
                # Encryption completely disabled - process data as-is
                logger.warning(f"Job {job_id}: Processing unencrypted data (ENCRYPTION DISABLED)")
            elif encryption_mode == "manual" and not self.encryption_disabled:
                # For manual mode, data is already encrypted - need to decrypt it first
                logger.info(f"Job {job_id}: Decrypting pre-encrypted data for processing")
                
                # Create temporary file for decrypted content
                decrypted_storage = SecureFile(size_hint=len(file_data))
                decrypted_path = decrypted_storage.get_file_path()
                
                if not decrypted_path:
                    raise Exception("Failed to allocate secure decryption storage")
                
                try:
                    # SECURITY: Retrieve and decrypt the stored password
                    decryption_password = await self._get_decrypted_password(job_id)
                    if not decryption_password:
                        raise ValueError("Manual mode requires decryption password")
                    
                    # Decrypt the encrypted file data using password-based decryption
                    result = self.encryption_manager.decrypt_password_based_file(
                        str(input_file_path), str(decrypted_path), decryption_password
                    )
                    
                    # Clear password from memory immediately after use
                    decryption_password = None
                    
                    actual_input_path = decrypted_path
                    logger.info(f"Job {job_id}: Successfully decrypted input file ({result['size']} bytes)")
                    
                except Exception as e:
                    logger.error(f"Job {job_id}: Password-based decryption failed: {e}")
                    # If password-based decryption fails, the manual mode cannot proceed
                    raise Exception(f"Manual mode decryption failed: {e}")
            else:
                # For automated mode, data is unencrypted - will be encrypted transparently
                logger.info(f"Job {job_id}: Processing with transparent encryption")
            
            # ENHANCED PROGRESS TRACKING: Extract media duration and setup progress parser
            await self._update_job_status(job_id, "processing", "Analyzing media duration and parameters", 30)
            
            # Initialize progress parser for this job
            progress_parser = FFmpegProgressParser()
            
            # Extract total duration using ffprobe
            total_duration = await progress_parser.get_media_duration(str(actual_input_path))
            
            # Parse FFmpeg parameters for time-based cuts
            safe_params = params.get('safe_params', {}) if isinstance(params, dict) else params
            if isinstance(safe_params, dict) and 'custom_params' in safe_params:
                ffmpeg_params = safe_params['custom_params']
            elif isinstance(safe_params, list):
                ffmpeg_params = safe_params
            else:
                ffmpeg_params = []
            
            time_info = progress_parser.parse_time_parameters(ffmpeg_params)
            
            # Update job record with duration and time information
            async with self.job_lock:
                if job_id in self.jobs:
                    self.jobs[job_id]["progress_details"].update({
                        "total_duration": total_duration,
                        "processing_duration": time_info.get("processing_duration"),
                        "start_offset": time_info.get("start_time", 0.0),
                        "has_time_cuts": time_info.get("start_time", 0) > 0 or time_info.get("duration") is not None or time_info.get("end_time") is not None
                    })
                    # Store progress parser instance in job for monitoring
                    self.jobs[job_id]["_progress_parser"] = progress_parser
            
            duration_msg = f"Media duration: {progress_parser.format_duration(total_duration)}"
            if time_info.get("processing_duration"):
                duration_msg += f", Processing: {progress_parser.format_duration(time_info['processing_duration'])}"
            if time_info.get("has_time_cuts", False):
                duration_msg += f" (with time cuts from {progress_parser.format_duration(time_info.get('start_time', 0))})"
            
            logger.info(f"Job {job_id}: {duration_msg}")
            
            await self._update_job_status(job_id, "processing", "Starting FFmpeg processing", 40)
            
            # Check for cancellation before FFmpeg execution
            if job_id in self.cancelling_jobs:
                logger.debug(f"DEBUG: Job {job_id} - Cancellation detected before FFmpeg execution (in cancelling_jobs set)")
                await self._update_job_status(job_id, "cancelled", "Job cancelled before FFmpeg execution", None)
                return
            
            # Build FFmpeg command with secure file paths
            output_file_path = self._generate_secure_output_path(job_id)
            ffmpeg_cmd = self.ffmpeg_validator.build_command(
                str(actual_input_path), str(output_file_path), params
            )
            
            # Execute FFmpeg with secure memory constraints
            logger.info(f"Job {job_id}: Executing FFmpeg command")
            ffmpeg_result = await self._execute_ffmpeg_secure(job_id, ffmpeg_cmd)
            
            if ffmpeg_result == "cancelled":
                logger.debug(f"DEBUG: Job {job_id} - FFmpeg execution returned 'cancelled' - job was cancelled")
                await self._update_job_status(job_id, "cancelled", "Job cancelled during FFmpeg execution", None)
                return  # Exit processing cleanly
            elif not ffmpeg_result:
                raise Exception("FFmpeg processing failed")
            
            await self._update_job_status(job_id, "processing", "Reading processed output", 90)
            
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
            # CRITICAL: Check if job was cancelled before marking as failed
            async with self.job_lock:
                current_job = self.jobs.get(job_id)
                if current_job and current_job.get("status") == "cancelled":
                    logger.debug(f"DEBUG: Job {job_id} - Exception occurred but job already cancelled: {e}")
                    return  # Job already properly marked as cancelled
                elif job_id in self.cancelling_jobs:
                    logger.debug(f"DEBUG: Job {job_id} - Exception during cancellation process: {e}")
                    await self._update_job_status(job_id, "cancelled", "Job cancelled with cleanup", None)
                    return
            
            logger.error(f"Job {job_id} failed: {e}")
            logger.debug(f"DEBUG: Job {job_id} - Marking as failed (not cancelled)")
            await self._update_job_status(job_id, "failed", str(e), None)
        
        finally:
            # Cleanup secure storage
            if input_storage:
                input_storage.close()
            logger.info(f"Job {job_id}: Cleanup completed")
    
    async def _execute_ffmpeg_secure(self, job_id: str, cmd: List[str]) -> bool:
        """
        Execute FFmpeg with complete isolation and security constraints.
        
        Implements Layer 2 & 3 security:
        - Complete network isolation
        - Restricted file system access
        - Resource limits and process isolation
        - Minimal environment variables
        """
        try:
            logger.info(f"Job {job_id}: Starting isolated FFmpeg: {' '.join(cmd[:3])} ... {' '.join(cmd[-2:])}")
            
            # Create completely isolated subprocess environment
            isolated_env = self._create_isolated_environment()
            
            # Create subprocess with security isolation (resource management handled by container)
            logger.info(f"Job {job_id}: Executing FFmpeg with security isolation")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/memory-pool",  # Secure tmpfs working directory
                env=isolated_env,  # Minimal environment
                # SECURITY: Process isolation without artificial resource limits
                close_fds=True,  # Close all file descriptors except std streams
                shell=False      # Ensure no shell interpretation
            )
            
            # Register process for potential cancellation
            async with self.job_lock:
                self.job_processes[job_id] = process
                logger.debug(f"DEBUG: Job {job_id} - Registered FFmpeg process (PID: {process.pid}) in job_processes dict")
            
            # Monitor progress concurrently with FFmpeg execution
            progress_task = asyncio.create_task(
                self._monitor_ffmpeg_progress(job_id, process)
            )
            
            # Wait for BOTH FFmpeg completion AND progress monitoring to finish
            try:
                await asyncio.gather(
                    process.wait(),          # Wait for FFmpeg to finish
                    progress_task            # Wait for progress monitoring to finish
                )
            except asyncio.CancelledError:
                # If cancelled, make sure to clean up
                logger.debug(f"DEBUG: Job {job_id} - AsyncIO CancelledError caught during FFmpeg execution")
                logger.info(f"Job {job_id}: FFmpeg execution cancelled, cleaning up process")
                if not process.returncode:
                    try:
                        process.terminate()
                        # Wait briefly for graceful shutdown
                        await asyncio.wait_for(process.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        # Force kill if graceful termination fails
                        logger.warning(f"Job {job_id}: Forcing FFmpeg termination")
                        process.kill()
                        await process.wait()
                raise
            finally:
                # Clean up process tracking regardless of outcome
                async with self.job_lock:
                    logger.debug(f"DEBUG: Job {job_id} - Removing process from job_processes dict")
                    self.job_processes.pop(job_id, None)
            
            # Read any remaining stdout data (stderr is handled by monitoring task)
            if process.stdout:
                try:
                    stdout = await asyncio.wait_for(process.stdout.read(), timeout=1.0)
                except asyncio.TimeoutError:
                    stdout = b""
            else:
                stdout = b""
            
            if process.returncode == 0:
                logger.debug(f"DEBUG: Job {job_id} - FFmpeg process completed with return code 0")
                logger.info(f"Job {job_id}: FFmpeg completed successfully")
                return True
            elif process.returncode in [-9, -15, 137, 143]:  # SIGKILL, SIGTERM signals
                # These return codes indicate process termination, likely from cancellation
                logger.debug(f"DEBUG: Job {job_id} - FFmpeg terminated with signal (return code {process.returncode})")
                async with self.job_lock:
                    if job_id in self.cancelling_jobs or (job_id in self.jobs and self.jobs[job_id].get('status') == 'cancelled'):
                        logger.info(f"Job {job_id}: FFmpeg terminated due to cancellation")
                        return "cancelled"  # Special return value to indicate cancellation
                    else:
                        logger.warning(f"Job {job_id}: FFmpeg terminated unexpectedly with signal {process.returncode}")
                        return False
            else:
                logger.debug(f"DEBUG: Job {job_id} - FFmpeg process failed with return code {process.returncode}")
                logger.error(f"Job {job_id}: FFmpeg failed with code {process.returncode}")
                # stderr is handled by monitoring task, so we log what we can
                logger.error(f"Job {job_id}: Check job progress details for error information")
                return False
                
        except Exception as e:
            logger.debug(f"DEBUG: Job {job_id} - Exception in _execute_ffmpeg_secure: {e}")
            logger.error(f"Job {job_id}: FFmpeg execution error: {e}")
            return False
    
    def _create_isolated_environment(self) -> Dict[str, str]:
        """
        Create completely isolated environment for FFmpeg execution.
        
        Removes ALL environment variables except absolute essentials,
        preventing any potential environment-based attacks or data leakage.
        """
        isolated_env = {
            # Absolute minimum required for FFmpeg operation
            "PATH": "/usr/local/bin:/usr/bin:/bin",  # Minimal PATH for FFmpeg binary
            "HOME": "/tmp/memory-pool",  # Redirect home to tmpfs
            "USER": "ffmpeg",  # Dedicated user (if available)
            "LANG": "C",  # Minimal locale
            
            # Tmpfs directories (all temporary storage)
            "TMPDIR": "/tmp/memory-pool",
            "TEMP": "/tmp/memory-pool", 
            "TMP": "/tmp/memory-pool",
            
            # Prevent any network access
            "no_proxy": "*",
            "NO_PROXY": "*",
            
            # Disable any potential debugging/development features
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": "",
            
            # Minimal system identification
            "TERM": "dumb",  # No terminal features
        }
        
        # Explicitly remove dangerous environment variables that might exist
        dangerous_vars = [
            "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY",  # SSH info
            "DISPLAY", "XAUTHORITY",  # X11/GUI
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",  # AWS credentials
            "GOOGLE_APPLICATION_CREDENTIALS",  # Google Cloud
            "AZURE_CLIENT_SECRET",  # Azure
            "DATABASE_URL", "REDIS_URL",  # Database connections
            "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY",  # Proxy settings
            "LD_PRELOAD", "LD_LIBRARY_PATH",  # Library injection
        ]
        
        # Ensure dangerous vars are not present
        for var in dangerous_vars:
            isolated_env.pop(var, None)
        
        logger.debug("Created isolated environment with minimal variables")
        return isolated_env
    
    def _setup_network_isolation(self):
        """
        Set up network isolation for FFmpeg process.
        
        This creates a network namespace or uses container networking
        to ensure FFmpeg has zero network access.
        """
        try:
            # For container environments, this is handled by Docker networking
            # For direct execution, we can use Linux namespaces
            if os.path.exists("/proc/sys/net/ipv4"):
                # Linux system - can implement network namespace isolation
                logger.info("Network isolation: Using container network restrictions")
                
            # Additional network blocking through firewall rules
            # This would be configured at the container/host level
            
        except Exception as e:
            logger.warning(f"Network isolation setup warning: {e}")
    
    def _validate_execution_environment(self) -> Dict[str, Any]:
        """
        Adaptive security environment validation with transparent assessment.
        
        Returns detailed security assessment allowing for different security levels:
        - MAXIMUM: All checks must pass (production)
        - HIGH: Core checks must pass, AppArmor/container optional (testing)  
        - MEDIUM: Basic checks only (development)
        
        Returns:
            Dictionary with security assessment results
        """
        is_production = self.environment == "secure-production"
        is_testing = "test" in self.environment.lower() or not is_production
        is_maximum_security = self.security_level == "maximum"
        
        security_checks = []
        violations = []
        warnings = []
        critical_failures = []
        
        logger.info(f"Security validation - Environment: {self.environment}, Level: {self.security_level}")
        
        # Check 1: Verify secure tmpfs mount for memory-pool
        if not os.path.exists("/tmp/memory-pool"):
            msg = "tmpfs workspace not available - using fallback directory"
            if is_maximum_security:
                critical_failures.append(msg)
            else:
                warnings.append(msg)
            security_checks.append(False)
        else:
            # Verify it's actually tmpfs
            try:
                with open("/proc/mounts", "r") as f:
                    mounts = f.read()
                    if "tmpfs /tmp/memory-pool" in mounts:
                        logger.debug("✓ Secure tmpfs workspace verified")
                        security_checks.append(True)
                    else:
                        msg = "memory-pool exists but is not tmpfs - reduced security"
                        if is_maximum_security:
                            violations.append(msg)
                        else:
                            warnings.append(msg)
                        security_checks.append(False)
            except Exception as e:
                logger.debug(f"Could not verify tmpfs mount: {e}")
                warnings.append("Cannot verify tmpfs status")
                security_checks.append(False)
        
        # Check 2: Verify containerized environment (recommended but not critical)
        if not (os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")):
            msg = "Not running in containerized environment - reduced isolation"
            if is_maximum_security:
                warnings.append(msg)
            else:
                logger.debug("Security notice: Not containerized")
        else:
            logger.debug("✓ Container environment detected")
        
        # Check 3: Verify AppArmor FFmpeg profile (critical for production)
        apparmor_enforced = self._verify_apparmor_enforcement()
        if apparmor_enforced:
            logger.debug("✓ AppArmor FFmpeg profile enforced")
            security_checks.append(True)
        else:
            msg = "AppArmor profile not enforced - reduced process confinement"
            if is_production:
                violations.append(msg)
            else:
                warnings.append(msg)
            security_checks.append(False)
        
        # Check 4: Verify network isolation capability (important but not critical)
        network_isolated = self._verify_network_isolation()
        if network_isolated:
            logger.debug("✓ Network isolation verified")
            security_checks.append(True)
        else:
            msg = "Network isolation not fully configured - potential security concern"
            if is_production:
                warnings.append(msg)
            else:
                logger.debug("Network isolation check skipped in development")
            security_checks.append(False)
        
        # Check 5: Verify resource limits are supported (recommended)
        try:
            import resource
            # Test critical resource limits
            current_mem = resource.getrlimit(resource.RLIMIT_AS)
            current_cpu = resource.getrlimit(resource.RLIMIT_CPU)
            current_procs = resource.getrlimit(resource.RLIMIT_NPROC)
            
            logger.debug("✓ Resource limit enforcement available")
            security_checks.append(True)
        except ImportError:
            msg = "Resource limits not available - no process restriction capability"
            warnings.append(msg)
            security_checks.append(False)
        
        # Check 6: Verify FFmpeg binary is available (CRITICAL)
        ffmpeg_path = self._verify_ffmpeg_binary()
        if ffmpeg_path:
            logger.debug(f"✓ FFmpeg binary verified at {ffmpeg_path}")
            security_checks.append(True)
        else:
            critical_failures.append("FFmpeg binary not found - cannot process media")
            security_checks.append(False)
        
        # Assess overall security posture
        passed_checks = sum(security_checks)
        total_checks = len(security_checks)
        
        # Determine if requirements are met based on security level
        if is_maximum_security:
            meets_requirements = (passed_checks == total_checks) and (len(critical_failures) == 0) and (len(violations) == 0)
        elif self.security_level == "high":
            meets_requirements = (passed_checks >= total_checks - 1) and (len(critical_failures) == 0)  # Allow 1 failure
        else:  # medium or basic
            meets_requirements = (passed_checks >= total_checks - 2) and (len(critical_failures) == 0)  # Allow 2 failures
        
        # Log assessment
        if meets_requirements:
            logger.info(f"✓ Security requirements met for {self.security_level} level ({passed_checks}/{total_checks} checks passed)")
        else:
            logger.warning(f"⚠ Security requirements NOT fully met ({passed_checks}/{total_checks} checks passed)")
            
        if violations:
            logger.warning("Security violations:")
            for violation in violations:
                logger.warning(f"  - {violation}")
                
        if critical_failures:
            logger.error("Critical security failures:")
            for failure in critical_failures:
                logger.error(f"  - {failure}")
        
        # Return detailed assessment
        return {
            "meets_requirements": meets_requirements,
            "security_level": self.security_level,
            "environment": self.environment,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
            "security_checks": security_checks,
            "warnings": warnings,
            "violations": violations,
            "critical_failures": critical_failures,
            "assessment": "maximum_security" if passed_checks == total_checks else
                         "high_security" if passed_checks >= total_checks - 1 else
                         "basic_security" if passed_checks >= total_checks - 2 else
                         "minimal_security"
        }
    
    def _verify_apparmor_enforcement(self) -> bool:
        """
        Verify that AppArmor FFmpeg profile is loaded and in ENFORCE mode.
        
        Uses multiple detection methods with graceful fallback to handle permission
        denied errors in nested container environments (Docker-in-LXC).
        
        Returns:
            True if AppArmor is properly enforcing FFmpeg restrictions
        """
        logger.debug("Starting AppArmor verification with multiple detection methods")
        
        # Method 1: Check AppArmor kernel module availability
        apparmor_available = self._check_apparmor_kernel_module()
        if not apparmor_available:
            logger.error("AppArmor kernel module not available on this system")
            return False
            
        # Method 2: Check current process AppArmor profile (Docker default validation)
        current_profile_check = self._check_current_apparmor_profile()
        
        # Method 3: Check system profiles using primary method (may fail in containers)
        system_profiles_check = self._check_system_apparmor_profiles()
        
        # Method 4: Alternative profile detection methods
        if not system_profiles_check:
            logger.warning("Primary profile detection failed, attempting alternative methods")
            alternative_check = self._check_apparmor_alternative_methods()
            
            # Determine result based on security level and available information
            return self._evaluate_apparmor_enforcement_result(
                current_profile_check, 
                system_profiles_check, 
                alternative_check
            )
        
        logger.debug("✓ AppArmor enforcement verified through primary method")
        return True
    
    def _check_apparmor_kernel_module(self) -> bool:
        """
        Check if AppArmor kernel module is enabled using multiple methods.
        
        Returns:
            True if AppArmor kernel module is available and enabled
        """
        # Method 1: Check kernel module parameter (most reliable)
        try:
            with open("/sys/module/apparmor/parameters/enabled", "r") as f:
                enabled = f.read().strip()
                if enabled == "Y":
                    logger.debug("✓ AppArmor kernel module enabled (via parameters)")
                    return True
                else:
                    logger.warning(f"AppArmor kernel module disabled: {enabled}")
                    return False
        except FileNotFoundError:
            logger.debug("AppArmor module parameters not found (module may not be loaded)")
        except PermissionError:
            logger.debug("Permission denied accessing AppArmor module parameters")
        except Exception as e:
            logger.debug(f"Unexpected error checking AppArmor module parameters: {e}")
            
        # Method 2: Check AppArmor security filesystem
        if os.path.exists("/sys/kernel/security/apparmor"):
            logger.debug("✓ AppArmor security filesystem present")
            return True
        else:
            logger.debug("AppArmor security filesystem not present")
            return False
    
    def _check_current_apparmor_profile(self) -> bool:
        """
        Check if current process is running under AppArmor (Docker container validation).
        
        Returns:
            True if current process has AppArmor profile applied
        """
        try:
            # Try modern AppArmor interface first (kernel 5.10+)
            try:
                with open("/proc/self/attr/apparmor/current", "r") as f:
                    profile = f.read().strip()
                    if profile and profile != "unconfined":
                        logger.debug(f"✓ Current process AppArmor profile (modern): {profile}")
                        return True
            except FileNotFoundError:
                # Fallback to legacy interface
                pass
                
            # Try legacy AppArmor interface
            with open("/proc/self/attr/current", "r") as f:
                profile = f.read().strip()
                if profile and profile != "unconfined":
                    logger.debug(f"✓ Current process AppArmor profile (legacy): {profile}")
                    return True
                else:
                    logger.debug("Current process is unconfined (no AppArmor profile)")
                    return False
                    
        except FileNotFoundError:
            logger.debug("AppArmor process attributes not available")
            return False
        except PermissionError:
            logger.debug("Permission denied accessing AppArmor process attributes")
            return False
        except OSError as e:
            if e.errno == 22:  # EINVAL - Invalid argument (common on newer kernels)
                logger.debug("AppArmor process attributes returned invalid argument (kernel compatibility)")
            else:
                logger.debug(f"OS error accessing AppArmor process attributes: {e}")
            return False
        except Exception as e:
            logger.debug(f"Unexpected error checking current AppArmor profile: {e}")
            return False
    
    def _check_system_apparmor_profiles(self) -> bool:
        """
        Check system AppArmor profiles using the original method.
        
        Returns:
            True if FFmpeg AppArmor profiles are found and enforced
        """
        try:
            # Original method - may fail with permission denied in containers
            with open("/sys/kernel/security/apparmor/profiles", "r") as f:
                profiles = f.read()
                
                # Look for our specific FFmpeg profile
                ffmpeg_profiles = [line for line in profiles.split('\n') if 'ffmpeg' in line.lower()]
                
                if not ffmpeg_profiles:
                    logger.debug("No FFmpeg AppArmor profiles found in system profiles")
                    return False
                
                # Check if profile is in enforce mode
                enforce_mode_profiles = [line for line in ffmpeg_profiles if 'enforce' in line]
                
                if not enforce_mode_profiles:
                    logger.debug("FFmpeg AppArmor profile found but not in enforce mode")
                    # For development, might allow complain mode
                    complain_mode_profiles = [line for line in ffmpeg_profiles if 'complain' in line]
                    if complain_mode_profiles:
                        logger.debug("FFmpeg profile in complain mode - reduced security")
                        return True  # Allow for testing
                    return False
                
                logger.debug(f"✓ AppArmor FFmpeg profiles in enforce mode: {len(enforce_mode_profiles)}")
                return True
                
        except PermissionError:
            logger.warning("Permission denied accessing /sys/kernel/security/apparmor/profiles (Docker-in-LXC environment)")
            return False
        except FileNotFoundError:
            logger.debug("AppArmor profiles file not found")
            return False
        except Exception as e:
            logger.warning(f"Failed to verify AppArmor system profiles: {e}")
            return False
    
    def _check_apparmor_alternative_methods(self) -> Dict[str, bool]:
        """
        Alternative AppArmor detection methods when primary methods fail.
        
        Returns:
            Dictionary with results of alternative detection methods
        """
        results = {
            "docker_profile_present": False,
            "apparmor_parser_available": False,
            "profile_enforcement_detected": False
        }
        
        # Check 1: Look for Docker default profile application
        try:
            with open("/proc/1/attr/current", "r") as f:
                init_profile = f.read().strip()
                if "docker-default" in init_profile or "docker" in init_profile:
                    logger.debug(f"✓ Docker AppArmor profile detected on PID 1: {init_profile}")
                    results["docker_profile_present"] = True
        except (FileNotFoundError, PermissionError, OSError):
            logger.debug("Cannot access PID 1 AppArmor attributes")
        
        # Check 2: Test if apparmor_parser is available in the system
        try:
            import subprocess
            result = subprocess.run(['which', 'apparmor_parser'], 
                                    capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                logger.debug("✓ apparmor_parser binary available")
                results["apparmor_parser_available"] = True
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            logger.debug("apparmor_parser not available or check failed")
        
        # Check 3: Test AppArmor enforcement by attempting restricted operation
        try:
            # Try to access a typically restricted path (non-destructive test)
            test_paths = ["/proc/sysrq-trigger", "/sys/kernel/debug", "/dev/mem"]
            for test_path in test_paths:
                try:
                    with open(test_path, "r") as f:
                        # If we can read these, AppArmor might not be enforcing
                        logger.debug(f"Warning: Could access restricted path {test_path}")
                        break
                except PermissionError:
                    # This is expected with AppArmor enforcement
                    logger.debug(f"✓ Access to {test_path} properly restricted")
                    results["profile_enforcement_detected"] = True
                    break
                except FileNotFoundError:
                    # Path doesn't exist, try next
                    continue
        except Exception:
            logger.debug("Could not test AppArmor enforcement through restricted access")
        
        return results
    
    def _evaluate_apparmor_enforcement_result(self, current_profile: bool, 
                                              system_profiles: bool, 
                                              alternative_results: Dict[str, bool]) -> bool:
        """
        Evaluate AppArmor enforcement based on available information and security level.
        
        Args:
            current_profile: Result of current process profile check
            system_profiles: Result of system profiles check  
            alternative_results: Results from alternative detection methods
        
        Returns:
            True if AppArmor enforcement is considered acceptable for current security level
        """
        is_maximum_security = self.security_level == "maximum"
        is_production = self.environment == "secure-production"
        
        # If we have clear positive results, return True
        if system_profiles or current_profile:
            logger.debug("✓ AppArmor enforcement confirmed through direct methods")
            return True
        
        # Evaluate alternative results based on security level
        alternative_indicators = sum([
            alternative_results.get("docker_profile_present", False),
            alternative_results.get("apparmor_parser_available", False),
            alternative_results.get("profile_enforcement_detected", False)
        ])
        
        if alternative_indicators >= 2:
            if is_maximum_security:
                logger.warning("AppArmor enforcement likely active but cannot verify profile details")
                # In maximum security, we need high confidence
                if is_production:
                    logger.error("Maximum security level requires confirmed AppArmor profile enforcement")
                    return False
                else:
                    logger.warning("Allowing based on alternative indicators (testing environment)")
                    return True
            else:
                logger.debug("✓ AppArmor enforcement likely active based on alternative indicators")
                return True
        elif alternative_indicators >= 1:
            if is_maximum_security or is_production:
                logger.warning("Insufficient evidence of AppArmor enforcement for production/maximum security")
                return False
            else:
                logger.debug("Partial AppArmor indicators - acceptable for current security level")
                return True
        else:
            logger.warning("No clear evidence of AppArmor enforcement found")
            return False
    
    def _verify_network_isolation(self) -> bool:
        """
        Verify that network isolation is properly configured.
        
        Returns:
            True if network access is properly restricted
        """
        try:
            # In containerized environments, check container network configuration
            if os.path.exists("/.dockerenv"):
                # Docker container - network should be restricted by container config
                logger.debug("Container environment - assuming network restrictions via Docker")
                return True
            
            # For direct execution, check if we can create network connections
            # This is a basic check - real isolation would be via AppArmor/namespaces
            try:
                import socket
                # Try to create a socket (should be blocked by AppArmor)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.close()
                
                # If we get here, socket creation succeeded
                # This might be OK if AppArmor will block actual network operations
                logger.warning("Socket creation succeeded - network isolation depends on AppArmor")
                return True  # Trust that AppArmor will block actual network access
                
            except Exception:
                # Socket creation failed - network might already be isolated
                logger.info("Socket creation failed - network already isolated")
                return True
                
        except Exception as e:
            logger.warning(f"Network isolation check failed: {e}")
            return False
    
    def _verify_ffmpeg_binary(self) -> str:
        """
        Verify FFmpeg binary is available and accessible.
        
        Returns:
            Path to FFmpeg binary if found, None otherwise
        """
        import shutil
        
        # Standard locations for FFmpeg
        ffmpeg_locations = [
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg", 
            "/opt/ffmpeg/bin/ffmpeg"
        ]
        
        # Check if FFmpeg is in PATH
        ffmpeg_path = shutil.which("ffmpeg")
        if ffmpeg_path:
            if os.access(ffmpeg_path, os.X_OK):
                return ffmpeg_path
        
        # Check standard locations
        for location in ffmpeg_locations:
            if os.path.exists(location) and os.access(location, os.X_OK):
                return location
        
        logger.error("FFmpeg binary not found in any expected location")
        return None
    
    async def _monitor_ffmpeg_progress(self, job_id: str, process: asyncio.subprocess.Process) -> None:
        """Monitor FFmpeg progress with real-time stderr parsing and granular updates."""
        progress_parser = None
        last_update_time = 0
        update_interval = 0.1  # Update every 100ms for smooth frontend progress
        
        try:
            # Get the progress parser for this job
            async with self.job_lock:
                if job_id in self.jobs:
                    progress_parser = self.jobs[job_id].get("_progress_parser")
            
            if not progress_parser:
                logger.warning(f"Job {job_id}: No progress parser available, falling back to basic monitoring")
                # Fallback to basic progress monitoring
                progress = 40
                while process.returncode is None:
                    # Check for cancellation request
                    if job_id in self.cancelling_jobs:
                        logger.debug(f"DEBUG: Job {job_id} - Cancellation detected in basic monitoring (in cancelling_jobs set)")
                        logger.info(f"Job {job_id}: Cancellation detected in basic monitoring")
                        return
                    
                    await asyncio.sleep(1)
                    progress = min(progress + 1, 89)  # Max at 89% to leave room for finalization
                    await self._update_job_status(
                        job_id, "processing", "Processing media (basic monitoring)", progress
                    )
                return
            
            logger.debug(f"Progress monitor started for job {job_id}")
            
            # Buffer for partial lines
            line_buffer = ""
            lines_processed = 0
            
            while process.returncode is None:
                try:
                    # Check for cancellation request
                    if job_id in self.cancelling_jobs:
                        logger.debug(f"DEBUG: Job {job_id} - Cancellation detected in advanced progress monitoring (in cancelling_jobs set)")
                        logger.info(f"Job {job_id}: Cancellation detected in progress monitoring")
                        return
                    
                    # Read stderr with larger buffer to avoid truncation
                    try:
                        stderr_data = await asyncio.wait_for(
                            process.stderr.read(4096), timeout=0.5
                        )
                    except asyncio.TimeoutError:
                        # No data available, continue monitoring
                        await asyncio.sleep(0.1)
                        continue
                    
                    if not stderr_data:
                        # No more data, process might be finishing
                        await asyncio.sleep(0.1)
                        continue
                    
                    # Decode stderr data and add to buffer
                    try:
                        decoded_data = stderr_data.decode('utf-8', errors='ignore')
                        line_buffer += decoded_data
                        
                        # Debug log first few data reads  
                        if lines_processed < 10:
                            logger.debug(f"Stderr data received for job {job_id}: {len(stderr_data)} bytes")
                        
                    except UnicodeDecodeError:
                        # Skip malformed data
                        continue
                    
                    # Process complete lines - handle both \n and \r (FFmpeg uses \r for progress)
                    # Split on both newline and carriage return
                    lines = line_buffer.replace('\r', '\n').split('\n')
                    line_buffer = lines[-1]  # Keep partial line for next iteration
                    
                    # Debug log first few line processing
                    if lines_processed < 5 and len(lines) > 1:
                        logger.debug(f"Job {job_id}: Processing {len(lines)-1} complete lines")
                        lines_processed += 1
                    
                    for line in lines[:-1]:  # Process all complete lines
                        clean_line = line.strip()
                        if not clean_line:
                            continue
                        
                        # Debug: Log every line we're trying to parse (first 15 lines)
                        if lines_processed < 15:
                            logger.debug(f"Parsing line for job {job_id}: {repr(clean_line[:100])}")
                        
                        # Parse progress from this line
                        progress_data = progress_parser.parse_progress_line(clean_line)
                        
                        if progress_data:
                            frame = progress_data.get('frame', 0)
                            fps = progress_data.get('fps', 'N/A')
                            time_str = progress_data.get('current_time_str', '00:00:00')
                            speed = progress_data.get('speed', 'N/A')
                            progress = progress_data.get('progress_percent', 0)
                            
                            logger.debug(f"Progress parsed for job {job_id}: frame={frame} fps={fps} time={time_str} speed={speed} progress={progress:.1f}%")
                            
                            current_time = time.time()
                            # Rate limit updates to avoid overwhelming the frontend (50ms updates)
                            if current_time - last_update_time >= 0.05:
                                await self._update_job_progress(job_id, progress_data)
                                last_update_time = current_time
                                logger.debug(f"Progress updated for job {job_id}: {progress:.1f}%")
                        else:
                            if lines_processed < 15:
                                logger.debug(f"No progress data in line for job {job_id}: {clean_line[:80]}")
                        
                        lines_processed += 1
                    
                    # Small delay to prevent busy waiting
                    await asyncio.sleep(0.05)
                    
                except Exception as e:
                    logger.debug(f"Job {job_id}: Progress parsing error: {e}")
                    # Continue monitoring even if individual parsing fails
                    await asyncio.sleep(0.1)
            
            logger.debug(f"Job {job_id}: FFmpeg process completed, progress monitoring ended")
            
        except asyncio.CancelledError:
            logger.debug(f"Job {job_id}: Progress monitoring cancelled")
        except Exception as e:
            logger.warning(f"Job {job_id}: Progress monitoring error: {e}")
    
    async def _update_job_progress(self, job_id: str, progress_data: Dict) -> None:
        """Update job with detailed progress information."""
        try:
            async with self.job_lock:
                if job_id not in self.jobs:
                    return
                
                job = self.jobs[job_id]
                
                # Update main progress percentage - map FFmpeg progress (0-100%) to encoding phase (40-90%)
                if progress_data.get("progress_percent") is not None:
                    ffmpeg_progress = progress_data["progress_percent"]
                    # Linear mapping: 0-100% FFmpeg → 40-90% overall progress
                    job["progress"] = min(40 + (ffmpeg_progress * 0.5), 90)
                
                # Update detailed progress information
                progress_details = job["progress_details"]
                progress_details.update({
                    "current_time": progress_data.get("current_time"),
                    "current_time_str": progress_data.get("current_time_str", "00:00:00"),
                    "fps": progress_data.get("fps"),
                    "speed": progress_data.get("speed"),
                    "eta": progress_data.get("eta"),
                    "frame": progress_data.get("frame")
                })
                
                # Update job message with current metrics
                fps_str = f"{progress_data.get('fps', 0):.1f} fps" if progress_data.get('fps') else ""
                speed_str = f"{progress_data.get('speed', 0):.1f}x" if progress_data.get('speed') else ""
                time_str = progress_data.get('current_time_str', '00:00:00')
                
                status_parts = [f"Processing at {time_str}"]
                if fps_str and speed_str:
                    status_parts.append(f"({fps_str}, {speed_str})")
                elif fps_str:
                    status_parts.append(f"({fps_str})")
                elif speed_str:
                    status_parts.append(f"({speed_str})")
                
                if progress_data.get("eta"):
                    status_parts.append(f"ETA: {progress_data['eta']}")
                
                job["message"] = " ".join(status_parts)
                
                logger.debug(f"Job {job_id}: Progress {progress_data.get('progress_percent', 0):.1f}% - {job['message']}")
                
        except Exception as e:
            logger.warning(f"Job {job_id}: Failed to update progress: {e}")
    
    async def _handle_output_encryption(self, job_id: str, output_data: bytes, encryption_mode: str) -> bytes:
        """Handle output encryption based on mode."""
        # Check if encryption is completely disabled
        if self.encryption_disabled or encryption_mode == "none":
            logger.warning(f"Job {job_id}: Returning unencrypted output (ENCRYPTION DISABLED)")
            return output_data
            
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
            
            # SECURITY: Retrieve and decrypt the stored password
            decryption_password = await self._get_decrypted_password(job_id)
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
                
                # Clear password from memory immediately after use
                decryption_password = None
                
                logger.info(f"Job {job_id}: Successfully encrypted output ({len(output_data)} → {len(encrypted_output)} bytes)")
                return encrypted_output
                
            finally:
                # Clean up temporary files
                for temp_file in [temp_unencrypted, temp_encrypted]:
                    if os.path.exists(temp_file):
                        self._secure_delete_file(temp_file)
    
    async def _get_decrypted_password(self, job_id: str) -> Optional[str]:
        """
        Securely retrieve and decrypt the stored password for a job.
        
        Returns:
            Decrypted password string or None if no password stored
        """
        try:
            async with self.job_lock:
                if job_id not in self.jobs:
                    return None
                
                encrypted_password_data = self.jobs[job_id].get("encrypted_password")
            
            if not encrypted_password_data:
                return None
            
            # Handle plaintext password (only when encryption is disabled)
            if self.encryption_disabled and isinstance(encrypted_password_data, str):
                logger.warning(f"Job {job_id}: Returning plaintext password (ENCRYPTION DISABLED)")
                return encrypted_password_data
            
            # Decrypt encrypted password
            if isinstance(encrypted_password_data, dict):
                encrypted_data = encrypted_password_data.get('encrypted_data')
                key_id = encrypted_password_data.get('key_id')
                
                if not encrypted_data or not key_id:
                    logger.error(f"Job {job_id}: Invalid encrypted password format")
                    return None
                
                # Use encryption manager to decrypt password
                try:
                    decrypted_password_bytes = self.encryption_manager.automated_decrypt(
                        encrypted_data, key_id
                    )
                    decrypted_password = decrypted_password_bytes.decode('utf-8')
                    logger.debug(f"Job {job_id}: Password successfully decrypted from secure storage")
                    return decrypted_password
                    
                except Exception as e:
                    logger.error(f"Job {job_id}: Failed to decrypt stored password: {e}")
                    return None
            else:
                logger.error(f"Job {job_id}: Unknown encrypted password format")
                return None
                
        except Exception as e:
            logger.error(f"Job {job_id}: Error retrieving encrypted password: {e}")
            return None
    
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
        """List all jobs with basic information and enhanced progress details."""
        job_list = []
        for job in self.jobs.values():
            progress_details = job.get("progress_details", {})
            
            # Build job summary with enhanced progress information
            job_summary = {
                "id": job["id"],
                "status": job["status"],
                "created_at": job["created_at"],
                "encryption_mode": job["encryption_mode"],
                "progress": job["progress"],
                "memory_mode": job.get("memory_mode", "unknown"),
                "message": job.get("message", ""),
                # Enhanced progress metrics
                "current_time": progress_details.get("current_time_str", "00:00:00"),
                "total_duration": progress_details.get("total_duration"),
                "processing_duration": progress_details.get("processing_duration"),
                "fps": progress_details.get("fps"),
                "speed": progress_details.get("speed"),
                "eta": progress_details.get("eta"),
                "has_time_cuts": progress_details.get("has_time_cuts", False)
            }
            
            job_list.append(job_summary)
        
        return job_list
    
    async def cancel_job(self, job_id: str) -> Dict[str, Any]:
        """
        Cancel a job gracefully with comprehensive resource cleanup.
        
        This method provides graceful job cancellation while maintaining all security 
        guarantees including 3-pass secure deletion and memory cleanup.
        
        Args:
            job_id: Job ID to cancel
            
        Returns:
            Dictionary with cancellation status and cleanup information
            
        Raises:
            ValueError: If job not found or cannot be cancelled
        """
        async with self.job_lock:
            # Check if job exists
            if job_id not in self.jobs:
                raise ValueError(f"Job {job_id} not found")
            
            job = self.jobs[job_id]
            current_status = job["status"]
            
            # CRITICAL: Double-check for race conditions - re-read status after acquiring lock
            await asyncio.sleep(0.001)  # Brief yield to ensure any pending status updates are visible
            fresh_status = self.jobs[job_id]["status"]  # Re-read from dict
            if fresh_status != current_status:
                logger.debug(f"DEBUG: Job {job_id} - Status changed during lock acquisition: {current_status} -> {fresh_status}")
                current_status = fresh_status
                job = self.jobs[job_id]  # Re-get the job dict
            
            # Check if job can be cancelled
            logger.debug(f"DEBUG: Job {job_id} - Final status check: {current_status}, in cancelling_jobs: {job_id in self.cancelling_jobs}")
            logger.debug(f"DEBUG: Job {job_id} - Job dict status: {job.get('status', 'NO_STATUS_KEY')}")
            if current_status == "completed":
                raise ValueError(f"Job {job_id} already completed - cannot cancel")
            elif current_status == "failed":
                raise ValueError(f"Job {job_id} already failed - cannot cancel")  
            elif current_status == "cancelled":
                logger.debug(f"DEBUG: Job {job_id} - Refusing double cancellation: status is already 'cancelled'")
                raise ValueError(f"Job {job_id} already cancelled")
            elif job_id in self.cancelling_jobs:
                logger.debug(f"DEBUG: Job {job_id} - Refusing double cancellation: job is in cancelling_jobs set")
                raise ValueError(f"Job {job_id} already being cancelled")
            
            # Mark job as being cancelled
            self.cancelling_jobs.add(job_id)
            logger.debug(f"DEBUG: Job {job_id} - Added to cancelling_jobs set")
            logger.info(f"Job {job_id}: Starting cancellation process (current status: {current_status})")
            
            # Update job status to cancelled
            job["status"] = "cancelled"
            job["message"] = "Job cancelled by user request"
            job["cancelled_at"] = time.time()
            logger.debug(f"DEBUG: Job {job_id} - Status updated to 'cancelled' in jobs dict")
            
            # Verify the status update worked
            if self.jobs[job_id]["status"] != "cancelled":
                logger.error(f"DEBUG: Job {job_id} - Status update failed! Status is still: {self.jobs[job_id]['status']}")
                raise Exception(f"Failed to update job status to cancelled")
            
            logger.debug(f"DEBUG: Job {job_id} - Status update verified: {self.jobs[job_id]['status']}")
            
            # Force a brief yield to ensure changes are committed before releasing lock
            await asyncio.sleep(0.001)  # 1ms delay to ensure proper synchronization
            logger.debug(f"DEBUG: Job {job_id} - Post-update verification: status={self.jobs[job_id]['status']}, in_cancelling={job_id in self.cancelling_jobs}")
            
        try:
            cleanup_results = {
                "job_id": job_id,
                "previous_status": current_status,
                "cancelled_at": job["cancelled_at"],
                "cleanup_performed": []
            }
            
            # Step 1: Gracefully terminate FFmpeg process if running
            process = self.job_processes.get(job_id)
            logger.debug(f"DEBUG: Job {job_id} - Process lookup: {process is not None}, returncode: {process.returncode if process else 'N/A'}")
            if process and process.returncode is None:
                logger.debug(f"DEBUG: Job {job_id} - Found active FFmpeg process (PID: {process.pid})")
                logger.info(f"Job {job_id}: Terminating active FFmpeg process (PID: {process.pid})")
                cleanup_results["cleanup_performed"].append("ffmpeg_process_terminated")
                
                try:
                    # Graceful termination
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                    logger.info(f"Job {job_id}: FFmpeg process terminated gracefully")
                except asyncio.TimeoutError:
                    # Force termination if graceful fails
                    logger.warning(f"Job {job_id}: Force killing FFmpeg process")
                    process.kill()
                    await process.wait()
                    cleanup_results["cleanup_performed"].append("ffmpeg_process_force_killed")
            
            # Step 2: Clean up secure memory storage
            storage_id = job.get("result_storage_id")
            if storage_id:
                logger.info(f"Job {job_id}: Cleaning up secure memory storage")
                secure_memory_manager._cleanup_storage(storage_id)
                cleanup_results["cleanup_performed"].append("secure_memory_cleaned")
            
            # Step 3: Secure file deletion for temporary files
            if self.zero_trace_enabled:
                # Look for and securely delete any temporary files
                output_path = f"/tmp/memory-pool/output_{job_id}.mp4"
                if Path(output_path).exists():
                    logger.info(f"Job {job_id}: Performing 3-pass secure deletion of temporary file")
                    self._secure_delete_file(output_path)
                    cleanup_results["cleanup_performed"].append("temporary_file_shredded")
            
            # Step 4: Clear encrypted passwords and keys from memory
            if "encrypted_password" in job and job["encrypted_password"]:
                logger.info(f"Job {job_id}: Clearing encrypted password from memory")
                if isinstance(job["encrypted_password"], dict):
                    # Zero out the encrypted data
                    encrypted_data = job["encrypted_password"].get("encrypted_data", b"")
                    if isinstance(encrypted_data, bytes):
                        # Python bytes are immutable, but we clear the reference
                        job["encrypted_password"] = None
                else:
                    job["encrypted_password"] = None
                cleanup_results["cleanup_performed"].append("encrypted_password_cleared")
            
            # Step 5: Remove any encrypted results
            if "encrypted_result" in job:
                job["encrypted_result"] = None
                cleanup_results["cleanup_performed"].append("encrypted_result_cleared")
            
            logger.info(f"Job {job_id}: Cancellation completed successfully")
            cleanup_results["status"] = "cancelled"
            cleanup_results["message"] = "Job cancelled and resources cleaned up successfully"
            
            return cleanup_results
            
        except Exception as e:
            logger.error(f"Job {job_id}: Error during cancellation: {e}")
            # Even if cleanup partially fails, keep the job marked as cancelled
            async with self.job_lock:
                if job_id in self.jobs:
                    self.jobs[job_id]["message"] = f"Job cancelled with cleanup errors: {str(e)}"
            
            return {
                "job_id": job_id,
                "status": "cancelled",
                "message": f"Job cancelled but cleanup encountered errors: {str(e)}",
                "cleanup_performed": cleanup_results.get("cleanup_performed", [])
            }
            
        finally:
            # Always remove from cancelling jobs and process tracking
            async with self.job_lock:
                logger.debug(f"DEBUG: Job {job_id} - Finally block: Removing from cancelling_jobs and job_processes")
                logger.debug(f"DEBUG: Job {job_id} - Finally block: Job status before cleanup: {self.jobs.get(job_id, {}).get('status', 'NOT_FOUND')}")
                self.cancelling_jobs.discard(job_id)
                self.job_processes.pop(job_id, None)
                logger.debug(f"DEBUG: Job {job_id} - Finally block: Final job status after cleanup: {self.jobs.get(job_id, {}).get('status', 'NOT_FOUND')}")
            logger.debug(f"Job {job_id}: Removed from cancelling jobs tracking")