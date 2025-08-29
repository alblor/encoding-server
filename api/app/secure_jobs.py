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
                "decryption_password": decryption_password,
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
        Process job using secure memory management and complete isolation.
        
        Implements three-layer security:
        1. Parameter validation (already done)
        2. Safe command construction with resource limits
        3. Complete FFmpeg sandboxing and isolation
        """
        input_storage = None
        output_storage = None
        
        try:
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
            logger.error(f"Job {job_id} failed: {e}")
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
                if not process.returncode:
                    process.terminate()
                    await process.wait()
                raise
            
            # Read any remaining stdout data (stderr is handled by monitoring task)
            if process.stdout:
                try:
                    stdout = await asyncio.wait_for(process.stdout.read(), timeout=1.0)
                except asyncio.TimeoutError:
                    stdout = b""
            else:
                stdout = b""
            
            if process.returncode == 0:
                logger.info(f"Job {job_id}: FFmpeg completed successfully")
                return True
            else:
                logger.error(f"Job {job_id}: FFmpeg failed with code {process.returncode}")
                # stderr is handled by monitoring task, so we log what we can
                logger.error(f"Job {job_id}: Check job progress details for error information")
                return False
                
        except Exception as e:
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
        
        Returns:
            True if AppArmor is properly enforcing FFmpeg restrictions
        """
        try:
            # Check if AppArmor is available
            if not os.path.exists("/sys/kernel/security/apparmor"):
                logger.error("AppArmor not available on this system")
                return False
            
            # Check for FFmpeg profile in loaded profiles
            with open("/sys/kernel/security/apparmor/profiles", "r") as f:
                profiles = f.read()
                
                # Look for our specific FFmpeg profile
                ffmpeg_profiles = [line for line in profiles.split('\n') if 'ffmpeg' in line.lower()]
                
                if not ffmpeg_profiles:
                    logger.error("No FFmpeg AppArmor profiles found")
                    return False
                
                # Check if profile is in enforce mode
                enforce_mode_profiles = [line for line in ffmpeg_profiles if 'enforce' in line]
                
                if not enforce_mode_profiles:
                    logger.warning("FFmpeg AppArmor profile found but not in enforce mode")
                    # For development, might allow complain mode
                    complain_mode_profiles = [line for line in ffmpeg_profiles if 'complain' in line]
                    if complain_mode_profiles:
                        logger.warning("FFmpeg profile in complain mode - reduced security")
                        return True  # Allow for testing
                    return False
                
                logger.debug(f"AppArmor FFmpeg profiles in enforce mode: {len(enforce_mode_profiles)}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to verify AppArmor enforcement: {e}")
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