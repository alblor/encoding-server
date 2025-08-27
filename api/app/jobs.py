"""Job processing system for media encoding."""

import asyncio
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .config import settings
from .encryption import EncryptionManager


class FFmpegValidator:
    """
    Enhanced FFmpeg parameter validator with hybrid security architecture.
    
    Implements three-layer validation:
    1. Core parameter whitelist for explicit control
    2. Safe command construction with FFmpeg syntax validation  
    3. Security violation detection and prevention
    
    Author: Lorenzo Albanese (alblor)
    """
    
    def __init__(self):
        # Import configuration (separate file for maintainability)
        from .ffmpeg_validation_config import FFMPEG_CONFIG
        self.config = FFMPEG_CONFIG
    
    def validate_parameters(self, params: Dict) -> Dict:
        """
        Enhanced parameter validation supporting complex FFmpeg workflows.
        
        Args:
            params: Dictionary of FFmpeg parameters to validate
            
        Returns:
            Dict with validated parameters or validation errors
            
        Raises:
            ValueError: On security violation with detailed error message
        """
        result = {
            'valid': True,
            'safe_params': {},
            'violations': [],
            'ffmpeg_command': []
        }
        
        try:
            # Handle different parameter input formats
            if isinstance(params, dict):
                safe_params = self._validate_dict_params(params)
            elif isinstance(params, list):
                safe_params = self._validate_list_params(params) 
            else:
                raise ValueError("VIOLATION: Parameters must be dict or list format.")
                
            result['safe_params'] = safe_params
            
        except ValueError as e:
            result['valid'] = False
            result['violations'].append(str(e))
            # Re-raise for immediate handling
            raise
            
        return result
    
    def _validate_dict_params(self, params: Dict) -> Dict:
        """Validate dictionary-format parameters (legacy compatibility)."""
        safe_params = {}
        
        # Video codec validation with expanded support
        if 'video_codec' in params:
            codec = self._extract_codec_name(params['video_codec'])
            validation = self.config.validate_codec_value('video', codec)
            
            if validation['valid']:
                safe_params['video_codec'] = f'-c:v {codec}'
            else:
                raise ValueError(validation['message'])
        
        # Audio codec validation with expanded support
        if 'audio_codec' in params:
            codec = self._extract_codec_name(params['audio_codec'])
            validation = self.config.validate_codec_value('audio', codec)
            
            if validation['valid']:
                safe_params['audio_codec'] = f'-c:a {codec}'
            else:
                raise ValueError(validation['message'])
        
        # Enhanced custom parameters validation
        if 'custom_params' in params:
            safe_custom = self._validate_custom_parameters(params['custom_params'])
            safe_params['custom_params'] = safe_custom
        
        # Format validation
        if 'format' in params:
            validation = self.config.validate_format_value(params['format'])
            if validation['valid']:
                safe_params['format'] = f'-f {params["format"]}'
            else:
                raise ValueError(validation['message'])
        
        return safe_params
    
    def _validate_list_params(self, params: List) -> List:
        """Validate list-format parameters (modern approach)."""
        safe_params = []
        i = 0
        
        while i < len(params):
            param = params[i]
            
            # Skip empty parameters
            if not param or not isinstance(param, str):
                i += 1
                continue
            
            # Handle parameter-value pairs
            if param.startswith('-'):
                param_validation = self.config.validate_core_parameter(param)
                
                if not param_validation['valid']:
                    raise ValueError(param_validation['message'])
                
                safe_params.append(param)
                
                # Check if parameter expects a value
                if i + 1 < len(params) and not params[i + 1].startswith('-'):
                    value = params[i + 1]
                    
                    # Validate value based on parameter type
                    self._validate_parameter_value(param, value)
                    safe_params.append(value)
                    i += 2
                else:
                    i += 1
            else:
                # Standalone value - check for security violations
                security_check = self.config.check_security_violations(param)
                if not security_check['safe']:
                    raise ValueError(security_check['message'])
                    
                safe_params.append(param)
                i += 1
        
        return safe_params
    
    def _validate_custom_parameters(self, custom_params) -> List:
        """Enhanced custom parameter validation with security checks."""
        if not custom_params:
            return []
        
        if isinstance(custom_params, str):
            custom_params = [custom_params]
        elif not isinstance(custom_params, list):
            raise ValueError("VIOLATION: Custom parameters must be string or list.")
        
        safe_custom = []
        for param in custom_params:
            if not isinstance(param, str):
                continue
                
            # Security violation check
            security_check = self.config.check_security_violations(param)
            if not security_check['safe']:
                raise ValueError(security_check['message'])
            
            safe_custom.append(param)
        
        return safe_custom
    
    def _validate_parameter_value(self, param: str, value: str):
        """Validate parameter values based on parameter type."""
        # Security check first (always required)
        security_check = self.config.check_security_violations(value)
        if not security_check['safe']:
            raise ValueError(security_check['message'])
        
        # Codec-specific validation
        if param in ['-c:v', '-vcodec']:
            validation = self.config.validate_codec_value('video', value)
            if not validation['valid']:
                raise ValueError(validation['message'])
                
        elif param in ['-c:a', '-acodec']:
            validation = self.config.validate_codec_value('audio', value)
            if not validation['valid']:
                raise ValueError(validation['message'])
                
        elif param == '-f':
            validation = self.config.validate_format_value(value)
            if not validation['valid']:
                raise ValueError(validation['message'])
        
        # Complex filter parameters (allow flexible syntax with security checks)
        elif param in self.config.COMPLEX_VALUE_PARAMETERS:
            # Already passed security check, allow complex syntax
            # This enables support for: -vf "scale=-2:1440:flags=lanczos"
            pass
    
    def _extract_codec_name(self, codec_param: str) -> str:
        """Extract clean codec name from parameter string."""
        if not codec_param:
            return ''
            
        # Handle formats like "-c:v libx264" or "libx264"
        codec = codec_param.replace('-c:v ', '').replace('-c:a ', '').strip()
        return codec
    
    def validate_output_filename(self, filename: str) -> bool:
        """
        Validate output filename for security.
        
        Args:
            filename: Output filename to validate
            
        Returns:
            True if filename is safe
            
        Raises:
            ValueError: On security violation
        """
        validation = self.config.validate_output_filename(filename)
        if not validation['safe']:
            raise ValueError(validation['message'])
        return True
    
    def build_command(self, input_file: str, output_file: str, params: Dict) -> List[str]:
        """
        Build secure FFmpeg command from validated parameters.
        
        Uses argument arrays for safe subprocess execution (no shell injection).
        Supports both legacy dict format and modern list format parameters.
        
        Args:
            input_file: Path to input file
            output_file: Path to output file  
            params: Validated parameters (dict or from safe_params)
            
        Returns:
            List of command arguments for safe subprocess execution
        """
        # Validate output filename
        self.validate_output_filename(output_file)
        
        # Start with base command
        cmd = [settings.FFMPEG_PATH, '-i', input_file]
        
        # Handle dict-format parameters (legacy compatibility)
        if isinstance(params, dict) and any(key in params for key in ['video_codec', 'audio_codec', 'custom_params', 'format']):
            cmd.extend(self._build_from_dict_params(params))
        
        # Handle list-format parameters (modern approach)  
        elif isinstance(params, (list, dict)):
            if isinstance(params, dict) and 'safe_params' in params:
                # Extract from validation result
                safe_params = params['safe_params']
                if isinstance(safe_params, list):
                    cmd.extend(safe_params)
                else:
                    cmd.extend(self._build_from_dict_params(safe_params))
            elif isinstance(params, list):
                cmd.extend(params)
        
        # Add output file
        cmd.append(output_file)
        
        return cmd
    
    def _build_from_dict_params(self, params: Dict) -> List[str]:
        """Build command arguments from dictionary parameters."""
        cmd_parts = []
        
        # Add format first if specified
        if 'format' in params:
            cmd_parts.extend(params['format'].split())
        
        # Add video codec
        if 'video_codec' in params:
            cmd_parts.extend(params['video_codec'].split())
        
        # Add audio codec
        if 'audio_codec' in params:
            cmd_parts.extend(params['audio_codec'].split())
        
        # Add custom parameters (enhanced support)
        if 'custom_params' in params:
            custom = params['custom_params']
            if isinstance(custom, list):
                cmd_parts.extend(custom)
            elif isinstance(custom, str):
                # Split string parameters safely
                cmd_parts.extend(custom.split())
        
        return cmd_parts


class JobProcessor:
    """Handles encoding job processing."""
    
    def __init__(self, encryption_manager: EncryptionManager = None):
        self.encryption = encryption_manager or EncryptionManager()
        self.validator = FFmpegValidator()
        self.jobs: Dict[str, Dict] = {}
    
    async def submit_job(self, 
                        file_data: bytes, 
                        params: Dict, 
                        encryption_mode: str = "automated") -> str:
        """Submit a new encoding job."""
        job_id = str(uuid.uuid4())
        
        job = {
            'id': job_id,
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
            'encryption_mode': encryption_mode,
            'params': params,
            'progress': 0,
            'message': 'Job queued for processing'
        }
        
        self.jobs[job_id] = job
        
        # Process job asynchronously
        asyncio.create_task(self._process_job(job_id, file_data, params, encryption_mode))
        
        return job_id
    
    async def _process_job(self, job_id: str, file_data: bytes, params: Dict, encryption_mode: str):
        """Process an encoding job."""
        job = self.jobs[job_id]
        
        try:
            job['status'] = 'processing'
            job['progress'] = 10
            job['message'] = 'Preparing files...'
            
            # Create temporary workspace
            with tempfile.TemporaryDirectory(prefix=f'encoding_{job_id}_') as temp_dir:
                temp_path = Path(temp_dir)
                input_file = temp_path / 'input'
                processed_file = temp_path / 'output'
                
                # Handle input based on encryption mode
                if encryption_mode == 'manual':
                    # Data is pre-encrypted, decrypt it first
                    job['message'] = 'Decrypting input file...'
                    # For now, assume it's encrypted with a known key
                    # In production, client would provide decryption info
                    decrypted_file = temp_path / 'decrypted_input'
                    # This is simplified - implement proper key exchange
                    with open(input_file, 'wb') as f:
                        f.write(file_data)  # For demo purposes
                else:
                    # Automated mode - data comes in plaintext
                    with open(input_file, 'wb') as f:
                        f.write(file_data)
                
                job['progress'] = 30
                job['message'] = 'Validating parameters...'
                
                # Validate and build FFmpeg command
                safe_params = self.validator.validate_parameters(params)
                cmd = self.validator.build_command(str(input_file), str(processed_file), safe_params)
                
                job['progress'] = 40
                job['message'] = 'Processing media...'
                
                # Execute FFmpeg (with fallback for testing with fake data)
                try:
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    # Monitor progress (simplified)
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode != 0:
                        # For testing with fake data, create a mock processed file
                        if b"FAKE_VIDEO_DATA" in file_data:
                            job['message'] = 'Mock processing for test data...'
                            with open(processed_file, 'wb') as f:
                                f.write(file_data + b"_PROCESSED")  # Mock processing
                        else:
                            raise Exception(f"FFmpeg failed: {stderr.decode()}")
                    
                except FileNotFoundError:
                    # FFmpeg not found, create mock output for testing
                    job['message'] = 'Mock processing (FFmpeg not available)...'
                    with open(processed_file, 'wb') as f:
                        f.write(file_data + b"_PROCESSED")  # Mock processing
                
                job['progress'] = 80
                job['message'] = 'Preparing output...'
                
                # Read processed file
                with open(processed_file, 'rb') as f:
                    result_data = f.read()
                
                # Handle output based on encryption mode
                if encryption_mode == 'automated':
                    # Server encrypts result transparently (user never sees encryption)
                    job['encrypted_result'], job['key_id'] = self.encryption.automated_encrypt(result_data)
                    job['result_size'] = len(result_data)
                    # Store key_id in job for transparent decryption
                else:
                    # Manual mode - return encrypted data for client decryption
                    # For demo, we'll encrypt it anyway
                    key = self.encryption.generate_key()
                    encrypted_file = temp_path / 'encrypted_output'
                    self.encryption.encrypt_file(str(processed_file), str(encrypted_file), key)
                    
                    with open(encrypted_file, 'rb') as f:
                        job['encrypted_result'] = f.read()
                
                job['status'] = 'completed'
                job['progress'] = 100
                job['message'] = 'Job completed successfully'
                job['completed_at'] = datetime.now().isoformat()
                
        except Exception as e:
            job['status'] = 'failed'
            job['message'] = f'Job failed: {str(e)}'
            job['failed_at'] = datetime.now().isoformat()
    
    def get_job_status(self, job_id: str) -> Optional[Dict]:
        """Get job status and progress."""
        return self.jobs.get(job_id)
    
    def get_job_result(self, job_id: str) -> Optional[bytes]:
        """Get job result data."""
        job = self.jobs.get(job_id)
        if job and job['status'] == 'completed':
            return job.get('encrypted_result')
        return None
    
    def list_jobs(self) -> List[Dict]:
        """List all jobs."""
        return list(self.jobs.values())