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
    """Validates and sanitizes FFmpeg parameters."""
    
    # Whitelist of allowed codecs and parameters
    ALLOWED_VIDEO_CODECS = ['libx264', 'libx265', 'libvpx-vp9', 'copy']
    ALLOWED_AUDIO_CODECS = ['aac', 'mp3', 'libopus', 'copy']
    ALLOWED_FORMATS = ['mp4', 'mkv', 'webm', 'avi']
    
    # Blocked dangerous parameters
    BLOCKED_PATTERNS = [';', '&&', '||', '`', '$', 'rm ', 'wget', 'curl', '/etc/', '/proc/', '../']
    
    def validate_parameters(self, params: Dict) -> Dict:
        """Validate and sanitize FFmpeg parameters."""
        safe_params = {}
        
        # Video codec validation
        if 'video_codec' in params:
            codec = params['video_codec'].replace('-c:v ', '').strip()
            if codec in self.ALLOWED_VIDEO_CODECS:
                safe_params['video_codec'] = f'-c:v {codec}'
        
        # Audio codec validation  
        if 'audio_codec' in params:
            codec = params['audio_codec'].replace('-c:a ', '').strip()
            if codec in self.ALLOWED_AUDIO_CODECS:
                safe_params['audio_codec'] = f'-c:a {codec}'
        
        # Custom parameters (basic validation)
        if 'custom_params' in params:
            custom = params['custom_params']
            if isinstance(custom, list):
                safe_custom = []
                for param in custom:
                    if not any(blocked in param for blocked in self.BLOCKED_PATTERNS):
                        safe_custom.append(param)
                safe_params['custom_params'] = safe_custom
        
        return safe_params
    
    def build_command(self, input_file: str, output_file: str, params: Dict) -> List[str]:
        """Build FFmpeg command from validated parameters."""
        cmd = [settings.FFMPEG_PATH, '-i', input_file]
        
        # Add video codec
        if 'video_codec' in params:
            cmd.extend(params['video_codec'].split())
        
        # Add audio codec
        if 'audio_codec' in params:
            cmd.extend(params['audio_codec'].split())
        
        # Add custom parameters
        if 'custom_params' in params:
            cmd.extend(params['custom_params'])
        
        # Add output file
        cmd.append(output_file)
        
        return cmd


class JobProcessor:
    """Handles encoding job processing."""
    
    def __init__(self):
        self.encryption = EncryptionManager()
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
                
                # Execute FFmpeg
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Monitor progress (simplified)
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    raise Exception(f"FFmpeg failed: {stderr.decode()}")
                
                job['progress'] = 80
                job['message'] = 'Preparing output...'
                
                # Read processed file
                with open(processed_file, 'rb') as f:
                    result_data = f.read()
                
                # Handle output based on encryption mode
                if encryption_mode == 'automated':
                    # Server encrypts result transparently
                    job['encrypted_result'], job['key_id'] = self.encryption.automated_encrypt(result_data)
                    job['result_size'] = len(result_data)
                else:
                    # Manual mode - return encrypted data
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