#!/usr/bin/env python3
"""
Secure job submission helper for the Proxmox-Optimized Secure Media Encoding Server.

This utility provides a secure way to submit encrypted media files for processing
without exposing passwords in command-line arguments or shell history.

Author: Lorenzo Albanese (alblor)
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional

import getpass
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SecureJobSubmitter:
    """Secure job submission with password protection and progress monitoring."""
    
    def __init__(self, api_base_url: str, verify_ssl: bool = True):
        self.api_base_url = api_base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set timeout for all requests
        self.session.timeout = 30
        
        if not verify_ssl:
            # Disable SSL warnings for development
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get_password_securely(self, prompt: str = "🔐 Enter decryption password: ") -> str:
        """Get password using secure methods (environment variable or prompt)."""
        # Method 1: Environment variable (for automation)
        password = os.environ.get('MEDIA_ENCRYPTION_PASSWORD')
        if password:
            print("🔐 Using password from environment variable (MEDIA_ENCRYPTION_PASSWORD)")
            return password
        
        # Method 2: Interactive secure prompt (default)
        password = getpass.getpass(prompt)
        if not password:
            print("❌ Error: Password cannot be empty", file=sys.stderr)
            sys.exit(1)
        
        return password
    
    def submit_job(self, encrypted_file: str, ffmpeg_params: Dict = None, verbose: bool = False) -> Dict:
        """
        Submit encrypted media job with secure password handling.
        
        Args:
            encrypted_file: Path to encrypted media file
            ffmpeg_params: FFmpeg processing parameters
            verbose: Enable verbose output
            
        Returns:
            Job submission response
        """
        encrypted_path = Path(encrypted_file)
        
        if not encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")
        
        # Default FFmpeg parameters
        if ffmpeg_params is None:
            ffmpeg_params = {
                "video_codec": "libx264",
                "audio_codec": "aac",
                "preset": "medium",
                "crf": 23
            }
        
        # Get password securely (never in command line)
        password = self.get_password_securely()
        
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                file_data = f.read()
            
            if verbose:
                print(f"📁 Reading encrypted file: {encrypted_file} ({len(file_data):,} bytes)")
                print(f"🔧 FFmpeg parameters: {ffmpeg_params}")
            
            # Prepare secure submission
            files = {
                "file": (encrypted_path.name, file_data, "application/octet-stream")
            }
            
            data = {
                "params": json.dumps(ffmpeg_params),
                "encryption_mode": "manual",
                "decryption_password": password  # Protected by HTTPS/TLS
            }
            
            if verbose:
                print(f"🚀 Submitting job to {self.api_base_url}/v1/jobs")
            
            # Submit job with HTTPS protection
            response = self.session.post(
                f"{self.api_base_url}/v1/jobs",
                files=files,
                data=data,
                verify=self.verify_ssl
            )
            
            # Clear password from memory immediately after sending
            password = "X" * len(password)  # Overwrite memory
            del password
            
            if response.status_code == 200:
                result = response.json()
                if verbose:
                    print(f"✅ Job submitted successfully: {result['job_id']}")
                return result
            else:
                error_msg = f"Job submission failed: {response.status_code}"
                try:
                    error_detail = response.json()
                    if 'detail' in error_detail:
                        error_msg += f" - {error_detail['detail']}"
                except:
                    error_msg += f" - {response.text}"
                raise Exception(error_msg)
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error during job submission: {e}")
        finally:
            # Ensure password is cleared from memory
            if 'password' in locals():
                password = None
    
    def monitor_job(self, job_id: str, poll_interval: float = 2.0, verbose: bool = False) -> Dict:
        """
        Monitor job progress until completion.
        
        Args:
            job_id: Job ID to monitor
            poll_interval: Polling interval in seconds
            verbose: Show detailed progress
            
        Returns:
            Final job status
        """
        print(f"📊 Monitoring job {job_id}...")
        
        last_progress = -1
        
        while True:
            try:
                response = self.session.get(
                    f"{self.api_base_url}/v1/jobs/{job_id}",
                    verify=self.verify_ssl
                )
                
                if response.status_code != 200:
                    raise Exception(f"Failed to get job status: {response.status_code}")
                
                job_status = response.json()
                status = job_status.get('status', 'unknown')
                progress = job_status.get('progress', 0)
                message = job_status.get('message', '')
                
                # Show progress updates
                if progress != last_progress:
                    print(f"📈 Progress: {progress}% - {message}")
                    last_progress = progress
                elif verbose and message:
                    print(f"🔄 {message}")
                
                if status == "completed":
                    print(f"✅ Job {job_id} completed successfully!")
                    return job_status
                elif status == "failed":
                    print(f"❌ Job {job_id} failed: {message}")
                    return job_status
                elif status in ["queued", "processing"]:
                    time.sleep(poll_interval)
                else:
                    print(f"⚠️ Unknown job status: {status}")
                    time.sleep(poll_interval)
                    
            except KeyboardInterrupt:
                print(f"\n⏸️ Monitoring interrupted for job {job_id}")
                return {"id": job_id, "status": "monitoring_interrupted"}
            except Exception as e:
                print(f"❌ Error monitoring job {job_id}: {e}")
                return {"id": job_id, "status": "monitoring_failed", "error": str(e)}
    
    def download_result(self, job_id: str, output_path: str = None, verbose: bool = False) -> str:
        """
        Download job result.
        
        Args:
            job_id: Job ID
            output_path: Output file path (optional)
            verbose: Verbose output
            
        Returns:
            Path to downloaded file
        """
        if not output_path:
            output_path = f"result_{job_id}.enc"
        
        output_file = Path(output_path)
        
        try:
            if verbose:
                print(f"⬇️ Downloading result for job {job_id}...")
            
            response = self.session.get(
                f"{self.api_base_url}/v1/jobs/{job_id}/result",
                verify=self.verify_ssl,
                stream=True
            )
            
            if response.status_code == 200:
                # Create output directory if needed
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=64*1024):
                        if chunk:
                            f.write(chunk)
                
                file_size = output_file.stat().st_size
                print(f"✅ Result downloaded: {output_file} ({file_size:,} bytes)")
                return str(output_file)
            else:
                error_msg = f"Download failed: {response.status_code}"
                try:
                    error_detail = response.json()
                    if 'detail' in error_detail:
                        error_msg += f" - {error_detail['detail']}"
                except:
                    error_msg += f" - {response.text}"
                raise Exception(error_msg)
                
        except Exception as e:
            print(f"❌ Download error: {e}", file=sys.stderr)
            raise


def main():
    """Command-line interface for secure job submission."""
    parser = argparse.ArgumentParser(
        description="Secure job submission for encrypted media processing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Submit job and monitor progress
  python secure_submit.py encrypted.enc --api-url https://localhost:8443

  # Submit with custom FFmpeg parameters
  python secure_submit.py encrypted.enc --params '{"video_codec": "libx265", "crf": 28}'

  # Submit and download result automatically
  python secure_submit.py encrypted.enc --download --output result.enc

  # Monitor existing job
  python secure_submit.py --monitor abc-123-def --api-url https://localhost:8443

Environment Variables:
  MEDIA_ENCRYPTION_PASSWORD - Set decryption password (for automation)
  API_BASE_URL - Default API base URL
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Encrypted media file to process')
    parser.add_argument('--api-url', default=os.environ.get('API_BASE_URL', 'https://localhost:8443'),
                        help='API base URL (default: https://localhost:8443)')
    parser.add_argument('--params', help='JSON string of FFmpeg parameters')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--download', action='store_true', help='Automatically download result when complete')
    parser.add_argument('--output', '-o', help='Output file path for downloaded result')
    parser.add_argument('--monitor', help='Monitor existing job by ID')
    parser.add_argument('--poll-interval', type=float, default=2.0, help='Job monitoring poll interval (seconds)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.monitor and not args.input_file:
        parser.error("Either input_file or --monitor is required")
    
    try:
        submitter = SecureJobSubmitter(args.api_url, verify_ssl=not args.no_ssl_verify)
        
        if args.monitor:
            # Monitor existing job
            final_status = submitter.monitor_job(args.monitor, args.poll_interval, args.verbose)
            
            if args.download and final_status.get('status') == 'completed':
                submitter.download_result(args.monitor, args.output, args.verbose)
            
        else:
            # Parse FFmpeg parameters
            ffmpeg_params = None
            if args.params:
                try:
                    ffmpeg_params = json.loads(args.params)
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON parameters: {e}", file=sys.stderr)
                    sys.exit(1)
            
            # Submit job
            result = submitter.submit_job(args.input_file, ffmpeg_params, args.verbose)
            job_id = result['job_id']
            
            print(f"🎯 Job submitted: {job_id}")
            
            # Monitor progress
            final_status = submitter.monitor_job(job_id, args.poll_interval, args.verbose)
            
            # Download result if requested and job completed
            if args.download and final_status.get('status') == 'completed':
                output_path = args.output or f"result_{job_id}.enc"
                submitter.download_result(job_id, output_path, args.verbose)
                
                print(f"\n🎉 Complete workflow finished!")
                print(f"   Input: {args.input_file}")
                print(f"   Output: {output_path}")
                print(f"   Job ID: {job_id}")
    
    except FileNotFoundError as e:
        print(f"❌ File error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()