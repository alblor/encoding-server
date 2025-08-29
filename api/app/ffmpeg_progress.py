"""
FFmpeg Progress Parser for Real-Time Granular Progress Tracking

Provides accurate progress calculation for media encoding operations by:
1. Extracting media duration using ffprobe
2. Detecting and parsing time-cut parameters (-ss, -t, -to)
3. Parsing FFmpeg stderr output for current position, fps, and speed
4. Calculating precise progress percentages suitable for frontend updates

Author: Lorenzo Albanese (alblor)
"""

import asyncio
import json
import logging
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class FFmpegProgressParser:
    """
    Advanced FFmpeg progress tracking with granular metrics.
    
    Provides real-time progress updates suitable for frontend applications
    requiring sub-second progress updates and detailed encoding metrics.
    """
    
    # Simple field extraction patterns
    FRAME_PATTERN = re.compile(r'frame=\s*(\d+)')
    FPS_PATTERN = re.compile(r'fps=\s*([\d.]+)')
    TIME_PATTERN_EXTRACT = re.compile(r'time=\s*([\d:]+\.?\d*)')
    SPEED_PATTERN = re.compile(r'speed=\s*([\d.]+)x')
    
    TIME_PATTERN = re.compile(r'(\d+):(\d{2}):(\d{2})(?:\.(\d+))?')
    
    # FFprobe command template for duration extraction
    FFPROBE_DURATION_CMD = [
        'ffprobe', '-v', 'error',
        '-show_entries', 'format=duration',
        '-of', 'json'
    ]
    
    def __init__(self, ffmpeg_path: str = "ffmpeg", ffprobe_path: str = "ffprobe"):
        self.ffmpeg_path = ffmpeg_path
        self.ffprobe_path = ffprobe_path
        
        # Progress state tracking
        self.total_duration: Optional[float] = None
        self.processing_duration: Optional[float] = None
        self.start_offset: float = 0.0
        self.last_progress: Dict = {}
        
        logger.debug("FFmpegProgressParser initialized")
    
    async def get_media_duration(self, input_file: str) -> Optional[float]:
        """
        Extract media duration using ffprobe.
        
        Args:
            input_file: Path to input media file
            
        Returns:
            Duration in seconds, or None if extraction fails
        """
        if not Path(input_file).exists():
            logger.error(f"Input file does not exist: {input_file}")
            return None
        
        try:
            logger.debug(f"Extracting duration for: {input_file}")
            
            # Build ffprobe command
            cmd = self.FFPROBE_DURATION_CMD + [input_file]
            
            # Execute ffprobe
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"ffprobe failed for {input_file}: {stderr.decode()}")
                return None
            
            # Parse JSON output
            output = json.loads(stdout.decode())
            duration_str = output.get('format', {}).get('duration')
            
            if duration_str:
                duration = float(duration_str)
                logger.info(f"Extracted duration: {duration:.2f}s for {input_file}")
                self.total_duration = duration
                return duration
            else:
                logger.warning(f"No duration found in ffprobe output for {input_file}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to extract duration for {input_file}: {e}")
            return None
    
    def parse_time_parameters(self, ffmpeg_params: List[str]) -> Dict[str, float]:
        """
        Parse FFmpeg parameters to detect time-based cuts and calculate processing duration.
        
        Args:
            ffmpeg_params: List of FFmpeg command parameters
            
        Returns:
            Dictionary with start_time, duration, and end_time information
        """
        start_time = 0.0  # -ss parameter
        duration = None   # -t parameter 
        end_time = None   # -to parameter
        
        i = 0
        while i < len(ffmpeg_params):
            param = ffmpeg_params[i]
            
            if param == '-ss' and i + 1 < len(ffmpeg_params):
                # Start time offset
                try:
                    start_time = self._parse_time_string(ffmpeg_params[i + 1])
                    logger.debug(f"Found start offset: {start_time}s (-ss {ffmpeg_params[i + 1]})")
                except ValueError as e:
                    logger.warning(f"Invalid start time format '{ffmpeg_params[i + 1]}': {e}")
                i += 2
                
            elif param == '-t' and i + 1 < len(ffmpeg_params):
                # Duration limit
                try:
                    duration = self._parse_time_string(ffmpeg_params[i + 1])
                    logger.debug(f"Found duration limit: {duration}s (-t {ffmpeg_params[i + 1]})")
                except ValueError as e:
                    logger.warning(f"Invalid duration format '{ffmpeg_params[i + 1]}': {e}")
                i += 2
                
            elif param == '-to' and i + 1 < len(ffmpeg_params):
                # End time
                try:
                    end_time = self._parse_time_string(ffmpeg_params[i + 1])
                    logger.debug(f"Found end time: {end_time}s (-to {ffmpeg_params[i + 1]})")
                except ValueError as e:
                    logger.warning(f"Invalid end time format '{ffmpeg_params[i + 1]}': {e}")
                i += 2
            else:
                i += 1
        
        # Calculate actual processing duration
        if self.total_duration:
            if duration is not None:
                # Duration explicitly specified with -t
                processing_duration = duration
            elif end_time is not None:
                # End time specified with -to
                processing_duration = end_time - start_time
            else:
                # No explicit duration, process from start_time to end of media
                processing_duration = self.total_duration - start_time
                
            # Ensure we don't exceed total duration
            max_possible = self.total_duration - start_time
            processing_duration = min(processing_duration, max_possible)
        else:
            # No total duration available, use what we can determine
            processing_duration = duration
        
        # Store for progress calculations
        self.start_offset = start_time
        self.processing_duration = processing_duration
        
        result = {
            'start_time': start_time,
            'duration': duration,
            'end_time': end_time,
            'processing_duration': processing_duration,
            'total_duration': self.total_duration
        }
        
        logger.info(f"Time parameters parsed: {result}")
        return result
    
    def _parse_time_string(self, time_str: str) -> float:
        """
        Parse time string in various formats to seconds.
        
        Supports:
        - HH:MM:SS.mmm
        - MM:SS.mmm
        - SS.mmm
        - SS (integer seconds)
        
        Args:
            time_str: Time string to parse
            
        Returns:
            Time in seconds as float
            
        Raises:
            ValueError: If time format is invalid
        """
        time_str = time_str.strip()
        
        # Try to match HH:MM:SS.mmm format
        match = self.TIME_PATTERN.match(time_str)
        if match:
            hours = int(match.group(1))
            minutes = int(match.group(2))
            seconds = int(match.group(3))
            milliseconds = match.group(4)
            
            # Handle milliseconds
            if milliseconds:
                # Pad or truncate to 3 digits
                ms_str = milliseconds.ljust(3, '0')[:3]
                ms = int(ms_str) / 1000.0
            else:
                ms = 0.0
            
            total_seconds = hours * 3600 + minutes * 60 + seconds + ms
            return total_seconds
        
        # Try parsing as plain seconds (integer or float)
        try:
            return float(time_str)
        except ValueError:
            pass
        
        raise ValueError(f"Invalid time format: {time_str}")
    
    def parse_progress_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single line of FFmpeg stderr output for progress information.
        Simple, robust approach that extracts fields independently.
        
        Args:
            line: Single line from FFmpeg stderr
            
        Returns:
            Dictionary with progress data or None if line doesn't contain progress
        """
        # Quick check: must have frame= and time= to be a progress line
        if 'frame=' not in line or 'time=' not in line:
            return None
        
        try:
            # Extract required fields (frame and time)
            frame = self._extract_field(line, self.FRAME_PATTERN, int)
            time_str = self._extract_field(line, self.TIME_PATTERN_EXTRACT, str)
            
            if frame is None or time_str is None:
                return None
            
            # Extract optional fields (may be missing due to truncation)
            fps = self._extract_field(line, self.FPS_PATTERN, float)
            speed = self._extract_field(line, self.SPEED_PATTERN, float)
            
            # Parse current time position
            current_time = self._parse_time_string(time_str)
            
            # Calculate progress percentage
            progress_percent = self._calculate_progress_percentage(current_time)
            
            # Calculate ETA if we have speed
            eta = self._calculate_eta(current_time, speed) if speed else None
            
            progress_data = {
                'frame': frame,
                'fps': fps,
                'current_time': current_time,
                'current_time_str': time_str,
                'speed': speed,
                'progress_percent': progress_percent,
                'eta': eta,
                'timestamp': datetime.now().isoformat()
            }
            
            self.last_progress = progress_data
            return progress_data
            
        except Exception as e:
            logger.debug(f"Error parsing progress line: {e}")
            return None
    
    def _extract_field(self, line: str, pattern: re.Pattern, converter) -> Optional[Union[int, float, str]]:
        """Extract a single field from the line using the given pattern."""
        try:
            match = pattern.search(line)
            if match:
                value = match.group(1)
                return converter(value)
        except Exception:
            pass
        return None
    
    def _calculate_progress_percentage(self, current_time: float) -> Optional[float]:
        """Calculate progress percentage based on current position and expected duration."""
        if not self.processing_duration or self.processing_duration <= 0:
            return None
        
        # Adjust current time to account for start offset
        adjusted_time = current_time
        
        # Calculate percentage
        progress = (adjusted_time / self.processing_duration) * 100.0
        
        # Clamp to valid range
        progress = max(0.0, min(100.0, progress))
        
        return round(progress, 2)
    
    def _calculate_eta(self, current_time: float, speed: float) -> Optional[str]:
        """Calculate estimated time remaining based on current progress and speed."""
        if not self.processing_duration or speed <= 0:
            return None
        
        try:
            remaining_duration = self.processing_duration - current_time
            eta_seconds = remaining_duration / speed
            
            if eta_seconds <= 0:
                return "00:00:00"
            
            # Convert to HH:MM:SS format
            eta_delta = timedelta(seconds=eta_seconds)
            
            # Format as HH:MM:SS
            hours, remainder = divmod(eta_delta.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            
        except (ZeroDivisionError, ValueError):
            return None
    
    def get_summary(self) -> Dict:
        """
        Get current progress summary with all relevant metrics.
        
        Returns:
            Comprehensive progress summary dictionary
        """
        summary = {
            'total_duration': self.total_duration,
            'processing_duration': self.processing_duration, 
            'start_offset': self.start_offset,
            'has_time_cuts': self.start_offset > 0 or (
                self.processing_duration and 
                self.total_duration and 
                self.processing_duration < self.total_duration
            ),
            'last_progress': self.last_progress.copy() if self.last_progress else None,
            'parser_ready': bool(self.processing_duration)
        }
        
        return summary
    
    def format_duration(self, seconds: Optional[float]) -> str:
        """Format duration in seconds to HH:MM:SS string."""
        if seconds is None:
            return "Unknown"
        
        try:
            delta = timedelta(seconds=seconds)
            hours, remainder = divmod(delta.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        except (ValueError, TypeError):
            return "Unknown"