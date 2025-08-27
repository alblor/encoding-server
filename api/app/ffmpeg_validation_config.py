"""
FFmpeg Validation Configuration - Hybrid Security Architecture

This configuration implements a three-layer security approach:
1. Core Parameter Whitelist - Explicit control over fundamental operations
2. Safe Command Construction - Secure parameter passing to FFmpeg subprocess
3. Proper Sandboxing - Real security through AppArmor and container isolation

Author: Lorenzo Albanese (alblor)
"""

import re
from typing import Dict, List, Set, Optional, Pattern


class FFmpegValidationConfig:
    """
    Professional FFmpeg validation with hybrid security architecture.
    
    Balances security control with operational flexibility by:
    - Whitelisting core parameters for explicit control
    - Allowing complex filters with safety validation  
    - Relying on proper sandboxing for real security
    """
    
    # ===== LAYER 1: CORE PARAMETER WHITELIST =====
    
    # Basic I/O and stream control (always allowed)
    CORE_IO_PARAMETERS = {
        # Input/Output Control
        '-i', '-f', '-t', '-ss', '-to', '-itsoffset', '-timestamp',
        '-metadata', '-fflags', '-probesize', '-analyzeduration',
        
        # Stream Control
        '-map', '-c', '-codec', '-disposition', '-shortest',
        '-avoid_negative_ts', '-copyts', '-start_at_zero',
        
        # Output Control  
        '-y', '-n', '-stats', '-v', '-loglevel',
    }
    
    # Video core parameters with comprehensive codec support
    VIDEO_PARAMETERS = {
        # Core Video Options
        '-c:v', '-vcodec', '-r', '-s', '-aspect', '-pix_fmt', '-vframes',
        '-b:v', '-minrate', '-maxrate', '-bufsize', '-g', '-crf',
        
        # Quality and Rate Control
        '-preset', '-tune', '-profile', '-level', '-qp', '-qmin', '-qmax',
        '-refs', '-keyint', '-keyint_min', '-sc_threshold',
        
        # Advanced Video Options  
        '-pass', '-passlogfile', '-threads', '-slices',
        '-hwaccel', '-hwaccel_device', '-hwaccel_output_format',
        
        # Codec-specific options (missing from original implementation)
        '-row-mt', '-cpu-used', '-lag-in-frames', '-tile-columns', '-tile-rows',
        '-frame-parallel', '-aq-mode', '-arnr-maxframes', '-arnr-strength',
        '-auto-alt-ref', '-enable-cdef', '-enable-restoration',
        
        # Audio control from video context
        '-an', '-vn', '-sn',  # disable audio/video/subtitles
        
        # Video filters (special handling)
        '-vf', '-filter:v', '-filter_complex',
    }
    
    # Audio core parameters with comprehensive codec support
    AUDIO_PARAMETERS = {
        # Core Audio Options
        '-c:a', '-acodec', '-ar', '-ac', '-b:a', '-q:a', '-vol',
        '-sample_fmt', '-channel_layout', '-af', '-filter:a',
        
        # Audio Quality
        '-compression_level', '-cutoff', '-joint_stereo', '-reservoir',
        
        # Audio-specific codec options
        '-application', '-frame_duration', '-packet_loss', '-fec', '-dtx',
        '-vbr', '-mapping_family',
    }
    
    # Comprehensive modern codec support (including missing AV1 codecs)
    ALLOWED_VIDEO_CODECS = {
        # Modern Codecs (AV1 support was missing!)
        'libaom-av1', 'librav1e', 'libsvtav1', 'av1_nvenc', 'av1_qsv', 'av1_amf',
        
        # H.264/AVC Family
        'libx264', 'libx264rgb', 'h264', 'h264_nvenc', 'h264_qsv', 'h264_amf',
        'h264_videotoolbox', 'h264_vaapi', 'h264_v4l2m2m',
        
        # H.265/HEVC Family  
        'libx265', 'hevc', 'hevc_nvenc', 'hevc_qsv', 'hevc_amf',
        'hevc_videotoolbox', 'hevc_vaapi', 'hevc_v4l2m2m',
        
        # VP8/VP9
        'libvpx', 'libvpx-vp9', 'vp8', 'vp9', 'vp8_vaapi', 'vp9_vaapi', 'vp9_qsv',
        
        # Legacy and Specialized  
        'mpeg1video', 'mpeg2video', 'mpeg4', 'libxvid', 'h261', 'h263', 'h263p',
        'flv1', 'wmv1', 'wmv2', 'theora', 'libtheora', 'dirac', 'vc2',
        
        # High Quality/Lossless
        'ffv1', 'utvideo', 'huffyuv', 'ffvhuff', 'prores', 'prores_aw', 'prores_ks',
        'dnxhd', 'cineform', 'cfhd', 'v210', 'v308', 'v408', 'v410',
        
        # Image Formats
        'mjpeg', 'ljpeg', 'jpeg2000', 'libopenjpeg', 'png', 'apng', 
        'tiff', 'bmp', 'gif', 'webp',
        
        # Passthrough
        'copy'
    }
    
    # Comprehensive audio codec support
    ALLOWED_AUDIO_CODECS = {
        # Modern Audio Codecs
        'aac', 'libfdk_aac', 'aac_at', 'libopus', 'opus', 'libvorbis', 'vorbis',
        
        # MP3 Family
        'libmp3lame', 'mp3', 'mp3_at', 'libshine', 'libtwolame', 'mp2', 'mp2fixed',
        
        # AC-3 Family
        'ac3', 'ac3_fixed', 'eac3', 'truehd', 'dts', 'dca',
        
        # Lossless Audio
        'alac', 'flac', 'wavpack', 'tta', 'mlp',
        
        # PCM Formats
        'pcm_s16le', 'pcm_s16be', 'pcm_s24le', 'pcm_s24be', 'pcm_s32le', 'pcm_s32be',
        'pcm_f32le', 'pcm_f32be', 'pcm_f64le', 'pcm_f64be', 'pcm_s8', 'pcm_u8',
        'pcm_alaw', 'pcm_mulaw',
        
        # Specialized  
        'adpcm_ima_qt', 'adpcm_ima_wav', 'adpcm_ms', 'adpcm_g722', 'adpcm_g726',
        'g723_1', 'gsm', 'libgsm', 'libgsm_ms', 'speex', 'libspeex', 'nellymoser',
        
        # Passthrough
        'copy'
    }
    
    # Container formats
    ALLOWED_FORMATS = {
        # Video Containers
        'mp4', 'mov', 'mkv', 'webm', 'avi', 'flv', 'm4v', '3gp', '3g2',
        'wmv', 'asf', 'mxf', 'gxf', 'nut', 'ts', 'mts', 'm2ts', 'vob',
        'mpg', 'mpeg', 'ogv', 'rm', 'rmvb',
        
        # Audio Containers  
        'mp3', 'aac', 'ogg', 'oga', 'flac', 'wav', 'm4a', 'wma', 'opus',
        'ac3', 'dts', 'tta', 'wv', 'aiff', 'au', 'caf', 'mka',
        
        # Raw/Uncompressed
        'yuv', 'rgb', 'rawvideo'
    }
    
    # ===== LAYER 2: SAFE CONSTRUCTION PATTERNS =====
    
    # Parameters that accept complex values (validated for safety, not syntax)
    COMPLEX_VALUE_PARAMETERS = {
        '-vf', '-filter:v', '-af', '-filter:a', '-filter_complex',
        '-aom-params', '-x264-params', '-x264opts', '-x265-params',
        '-svtav1-params', '-rav1e-params', '-vpx-params',
        # Container-specific parameters that may contain flags
        '-movflags', '-fflags', '-rtmp_options'
    }
    
    # Stream specifier pattern (e.g., -c:v:0, -b:a:1, -0:d for negative stream selection)
    STREAM_SPECIFIER_PATTERN = re.compile(r'^-[a-z]*\d*:[vasondt](?::\d+)?$')
    
    # ===== LAYER 3: SECURITY VIOLATION PATTERNS =====
    
    # Critical security patterns that must always be blocked
    SECURITY_VIOLATIONS = [
        # Shell injection patterns
        (r'[;&|`]', 'shell_metacharacters'),
        (r'\$\([^)]*\)', 'command_substitution'), 
        (r'`[^`]*`', 'backtick_execution'),
        
        # File system access (outside working directory) - Allow our secure tmpfs workspaces
        (r'\.\./', 'path_traversal'),
        (r'/(?:etc|proc|sys|dev|root|var|bin|usr)/', 'system_directory_access'),
        (r'^/', 'absolute_path_access'),  # Block any absolute paths
        (r'\\\\', 'windows_unc_path'),
        # Fixed: More specific Windows drive pattern to avoid false positives
        (r'\b[A-Z]:[/\\]', 'windows_drive_access'),
        
        # Network access
        (r'(?:https?|ftp|rtmp|tcp|udp)://', 'network_access'),
        
        # System commands  
        (r'\b(?:rm|mv|cp|wget|curl|ssh|chmod|chown|kill|service)\s+', 'system_command'),
    ]
    
    # Compile violation patterns for performance
    COMPILED_VIOLATIONS = [(re.compile(pattern, re.IGNORECASE), violation_type) 
                          for pattern, violation_type in SECURITY_VIOLATIONS]
    
    @classmethod
    def validate_core_parameter(cls, param: str, value: str = None) -> Dict[str, any]:
        """
        Validate core FFmpeg parameters against whitelist.
        
        Args:
            param: Parameter name (e.g., '-c:v')
            value: Parameter value (e.g., 'libx264')
            
        Returns:
            Dict with validation result and details
        """
        result = {
            'valid': False,
            'violation_type': None,
            'message': None,
            'parameter_type': None
        }
        
        # Check if parameter is in core whitelist
        all_core_params = (cls.CORE_IO_PARAMETERS | cls.VIDEO_PARAMETERS | cls.AUDIO_PARAMETERS)
        
        if param in all_core_params:
            result['valid'] = True
            result['parameter_type'] = cls._get_parameter_type(param)
            return result
        
        # Check stream specifier pattern (e.g., -c:v:0)
        if cls.STREAM_SPECIFIER_PATTERN.match(param):
            result['valid'] = True
            result['parameter_type'] = 'stream_specifier'
            return result
            
        # Check if it's a complex value parameter
        if param in cls.COMPLEX_VALUE_PARAMETERS:
            result['valid'] = True
            result['parameter_type'] = 'complex_value'
            return result
        
        # Parameter not in whitelist
        result['violation_type'] = 'invalid_parameter'
        result['message'] = f"VIOLATION: Parameter '{param}' is not in the approved FFmpeg parameter list."
        
        return result
    
    @classmethod
    def validate_codec_value(cls, codec_type: str, codec: str) -> Dict[str, any]:
        """
        Validate codec against allowed codec lists.
        
        Args:
            codec_type: 'video' or 'audio'
            codec: Codec name
            
        Returns:
            Dict with validation result
        """
        result = {
            'valid': False,
            'violation_type': None,
            'message': None
        }
        
        if codec_type == 'video' and codec in cls.ALLOWED_VIDEO_CODECS:
            result['valid'] = True
        elif codec_type == 'audio' and codec in cls.ALLOWED_AUDIO_CODECS:
            result['valid'] = True
        else:
            result['violation_type'] = 'invalid_codec'
            result['message'] = f"VIOLATION: {codec_type.title()} codec '{codec}' is not approved."
            
        return result
    
    @classmethod
    def validate_format_value(cls, format_name: str) -> Dict[str, any]:
        """
        Validate container format against allowed formats.
        
        Args:
            format_name: Format/container name
            
        Returns:
            Dict with validation result
        """
        result = {
            'valid': False,
            'violation_type': None, 
            'message': None
        }
        
        if format_name in cls.ALLOWED_FORMATS:
            result['valid'] = True
        else:
            result['violation_type'] = 'invalid_format'
            result['message'] = f"VIOLATION: Format '{format_name}' is not approved."
            
        return result
    
    @classmethod
    def check_security_violations(cls, value: str) -> Dict[str, any]:
        """
        Check value against security violation patterns.
        
        Args:
            value: Parameter value to check
            
        Returns:
            Dict with security check result
        """
        result = {
            'safe': True,
            'violation_type': None,
            'message': None
        }
        
        if not value:
            return result
            
        # Check against compiled violation patterns
        for pattern, violation_type in cls.COMPILED_VIOLATIONS:
            if pattern.search(value):
                result['safe'] = False
                result['violation_type'] = violation_type
                result['message'] = cls._get_violation_message(violation_type, value)
                break
                
        return result
    
    @classmethod
    def validate_output_filename(cls, filename: str) -> Dict[str, any]:
        """
        Validate output filename for safety.
        
        Allows internal secure paths while blocking dangerous user paths.
        
        Args:
            filename: Output filename (may be internal secure path)
            
        Returns:
            Dict with validation result
        """
        result = {
            'safe': True,
            'violation_type': None,
            'message': None
        }
        
        # Basic safety checks
        if not filename or len(filename) > 255:
            result['safe'] = False
            result['violation_type'] = 'invalid_filename'
            result['message'] = "VIOLATION: Invalid or excessively long filename."
            return result
        
        # Allow internal secure tmpfs paths - these are controlled by the system
        secure_paths = ['/tmp/memory-pool/', '/tmp/encrypted-swap/', '/tmp/encoding/']
        if any(filename.startswith(path) for path in secure_paths):
            return result  # Safe internal path
        
        # Security check for user-provided paths
        security_result = cls.check_security_violations(filename)
        if not security_result['safe']:
            result.update(security_result)
            
        return result
    
    @classmethod
    def _get_parameter_type(cls, param: str) -> str:
        """Get the type category of a parameter."""
        if param in cls.CORE_IO_PARAMETERS:
            return 'core_io'
        elif param in cls.VIDEO_PARAMETERS:
            return 'video'
        elif param in cls.AUDIO_PARAMETERS:
            return 'audio'
        else:
            return 'unknown'
    
    @classmethod  
    def _get_violation_message(cls, violation_type: str, value: str) -> str:
        """Generate specific violation error messages."""
        messages = {
            'shell_metacharacters': f"VIOLATION: Shell metacharacters detected. Command injection attempt blocked.",
            'command_substitution': f"VIOLATION: Command substitution pattern detected. Execution attempt blocked.", 
            'backtick_execution': f"VIOLATION: Backtick command execution detected. Security violation blocked.",
            'path_traversal': f"VIOLATION: Path traversal attempt detected. Filesystem access denied.",
            'system_directory_access': f"VIOLATION: System directory access attempt. Unauthorized path blocked.",
            'absolute_path_access': f"VIOLATION: Absolute path access detected. Only relative filenames allowed.",
            'windows_unc_path': f"VIOLATION: Windows UNC path detected. Network path access denied.",
            'windows_drive_access': f"VIOLATION: Windows drive access attempt. Path access denied.",
            'network_access': f"VIOLATION: Network resource access attempt. External connectivity blocked.",
            'system_command': f"VIOLATION: System command execution attempt. Dangerous operation blocked."
        }
        
        return messages.get(violation_type, f"VIOLATION: Security constraint violated.")


# Export singleton config instance
FFMPEG_CONFIG = FFmpegValidationConfig()