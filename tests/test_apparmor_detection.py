#!/usr/bin/env python3
"""
Comprehensive AppArmor Detection Testing
Test the robust AppArmor detection system with graceful fallback methods.

Author: Lorenzo Albanese (alblor)
Created: September 4, 2025
"""

import os
import sys
import unittest
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
import tempfile
import logging

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.app.secure_jobs import SecureJobProcessor

class TestAppArmorDetection(unittest.TestCase):
    """Test comprehensive AppArmor detection with fallback methods."""

    def setUp(self):
        """Set up test environment."""
        # Set environment variables for testing
        os.environ["ENVIRONMENT"] = "testing"
        os.environ["FFMPEG_SECURITY_LEVEL"] = "high"
        
        # Mock EncryptionManager since we're only testing AppArmor detection
        with patch('api.app.secure_jobs.EncryptionManager'):
            self.job_processor = SecureJobProcessor()
        # Reduce logging noise during tests
        logging.getLogger().setLevel(logging.WARNING)
    
    def test_apparmor_kernel_module_enabled(self):
        """Test successful AppArmor kernel module detection."""
        with patch("builtins.open", mock_open(read_data="Y\n")):
            result = self.job_processor._check_apparmor_kernel_module()
            self.assertTrue(result)
    
    def test_apparmor_kernel_module_disabled(self):
        """Test AppArmor kernel module disabled detection."""
        with patch("builtins.open", mock_open(read_data="N\n")):
            result = self.job_processor._check_apparmor_kernel_module()
            self.assertFalse(result)
    
    def test_apparmor_kernel_module_fallback_to_filesystem(self):
        """Test fallback to AppArmor filesystem when parameters fail."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.path.exists", return_value=True) as mock_exists:
                result = self.job_processor._check_apparmor_kernel_module()
                self.assertTrue(result)
                mock_exists.assert_called_with("/sys/kernel/security/apparmor")
    
    def test_apparmor_kernel_module_permission_denied(self):
        """Test graceful handling of permission denied on kernel module check."""
        with patch("builtins.open", side_effect=PermissionError):
            with patch("os.path.exists", return_value=True):
                result = self.job_processor._check_apparmor_kernel_module()
                self.assertTrue(result)
    
    def test_current_apparmor_profile_modern_interface(self):
        """Test current process AppArmor profile detection (modern kernel interface)."""
        mock_profile = "docker-default (enforce)"
        
        # Mock modern interface success
        with patch("builtins.open", mock_open(read_data=mock_profile)):
            result = self.job_processor._check_current_apparmor_profile()
            self.assertTrue(result)
    
    def test_current_apparmor_profile_legacy_interface(self):
        """Test current process AppArmor profile detection (legacy interface)."""
        mock_profile = "docker-default (enforce)"
        
        # Mock modern interface failure, legacy success
        def mock_open_behavior(path, *args, **kwargs):
            if "apparmor/current" in path:
                raise FileNotFoundError()
            elif "attr/current" in path:
                return mock_open(read_data=mock_profile)()
            else:
                raise FileNotFoundError()
        
        with patch("builtins.open", side_effect=mock_open_behavior):
            result = self.job_processor._check_current_apparmor_profile()
            self.assertTrue(result)
    
    def test_current_apparmor_profile_unconfined(self):
        """Test detection of unconfined process (no AppArmor profile)."""
        with patch("builtins.open", mock_open(read_data="unconfined\n")):
            result = self.job_processor._check_current_apparmor_profile()
            self.assertFalse(result)
    
    def test_current_apparmor_profile_permission_denied(self):
        """Test graceful handling of permission denied on process attributes."""
        with patch("builtins.open", side_effect=PermissionError):
            result = self.job_processor._check_current_apparmor_profile()
            self.assertFalse(result)
    
    def test_current_apparmor_profile_invalid_argument(self):
        """Test handling of EINVAL error (common on newer kernels)."""
        error = OSError()
        error.errno = 22  # EINVAL
        with patch("builtins.open", side_effect=error):
            result = self.job_processor._check_current_apparmor_profile()
            self.assertFalse(result)
    
    def test_system_apparmor_profiles_success(self):
        """Test successful system AppArmor profiles detection."""
        mock_profiles = """
/usr/bin/ffmpeg (enforce)
/usr/local/bin/ffmpeg (complain)
docker-default (enforce)
        """
        with patch("builtins.open", mock_open(read_data=mock_profiles)):
            result = self.job_processor._check_system_apparmor_profiles()
            self.assertTrue(result)
    
    def test_system_apparmor_profiles_complain_mode(self):
        """Test system AppArmor profiles in complain mode (acceptable for testing)."""
        mock_profiles = """
/usr/bin/ffmpeg (complain)
docker-default (enforce)
        """
        with patch("builtins.open", mock_open(read_data=mock_profiles)):
            result = self.job_processor._check_system_apparmor_profiles()
            self.assertTrue(result)  # Complain mode is allowed
    
    def test_system_apparmor_profiles_no_ffmpeg(self):
        """Test system AppArmor profiles with no FFmpeg profiles."""
        mock_profiles = """
docker-default (enforce)
/bin/bash (enforce)
        """
        with patch("builtins.open", mock_open(read_data=mock_profiles)):
            result = self.job_processor._check_system_apparmor_profiles()
            self.assertFalse(result)
    
    def test_system_apparmor_profiles_permission_denied(self):
        """Test graceful handling of permission denied (Docker-in-LXC scenario)."""
        with patch("builtins.open", side_effect=PermissionError):
            result = self.job_processor._check_system_apparmor_profiles()
            self.assertFalse(result)
    
    def test_alternative_methods_docker_profile_detected(self):
        """Test alternative detection methods - Docker profile on PID 1."""
        with patch("builtins.open", mock_open(read_data="docker-default (enforce)\n")):
            with patch("subprocess.run") as mock_run:
                # Mock which command failure
                mock_run.return_value = MagicMock(returncode=1)
                
                result = self.job_processor._check_apparmor_alternative_methods()
                
                self.assertTrue(result["docker_profile_present"])
                self.assertFalse(result["apparmor_parser_available"])
    
    def test_alternative_methods_apparmor_parser_available(self):
        """Test alternative detection methods - apparmor_parser availability."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("subprocess.run") as mock_run:
                # Mock which command success
                mock_run.return_value = MagicMock(returncode=0)
                
                result = self.job_processor._check_apparmor_alternative_methods()
                
                self.assertFalse(result["docker_profile_present"])
                self.assertTrue(result["apparmor_parser_available"])
    
    def test_alternative_methods_enforcement_detected(self):
        """Test alternative detection methods - enforcement through restricted access."""
        def mock_open_behavior(path, *args, **kwargs):
            if "/proc/1/attr/current" in path:
                raise FileNotFoundError()
            elif any(test_path in path for test_path in ["/proc/sysrq-trigger", "/sys/kernel/debug", "/dev/mem"]):
                raise PermissionError()  # Expected with AppArmor enforcement
            else:
                raise FileNotFoundError()
        
        with patch("builtins.open", side_effect=mock_open_behavior):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                
                result = self.job_processor._check_apparmor_alternative_methods()
                
                self.assertTrue(result["profile_enforcement_detected"])
    
    def test_evaluation_direct_methods_success(self):
        """Test evaluation with successful direct methods."""
        result = self.job_processor._evaluate_apparmor_enforcement_result(
            current_profile=True,
            system_profiles=False,
            alternative_results={}
        )
        self.assertTrue(result)
    
    def test_evaluation_alternative_methods_high_confidence(self):
        """Test evaluation with high confidence alternative methods."""
        alternative_results = {
            "docker_profile_present": True,
            "apparmor_parser_available": True,
            "profile_enforcement_detected": True
        }
        
        result = self.job_processor._evaluate_apparmor_enforcement_result(
            current_profile=False,
            system_profiles=False,
            alternative_results=alternative_results
        )
        self.assertTrue(result)
    
    def test_evaluation_maximum_security_production_strict(self):
        """Test evaluation in maximum security production mode (strict requirements)."""
        # Set maximum security production mode
        self.job_processor.security_level = "maximum"
        self.job_processor.environment = "secure-production"
        
        alternative_results = {
            "docker_profile_present": True,
            "apparmor_parser_available": False,
            "profile_enforcement_detected": True
        }
        
        result = self.job_processor._evaluate_apparmor_enforcement_result(
            current_profile=False,
            system_profiles=False,
            alternative_results=alternative_results
        )
        # Should fail in maximum security production with only alternative indicators
        self.assertFalse(result)
    
    def test_evaluation_maximum_security_testing_lenient(self):
        """Test evaluation in maximum security testing mode (more lenient)."""
        # Set maximum security testing mode
        self.job_processor.security_level = "maximum"
        self.job_processor.environment = "testing"
        
        alternative_results = {
            "docker_profile_present": True,
            "apparmor_parser_available": True,
            "profile_enforcement_detected": False
        }
        
        result = self.job_processor._evaluate_apparmor_enforcement_result(
            current_profile=False,
            system_profiles=False,
            alternative_results=alternative_results
        )
        # Should pass in maximum security testing with good alternative indicators
        self.assertTrue(result)
    
    def test_evaluation_no_evidence(self):
        """Test evaluation with no evidence of AppArmor enforcement."""
        alternative_results = {
            "docker_profile_present": False,
            "apparmor_parser_available": False,
            "profile_enforcement_detected": False
        }
        
        result = self.job_processor._evaluate_apparmor_enforcement_result(
            current_profile=False,
            system_profiles=False,
            alternative_results=alternative_results
        )
        self.assertFalse(result)
    
    def test_full_integration_success_primary_method(self):
        """Test full integration with successful primary method."""
        with patch.object(self.job_processor, '_check_apparmor_kernel_module', return_value=True):
            with patch.object(self.job_processor, '_check_system_apparmor_profiles', return_value=True):
                result = self.job_processor._verify_apparmor_enforcement()
                self.assertTrue(result)
    
    def test_full_integration_fallback_to_alternatives(self):
        """Test full integration with fallback to alternative methods."""
        alternative_results = {
            "docker_profile_present": True,
            "apparmor_parser_available": True,
            "profile_enforcement_detected": True
        }
        
        with patch.object(self.job_processor, '_check_apparmor_kernel_module', return_value=True):
            with patch.object(self.job_processor, '_check_current_apparmor_profile', return_value=False):
                with patch.object(self.job_processor, '_check_system_apparmor_profiles', return_value=False):
                    with patch.object(self.job_processor, '_check_apparmor_alternative_methods', return_value=alternative_results):
                        result = self.job_processor._verify_apparmor_enforcement()
                        self.assertTrue(result)
    
    def test_full_integration_kernel_module_unavailable(self):
        """Test full integration with kernel module unavailable."""
        with patch.object(self.job_processor, '_check_apparmor_kernel_module', return_value=False):
            result = self.job_processor._verify_apparmor_enforcement()
            self.assertFalse(result)

class TestAppArmorDetectionScenarios(unittest.TestCase):
    """Test specific real-world AppArmor detection scenarios."""

    def test_docker_in_lxc_permission_denied_scenario(self):
        """Test the specific Docker-in-LXC permission denied scenario."""
        # Set environment variables for production testing
        os.environ["ENVIRONMENT"] = "secure-production"
        os.environ["FFMPEG_SECURITY_LEVEL"] = "maximum"
        
        # Mock EncryptionManager since we're only testing AppArmor detection
        with patch('api.app.secure_jobs.EncryptionManager'):
            job_processor = SecureJobProcessor()
        
        # Simulate Docker-in-LXC scenario
        with patch.object(job_processor, '_check_apparmor_kernel_module', return_value=True):
            with patch.object(job_processor, '_check_current_apparmor_profile', return_value=True):
                with patch.object(job_processor, '_check_system_apparmor_profiles', return_value=False):
                    # Even with permission denied, should succeed if current profile is detected
                    result = job_processor._verify_apparmor_enforcement()
                    self.assertTrue(result)
    
    def test_proxmox_lxc_nested_container_scenario(self):
        """Test Proxmox LXC nested container scenario."""
        # Set environment variables for testing
        os.environ["ENVIRONMENT"] = "testing"  
        os.environ["FFMPEG_SECURITY_LEVEL"] = "high"
        
        # Mock EncryptionManager since we're only testing AppArmor detection
        with patch('api.app.secure_jobs.EncryptionManager'):
            job_processor = SecureJobProcessor()
        
        # Simulate partial AppArmor availability in nested container
        alternative_results = {
            "docker_profile_present": True,
            "apparmor_parser_available": False,
            "profile_enforcement_detected": True
        }
        
        with patch.object(job_processor, '_check_apparmor_kernel_module', return_value=True):
            with patch.object(job_processor, '_check_current_apparmor_profile', return_value=False):
                with patch.object(job_processor, '_check_system_apparmor_profiles', return_value=False):
                    with patch.object(job_processor, '_check_apparmor_alternative_methods', return_value=alternative_results):
                        result = job_processor._verify_apparmor_enforcement()
                        self.assertTrue(result)  # Should pass with alternative methods
    
    def test_development_environment_lenient(self):
        """Test development environment with lenient security requirements."""
        # Set environment variables for development testing
        os.environ["ENVIRONMENT"] = "development"
        os.environ["FFMPEG_SECURITY_LEVEL"] = "medium"
        
        # Mock EncryptionManager since we're only testing AppArmor detection
        with patch('api.app.secure_jobs.EncryptionManager'):
            job_processor = SecureJobProcessor()
        
        # Even minimal evidence should pass in development
        alternative_results = {
            "docker_profile_present": False,
            "apparmor_parser_available": True,  # Just parser available
            "profile_enforcement_detected": False
        }
        
        with patch.object(job_processor, '_check_apparmor_kernel_module', return_value=True):
            with patch.object(job_processor, '_check_current_apparmor_profile', return_value=False):
                with patch.object(job_processor, '_check_system_apparmor_profiles', return_value=False):
                    with patch.object(job_processor, '_check_apparmor_alternative_methods', return_value=alternative_results):
                        result = job_processor._verify_apparmor_enforcement()
                        self.assertTrue(result)


def main():
    """Run comprehensive AppArmor detection tests."""
    print("=" * 80)
    print("COMPREHENSIVE APPARMOR DETECTION TESTING")
    print("=" * 80)
    print()
    
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [TestAppArmorDetection, TestAppArmorDetectionScenarios]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True
    )
    
    result = runner.run(suite)
    
    print("\n" + "=" * 80)
    print(f"TESTING COMPLETE - Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\nSUCCESS RATE: {success_rate:.1f}%")
    print("=" * 80)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)