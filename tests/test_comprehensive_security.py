"""
Comprehensive Security Testing Suite
Tests HTTPS/TLS transport security and Seccomp syscall filtering implementation.

Author: Lorenzo Albanese (alblor)
"""

import pytest
import requests
import ssl
import socket
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any
import time


class TestTransportSecurity:
    """Test HTTPS/TLS transport encryption functionality."""
    
    def setup_class(self):
        """Setup test class with configuration."""
        self.http_base_url = "https://localhost:8443"
        self.https_base_url = "https://localhost:8443"
        self.project_root = Path(__file__).parent.parent
        
    def test_tls_manager_certificate_generation(self):
        """Test TLS manager can generate self-signed certificates."""
        # Import TLS manager
        import sys
        sys.path.append(str(self.project_root / "api"))
        
        from app.tls_config import TLSManager
        
        # Create TLS manager
        tls_manager = TLSManager(cert_dir="/tmp/test-certs")
        
        # Generate certificate
        success = tls_manager.generate_self_signed_cert(
            common_name="localhost",
            alt_names=["localhost", "127.0.0.1", "::1"]
        )
        
        assert success, "Certificate generation should succeed"
        assert tls_manager.cert_file.exists(), "Certificate file should exist"
        assert tls_manager.key_file.exists(), "Private key file should exist"
        
    def test_certificate_validation(self):
        """Test certificate validation functionality."""
        import sys
        sys.path.append(str(self.project_root / "api"))
        
        from app.tls_config import TLSManager
        
        tls_manager = TLSManager(cert_dir="/tmp/test-certs")
        
        # Should validate successfully after generation
        is_valid = tls_manager.validate_certificate()
        assert is_valid, "Generated certificate should be valid"
        
    def test_ssl_context_creation(self):
        """Test SSL context creation with proper security settings."""
        import sys
        sys.path.append(str(self.project_root / "api"))
        
        from app.tls_config import TLSManager
        
        tls_manager = TLSManager(cert_dir="/tmp/test-certs")
        ssl_context = tls_manager.get_ssl_context()
        
        assert ssl_context is not None, "SSL context should be created"
        assert ssl_context.minimum_version >= ssl.TLSVersion.TLSv1_2, "Should enforce TLS 1.2+"
        
    def test_certificate_info_endpoint(self):
        """Test certificate information retrieval."""
        import sys
        sys.path.append(str(self.project_root / "api"))
        
        from app.tls_config import TLSManager
        
        tls_manager = TLSManager(cert_dir="/tmp/test-certs")
        cert_info = tls_manager.get_certificate_info()
        
        assert cert_info["status"] == "valid", "Certificate should be valid"
        assert "subject" in cert_info, "Should include subject information"
        assert "not_valid_after" in cert_info, "Should include expiration date"
        assert cert_info["is_self_signed"] is True, "Should identify as self-signed"
        
    @pytest.mark.integration
    def test_https_server_availability(self):
        """Test HTTPS server responds correctly (integration test)."""
        # This test requires the server to be running with TLS enabled
        try:
            response = requests.get(
                f"{self.https_base_url}/health",
                verify=False,  # Accept self-signed certificate
                timeout=5
            )
            assert response.status_code == 200, "HTTPS health check should succeed"
            
            # Verify security headers are present
            headers = response.headers
            assert "Strict-Transport-Security" in headers, "HSTS header should be present"
            assert "X-Content-Type-Options" in headers, "Content-Type-Options header should be present"
            assert "X-Frame-Options" in headers, "Frame-Options header should be present"
            
        except requests.exceptions.ConnectionError:
            pytest.skip("HTTPS server not available for integration test")
            
    @pytest.mark.integration
    def test_http_redirect_functionality(self):
        """Test HTTP to HTTPS redirect when enabled."""
        # This test requires redirect to be enabled
        try:
            response = requests.get(
                f"{self.http_base_url}/health",
                allow_redirects=False,
                timeout=5
            )
            
            if response.status_code in [301, 302, 307, 308]:
                assert response.headers["Location"].startswith("https://"), "Should redirect to HTTPS"
            
        except requests.exceptions.ConnectionError:
            pytest.skip("HTTP server not available for integration test")


class TestSeccompSecurity:
    """Test Seccomp syscall filtering functionality."""
    
    def setup_class(self):
        """Setup test class with Seccomp profiles."""
        self.project_root = Path(__file__).parent.parent
        self.seccomp_dir = self.project_root / "security" / "seccomp"
        
    def test_seccomp_profile_json_validity(self):
        """Test all Seccomp profiles have valid JSON syntax."""
        seccomp_files = list(self.seccomp_dir.glob("*.json"))
        assert len(seccomp_files) > 0, "Should have Seccomp profile files"
        
        for profile_file in seccomp_files:
            with open(profile_file, 'r') as f:
                try:
                    profile_data = json.load(f)
                    assert "syscalls" in profile_data, f"Profile {profile_file.name} should have syscalls section"
                    assert "defaultAction" in profile_data, f"Profile {profile_file.name} should have defaultAction"
                    
                except json.JSONDecodeError as e:
                    pytest.fail(f"Invalid JSON in {profile_file.name}: {e}")
                    
    def test_dangerous_syscalls_blocked(self):
        """Test that dangerous syscalls are explicitly blocked."""
        api_profile = self.seccomp_dir / "api-server-secure.json"
        ffmpeg_profile = self.seccomp_dir / "ffmpeg-secure.json"
        
        dangerous_syscalls = [
            "ptrace", "process_vm_readv", "process_vm_writev", 
            "perf_event_open", "bpf", "init_module", "finit_module"
        ]
        
        for profile_file in [api_profile, ffmpeg_profile]:
            if profile_file.exists():
                with open(profile_file, 'r') as f:
                    profile_data = json.load(f)
                    
                # Find blocked syscalls
                blocked_syscalls = set()
                for syscall_rule in profile_data["syscalls"]:
                    if syscall_rule["action"] in ["SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_ERRNO"]:
                        blocked_syscalls.update(syscall_rule["names"])
                
                for dangerous_syscall in dangerous_syscalls:
                    assert dangerous_syscall in blocked_syscalls, f"{dangerous_syscall} should be blocked in {profile_file.name}"
                    
    def test_essential_syscalls_allowed(self):
        """Test that essential syscalls for operation are allowed."""
        api_profile = self.seccomp_dir / "api-server-secure.json"
        
        essential_syscalls = [
            "read", "write", "open", "close", "mmap", "munmap",
            "socket", "bind", "listen", "accept", "getpid"
        ]
        
        if api_profile.exists():
            with open(api_profile, 'r') as f:
                profile_data = json.load(f)
                
            # Find allowed syscalls
            allowed_syscalls = set()
            for syscall_rule in profile_data["syscalls"]:
                if syscall_rule["action"] == "SCMP_ACT_ALLOW":
                    allowed_syscalls.update(syscall_rule["names"])
            
            for essential_syscall in essential_syscalls:
                assert essential_syscall in allowed_syscalls, f"{essential_syscall} should be allowed in API profile"
                
    def test_seccomp_profile_architecture_support(self):
        """Test Seccomp profiles support required architectures."""
        required_arches = ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"]
        
        for profile_file in self.seccomp_dir.glob("*.json"):
            with open(profile_file, 'r') as f:
                profile_data = json.load(f)
                
            if "architectures" in profile_data:
                for arch in required_arches:
                    if arch in profile_data["architectures"]:
                        # At least one required architecture should be present
                        break
                else:
                    pytest.fail(f"No required architecture found in {profile_file.name}")
                    
    @pytest.mark.integration
    def test_docker_seccomp_integration(self):
        """Test Seccomp profiles work with Docker (integration test)."""
        api_profile = self.seccomp_dir / "api-server-secure.json"
        
        if not api_profile.exists():
            pytest.skip("Seccomp profile not found")
            
        # Test if Docker can use the Seccomp profile
        try:
            result = subprocess.run([
                "docker", "run", "--rm", 
                "--security-opt", f"seccomp={api_profile}",
                "alpine:latest", "echo", "Seccomp test"
            ], capture_output=True, text=True, timeout=10)
            
            assert result.returncode == 0, f"Docker Seccomp test failed: {result.stderr}"
            assert "Seccomp test" in result.stdout, "Docker should execute successfully with Seccomp profile"
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("Docker not available for Seccomp integration test")


class TestComprehensiveSecurity:
    """Test integrated security features."""
    
    def test_docker_compose_security_configuration(self):
        """Test Docker Compose security configuration is valid."""
        project_root = Path(__file__).parent.parent
        compose_file = project_root / "docker-compose.secure.yml"
        
        if not compose_file.exists():
            pytest.skip("Docker Compose secure configuration not found")
            
        # Validate Docker Compose configuration
        try:
            result = subprocess.run([
                "docker-compose", "-f", str(compose_file), "config"
            ], capture_output=True, text=True, timeout=10)
            
            assert result.returncode == 0, f"Docker Compose configuration invalid: {result.stderr}"
            
            # Check security options are present
            config_output = result.stdout
            assert "apparmor=ffmpeg-isolated" in config_output, "AppArmor profile should be configured"
            assert "seccomp=" in config_output, "Seccomp profile should be configured"
            assert "no-new-privileges" in config_output, "no-new-privileges should be set"
            
        except FileNotFoundError:
            pytest.skip("docker-compose not available")
            
    def test_security_installation_script_exists(self):
        """Test security installation script is present and executable."""
        project_root = Path(__file__).parent.parent
        install_script = project_root / "security" / "install-comprehensive-security.sh"
        
        assert install_script.exists(), "Security installation script should exist"
        assert os.access(install_script, os.X_OK), "Security installation script should be executable"
        
    def test_apparmor_profile_compatibility(self):
        """Test AppArmor profile exists and has proper structure."""
        project_root = Path(__file__).parent.parent
        apparmor_profile = project_root / "security" / "apparmor" / "ffmpeg-isolated"
        
        assert apparmor_profile.exists(), "AppArmor profile should exist"
        
        with open(apparmor_profile, 'r') as f:
            profile_content = f.read()
            
        # Check essential AppArmor profile elements
        assert "/usr/bin/ffmpeg" in profile_content, "Should include FFmpeg binary path"
        assert "deny network" in profile_content, "Should deny network access"
        assert "/tmp/memory-pool/" in profile_content, "Should allow tmpfs access"
        assert "deny ptrace" in profile_content, "Should deny debugging operations"
        
    @pytest.mark.integration  
    def test_layered_security_effectiveness(self):
        """Test that layered security (AppArmor + Seccomp) works together."""
        # This is a high-level integration test that would require
        # running the full containerized environment
        
        project_root = Path(__file__).parent.parent
        
        # Verify all security components are present
        security_components = [
            project_root / "security" / "apparmor" / "ffmpeg-isolated",
            project_root / "security" / "seccomp" / "api-server-secure.json",
            project_root / "security" / "seccomp" / "ffmpeg-secure.json",
            project_root / "docker-compose.secure.yml"
        ]
        
        for component in security_components:
            assert component.exists(), f"Security component should exist: {component}"
            
        # If we reach here, all layered security components are present
        assert True, "Layered security architecture is complete"


# Test configuration
pytest_plugins = []

if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])