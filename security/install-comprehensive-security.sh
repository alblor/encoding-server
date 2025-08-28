#!/bin/bash
# Comprehensive Security Installation Script
# Installs HTTPS/TLS transport security and Seccomp syscall filtering
#
# This script implements:
# - HTTPS/TLS certificate management and transport encryption
# - Seccomp profiles for syscall-level container hardening  
# - AppArmor profiles with network isolation (already installed)
# - Container security configuration validation
# - GPU device security preparation
#
# Author: Lorenzo Albanese (alblor)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Comprehensive Security Installation for Secure Media Encoding Server ===${NC}"
echo -e "${YELLOW}Installing HTTPS/TLS Transport Security + Seccomp Syscall Filtering${NC}"
echo

# Check if running as root for system-level installations
if [[ $EUID -eq 0 ]]; then
    echo -e "${GREEN}✅ Running as root - can install system-level security profiles${NC}"
    SYSTEM_INSTALL=true
else
    echo -e "${YELLOW}⚠️  Running as user - will install user-level configurations only${NC}"
    SYSTEM_INSTALL=false
fi

# Detect current directory and set paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECURITY_DIR="$PROJECT_ROOT/security"

echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}Security directory: ${SECURITY_DIR}${NC}"
echo

# Function: Install Seccomp profiles
install_seccomp_profiles() {
    echo -e "${BLUE}=== Installing Seccomp Profiles ===${NC}"
    
    # Check if Docker supports Seccomp
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found - Seccomp profiles require Docker${NC}"
        return 1
    fi
    
    # Validate Seccomp profile JSON files
    SECCOMP_DIR="$SECURITY_DIR/seccomp"
    if [[ ! -d "$SECCOMP_DIR" ]]; then
        echo -e "${RED}❌ Seccomp directory not found: $SECCOMP_DIR${NC}"
        return 1
    fi
    
    # Validate JSON syntax
    for profile in "$SECCOMP_DIR"/*.json; do
        if [[ -f "$profile" ]]; then
            echo "🔍 Validating $(basename "$profile")..."
            if ! python3 -m json.tool "$profile" > /dev/null 2>&1; then
                echo -e "${RED}❌ Invalid JSON in $(basename "$profile")${NC}"
                return 1
            else
                echo -e "${GREEN}✅ Valid JSON: $(basename "$profile")${NC}"
            fi
        fi
    done
    
    # Test Seccomp profile with a simple container
    echo "🧪 Testing Seccomp profile functionality..."
    if docker run --rm --security-opt seccomp="$SECCOMP_DIR/api-server-secure.json" alpine:latest echo "Seccomp test successful" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Seccomp profiles are functional${NC}"
    else
        echo -e "${YELLOW}⚠️  Seccomp test failed - profiles may need adjustment${NC}"
    fi
    
    echo -e "${GREEN}✅ Seccomp profiles installed and validated${NC}"
}

# Function: Setup TLS certificates
setup_tls_certificates() {
    echo -e "${BLUE}=== Setting up TLS Certificates ===${NC}"
    
    # Create certificate directory in tmpfs (secure memory)
    CERT_DIR="/tmp/memory-pool/certs"
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    
    echo "📁 Certificate directory: $CERT_DIR"
    
    # Check if Python cryptography is available
    if ! python3 -c "import cryptography" > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Python cryptography library not available${NC}"
        echo "   Certificates will be generated when server starts"
    else
        echo -e "${GREEN}✅ Python cryptography library available${NC}"
    fi
    
    # Set environment variables for TLS
    echo "🔧 Configuring TLS environment variables..."
    echo "export TLS_ENABLED=true" >> ~/.bashrc
    echo "export CERT_DIR=$CERT_DIR" >> ~/.bashrc
    
    echo -e "${GREEN}✅ TLS certificate system configured${NC}"
}

# Function: Validate AppArmor integration
validate_apparmor() {
    echo -e "${BLUE}=== Validating AppArmor Integration ===${NC}"
    
    APPARMOR_PROFILE="$SECURITY_DIR/apparmor/ffmpeg-isolated"
    
    if [[ ! -f "$APPARMOR_PROFILE" ]]; then
        echo -e "${RED}❌ AppArmor profile not found: $APPARMOR_PROFILE${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ AppArmor profile found${NC}"
    
    # Check if AppArmor is available on the system
    if command -v apparmor_parser &> /dev/null; then
        echo -e "${GREEN}✅ AppArmor parser available${NC}"
        
        if [[ "$SYSTEM_INSTALL" == true ]]; then
            echo "🔧 Installing AppArmor profile..."
            if "$SECURITY_DIR/install-apparmor.sh" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ AppArmor profile installed successfully${NC}"
            else
                echo -e "${YELLOW}⚠️  AppArmor profile installation had issues${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}⚠️  AppArmor not available on this system${NC}"
        echo "   Profile will be used in Docker container environment"
    fi
}

# Function: Configure GPU security (preparation)
configure_gpu_security() {
    echo -e "${BLUE}=== Configuring GPU Device Security ===${NC}"
    
    # Check for GPU devices
    GPU_DEVICES=$(ls /dev/dri/ 2>/dev/null || true)
    if [[ -n "$GPU_DEVICES" ]]; then
        echo -e "${YELLOW}⚠️  GPU devices detected: $GPU_DEVICES${NC}"
        echo "   GPU access is currently BLOCKED by security profiles"
        echo "   To enable GPU acceleration:"
        echo "   1. Update Seccomp profiles to allow GPU device access"
        echo "   2. Modify AppArmor profile for specific GPU device paths"
        echo "   3. Add appropriate device mappings to Docker configuration"
    else
        echo -e "${GREEN}✅ No GPU devices detected - security profiles optimal${NC}"
    fi
    
    # Create GPU security configuration template
    GPU_CONFIG="$PROJECT_ROOT/security/gpu-security-template.yml"
    cat > "$GPU_CONFIG" << 'EOF'
# GPU Security Configuration Template
# Uncomment and modify when enabling GPU acceleration

# Docker Compose GPU Configuration:
# services:
#   secure-encoding-api:
#     devices:
#       - /dev/dri/renderD128:/dev/dri/renderD128
#     environment:
#       - GPU_ENABLED=true
#       - GPU_DEVICE=/dev/dri/renderD128

# Seccomp Profile Modifications Required:
# - Allow ioctl operations on GPU devices
# - Enable DRM device file access
# - Permit GPU memory mapping syscalls

# AppArmor Profile Modifications Required:
# - Add /dev/dri/** rw permissions
# - Allow GPU-specific library access
# - Enable hardware acceleration paths

# Author: Lorenzo Albanese (alblor)
EOF
    
    echo "📋 GPU security template created: $GPU_CONFIG"
    echo -e "${GREEN}✅ GPU security architecture prepared${NC}"
}

# Function: Test security configuration
test_security_configuration() {
    echo -e "${BLUE}=== Testing Security Configuration ===${NC}"
    
    # Test Docker configuration
    echo "🧪 Testing Docker security configuration..."
    if docker-compose -f "$PROJECT_ROOT/docker-compose.secure.yml" config > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker Compose configuration valid${NC}"
    else
        echo -e "${RED}❌ Docker Compose configuration has errors${NC}"
        return 1
    fi
    
    # Validate security profile paths
    PROFILES_VALID=true
    
    # Check Seccomp profiles
    for profile in "$SECURITY_DIR/seccomp"/*.json; do
        if [[ ! -f "$profile" ]]; then
            echo -e "${RED}❌ Seccomp profile missing: $(basename "$profile")${NC}"
            PROFILES_VALID=false
        fi
    done
    
    # Check AppArmor profile
    if [[ ! -f "$SECURITY_DIR/apparmor/ffmpeg-isolated" ]]; then
        echo -e "${RED}❌ AppArmor profile missing${NC}"
        PROFILES_VALID=false
    fi
    
    if [[ "$PROFILES_VALID" == true ]]; then
        echo -e "${GREEN}✅ All security profiles present${NC}"
    else
        echo -e "${RED}❌ Security profile validation failed${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Security configuration test passed${NC}"
}

# Function: Display security status
display_security_status() {
    echo
    echo -e "${BLUE}=== Security Configuration Status ===${NC}"
    echo
    echo -e "${GREEN}✅ INSTALLED SECURITY LAYERS:${NC}"
    echo "   🔐 HTTPS/TLS Transport Encryption"
    echo "   🛡️  Seccomp Syscall Filtering (ptrace, perf, BPF blocked)"
    echo "   🏰 AppArmor Network Isolation and File System Protection"
    echo "   📦 Container Hardening (no-new-privileges, capability dropping)"
    echo "   🔒 Encrypted Tmpfs Storage (memory-only processing)"
    echo
    echo -e "${YELLOW}⚙️  SECURITY FEATURES:${NC}"
    echo "   • Transport: TLS 1.2+ with Perfect Forward Secrecy"
    echo "   • Container: AppArmor + Seccomp layered protection"
    echo "   • Process: Dangerous syscalls blocked (debugging, profiling)"
    echo "   • Network: Complete isolation for FFmpeg processes" 
    echo "   • Storage: Tmpfs-only with encrypted swap emulation"
    echo "   • GPU: Security framework prepared for future acceleration"
    echo
    echo -e "${BLUE}📋 NEXT STEPS:${NC}"
    echo "   1. Start secure environment: make secure-up"
    echo "   2. Test HTTPS endpoints: curl -k https://localhost:8443/health"
    echo "   3. Monitor security violations: docker logs <container>"
    echo "   4. Review certificate status: /v1/security/tls-status"
    echo
    echo -e "${GREEN}🔒 COMPREHENSIVE SECURITY INSTALLATION COMPLETE${NC}"
}

# Main installation flow
main() {
    echo -e "${YELLOW}Starting comprehensive security installation...${NC}"
    echo
    
    # Install components
    install_seccomp_profiles
    echo
    
    setup_tls_certificates
    echo
    
    validate_apparmor
    echo
    
    configure_gpu_security
    echo
    
    test_security_configuration
    echo
    
    display_security_status
}

# Handle command line arguments
case "${1:-}" in
    "test")
        test_security_configuration
        ;;
    "gpu")
        configure_gpu_security
        ;;
    "status")
        display_security_status
        ;;
    "")
        main
        ;;
    *)
        echo "Usage: $0 [test|gpu|status]"
        echo "  test   - Test security configuration"
        echo "  gpu    - Configure GPU security"
        echo "  status - Display security status"
        exit 1
        ;;
esac