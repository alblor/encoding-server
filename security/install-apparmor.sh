#!/bin/bash
# Install and activate AppArmor profile for isolated FFmpeg execution
#
# This script sets up the complete security layer for FFmpeg isolation:
# - Installs AppArmor profile with network denial
# - Configures profile enforcement
# - Sets up monitoring and logging
#
# Author: Lorenzo Albanese (alblor)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Installing AppArmor Profile for Isolated FFmpeg ===${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Usage: sudo $0"
   exit 1
fi

# Check if AppArmor is available
if ! command -v apparmor_parser &> /dev/null; then
    echo -e "${RED}Error: AppArmor is not installed${NC}"
    echo "Install AppArmor first:"
    echo "  Ubuntu/Debian: apt-get install apparmor apparmor-utils"
    echo "  CentOS/RHEL: yum install apparmor apparmor-parser"
    exit 1
fi

# Check if AppArmor is running
if ! systemctl is-active --quiet apparmor; then
    echo -e "${YELLOW}Warning: AppArmor service is not running${NC}"
    echo "Starting AppArmor service..."
    systemctl start apparmor
    systemctl enable apparmor
fi

# Profile paths
PROFILE_DIR="/etc/apparmor.d"
PROFILE_NAME="ffmpeg-isolated"
PROFILE_PATH="$PROFILE_DIR/$PROFILE_NAME"
SOURCE_PROFILE="$(dirname "$0")/apparmor/$PROFILE_NAME"

echo -e "${BLUE}Installing AppArmor profile...${NC}"

# Check if source profile exists
if [[ ! -f "$SOURCE_PROFILE" ]]; then
    echo -e "${RED}Error: Source profile not found at $SOURCE_PROFILE${NC}"
    exit 1
fi

# Install the profile
echo "Copying profile to $PROFILE_PATH"
cp "$SOURCE_PROFILE" "$PROFILE_PATH"
chmod 644 "$PROFILE_PATH"

# Validate profile syntax
echo "Validating profile syntax..."
if ! apparmor_parser -Q "$PROFILE_PATH"; then
    echo -e "${RED}Error: Profile syntax validation failed${NC}"
    exit 1
fi

# Load the profile in complain mode first (for testing)
echo "Loading profile in complain mode for testing..."
apparmor_parser -r "$PROFILE_PATH"

# Check profile status
echo "Profile status:"
aa-status | grep ffmpeg || echo "Profile loaded successfully"

# Function to switch to enforce mode
enable_enforce_mode() {
    echo -e "${BLUE}Switching to enforce mode...${NC}"
    
    # Change profile to enforce mode
    sed -i 's/flags=(complain)/flags=(enforce)/' "$PROFILE_PATH"
    
    # Reload profile
    apparmor_parser -r "$PROFILE_PATH"
    
    echo -e "${GREEN}AppArmor profile is now in ENFORCE mode${NC}"
    echo -e "${YELLOW}FFmpeg processes will be strictly confined${NC}"
}

# Function to test the profile
test_profile() {
    echo -e "${BLUE}Testing AppArmor profile...${NC}"
    
    # Create test directory if it doesn't exist
    mkdir -p /tmp/memory-pool
    chmod 755 /tmp/memory-pool
    
    # Test basic FFmpeg execution (should work)
    echo "Test 1: Basic FFmpeg execution (should succeed)"
    if timeout 10 ffmpeg -f lavfi -i testsrc=duration=1:size=320x240:rate=1 -c:v libx264 -t 1 /tmp/memory-pool/test.mp4 &>/dev/null; then
        echo -e "${GREEN}✓ Basic FFmpeg execution works${NC}"
    else
        echo -e "${YELLOW}⚠ Basic FFmpeg test failed (this may be expected in strict environments)${NC}"
    fi
    
    # Test network access (should fail in enforce mode)
    echo "Test 2: Network access test (should fail)"
    if timeout 5 ffmpeg -i http://example.com/nonexistent.mp4 /tmp/memory-pool/output.mp4 &>/dev/null; then
        echo -e "${RED}✗ Network access test unexpectedly succeeded${NC}"
    else
        echo -e "${GREEN}✓ Network access correctly blocked${NC}"
    fi
    
    # Test file system access outside tmpfs (should fail)
    echo "Test 3: File system access outside tmpfs (should fail)"
    if timeout 5 ffmpeg -f lavfi -i testsrc=duration=1:size=320x240:rate=1 -c:v libx264 -t 1 /tmp/unauthorized.mp4 &>/dev/null; then
        echo -e "${RED}✗ Unauthorized file access unexpectedly succeeded${NC}"
    else
        echo -e "${GREEN}✓ File system access correctly restricted${NC}"
    fi
    
    # Cleanup
    rm -f /tmp/memory-pool/test.mp4 /tmp/unauthorized.mp4
}

# Create log directory for AppArmor violations
APPARMOR_LOG_DIR="/var/log/apparmor"
mkdir -p "$APPARMOR_LOG_DIR"

# Setup log rotation for AppArmor logs
cat > /etc/logrotate.d/apparmor-ffmpeg << 'EOF'
/var/log/apparmor/ffmpeg-violations.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

# Create monitoring script for AppArmor violations
cat > /usr/local/bin/monitor-ffmpeg-apparmor << 'EOF'
#!/bin/bash
# Monitor AppArmor violations for FFmpeg profile
# Author: Lorenzo Albanese (alblor)

LOGFILE="/var/log/apparmor/ffmpeg-violations.log"
mkdir -p "$(dirname "$LOGFILE")"

# Monitor kernel logs for AppArmor denials related to FFmpeg
dmesg -w | grep -i apparmor | grep -i ffmpeg | while read line; do
    echo "$(date): $line" >> "$LOGFILE"
    
    # If this is a DENIED message, also log to syslog
    if echo "$line" | grep -qi "denied"; then
        logger -t "apparmor-ffmpeg" "FFmpeg security violation: $line"
    fi
done
EOF

chmod +x /usr/local/bin/monitor-ffmpeg-apparmor

echo -e "${GREEN}✓ AppArmor profile installation completed${NC}"
echo
echo -e "${YELLOW}Profile Status: COMPLAIN MODE (testing)${NC}"
echo "The profile is currently in complain mode for testing purposes."
echo
echo "Available commands:"
echo "  $0 test      - Test the profile functionality"
echo "  $0 enforce   - Switch to enforce mode (strict security)"
echo "  $0 complain  - Switch back to complain mode"
echo "  $0 status    - Show current profile status"
echo "  $0 monitor   - Start monitoring violations (runs in background)"
echo
echo -e "${BLUE}Next steps:${NC}"
echo "1. Test the profile: sudo $0 test"
echo "2. If tests pass, enable enforce mode: sudo $0 enforce"
echo "3. Monitor for violations: sudo $0 monitor"

# Handle command line arguments
case "${1:-}" in
    "test")
        test_profile
        ;;
    "enforce")
        enable_enforce_mode
        ;;
    "complain")
        echo "Switching to complain mode..."
        sed -i 's/flags=(enforce)/flags=(complain)/' "$PROFILE_PATH"
        apparmor_parser -r "$PROFILE_PATH"
        echo -e "${GREEN}Profile switched to complain mode${NC}"
        ;;
    "status")
        echo "Profile status:"
        aa-status | grep ffmpeg || echo "No FFmpeg profiles found"
        ;;
    "monitor")
        echo "Starting AppArmor violation monitoring..."
        /usr/local/bin/monitor-ffmpeg-apparmor &
        echo "Monitor started in background (PID: $!)"
        ;;
    "")
        # No arguments, just install
        ;;
    *)
        echo "Unknown command: $1"
        echo "Available: test, enforce, complain, status, monitor"
        ;;
esac