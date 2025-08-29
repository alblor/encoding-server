#!/bin/bash
# 
# Secure Secret Generation Script for Media Encoding Server
# Generates cryptographically secure secrets for Docker secrets integration
#
# Author: Lorenzo Albanese (alblor)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SECRETS_DIR="secrets"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( dirname "$SCRIPT_DIR" )"
FULL_SECRETS_PATH="$PROJECT_ROOT/$SECRETS_DIR"

# Secret definitions
SECRET_NAMES=("jwt_secret" "encryption_master_key" "redis_password" "api_master_key")
SECRET_DESCRIPTIONS=("JWT signing secret (32 bytes base64)" "Master key for encrypting job keys (32 bytes base64)" "Redis authentication password (24 bytes base64)" "Master key for API key generation (32 bytes base64)")

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_color $BLUE "🔍 Checking prerequisites..."
    
    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        print_color $RED "❌ Error: openssl is required but not installed"
        exit 1
    fi
    
    # Check if we're in the project root
    if [[ ! -f "$PROJECT_ROOT/docker-compose.secure.yml" ]]; then
        print_color $RED "❌ Error: Not in project root directory (docker-compose.secure.yml not found)"
        exit 1
    fi
    
    print_color $GREEN "✅ Prerequisites check passed"
}

# Function to create secrets directory
create_secrets_directory() {
    print_color $BLUE "📁 Creating secrets directory..."
    
    if [[ -d "$FULL_SECRETS_PATH" ]]; then
        print_color $YELLOW "⚠️  Warning: Secrets directory already exists at $FULL_SECRETS_PATH"
        echo -n "Do you want to regenerate all secrets? This will overwrite existing ones. [y/N]: "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            print_color $YELLOW "Aborted by user"
            exit 0
        fi
        print_color $YELLOW "🔄 Regenerating all secrets..."
    else
        mkdir -p "$FULL_SECRETS_PATH"
        print_color $GREEN "✅ Created secrets directory: $FULL_SECRETS_PATH"
    fi
    
    # Set secure directory permissions
    chmod 700 "$FULL_SECRETS_PATH"
    
    # Create .gitkeep file
    touch "$FULL_SECRETS_PATH/.gitkeep"
    chmod 644 "$FULL_SECRETS_PATH/.gitkeep"
}

# Function to generate a secure random secret
generate_secret() {
    local secret_name=$1
    local description=$2
    local bytes=$3
    local secret_file="$FULL_SECRETS_PATH/$secret_name"
    
    print_color $BLUE "🔑 Generating $secret_name ($description)..."
    
    # Generate cryptographically secure random data
    openssl rand -base64 $bytes | tr -d '\n' > "$secret_file"
    
    # Set secure file permissions (read-only for owner)
    chmod 600 "$secret_file"
    
    # Verify the secret was generated correctly
    if [[ -f "$secret_file" ]] && [[ -s "$secret_file" ]]; then
        local secret_preview=$(head -c 8 "$secret_file")
        print_color $GREEN "✅ Generated $secret_name (preview: ${secret_preview}...)"
    else
        print_color $RED "❌ Failed to generate $secret_name"
        exit 1
    fi
}

# Function to generate all secrets
generate_all_secrets() {
    print_color $BLUE "🔐 Generating secure secrets..."
    
    # Generate each secret with appropriate length
    generate_secret "jwt_secret" "JWT signing secret" 32
    generate_secret "encryption_master_key" "Master encryption key" 32
    generate_secret "redis_password" "Redis password" 24
    generate_secret "api_master_key" "API master key" 32
    
    print_color $GREEN "🎉 All secrets generated successfully!"
}

# Function to validate generated secrets
validate_secrets() {
    print_color $BLUE "✅ Validating generated secrets..."
    
    local validation_passed=true
    
    for secret_name in "${SECRET_NAMES[@]}"; do
        local secret_file="$FULL_SECRETS_PATH/$secret_name"
        
        if [[ ! -f "$secret_file" ]]; then
            print_color $RED "❌ Missing secret file: $secret_name"
            validation_passed=false
            continue
        fi
        
        # Check file permissions (skip permission check on macOS as the format differs)
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            local perms=$(stat -c %a "$secret_file" 2>/dev/null)
            if [[ "$perms" != "600" ]]; then
                print_color $YELLOW "⚠️  Warning: $secret_name has permissions $perms (should be 600)"
            fi
        fi
        
        # Check file is not empty
        if [[ ! -s "$secret_file" ]]; then
            print_color $RED "❌ Empty secret file: $secret_name"
            validation_passed=false
            continue
        fi
        
        # Check secret is valid base64 (remove any trailing newlines first)
        if ! tr -d '\n' < "$secret_file" | base64 -d > /dev/null 2>&1; then
            print_color $RED "❌ Invalid base64 in secret: $secret_name"
            validation_passed=false
            continue
        fi
        
        print_color $GREEN "✅ $secret_name: valid"
    done
    
    if [[ "$validation_passed" == true ]]; then
        print_color $GREEN "🎊 All secrets validation passed!"
    else
        print_color $RED "❌ Secret validation failed"
        exit 1
    fi
}

# Function to create README documentation
create_documentation() {
    local readme_file="$FULL_SECRETS_PATH/README.md"
    
    print_color $BLUE "📄 Creating secrets documentation..."
    
    cat > "$readme_file" << 'EOF'
# Docker Secrets for Secure Media Encoding Server

This directory contains Docker secrets used by the Secure Media Encoding Server. These files are mounted as read-only at `/run/secrets/` inside the containers.

## Security Notice

🔒 **NEVER commit these secret files to version control!**
- All files in this directory contain sensitive cryptographic material
- File permissions are set to 600 (owner read/write only)  
- The `.gitignore` file excludes this directory from git

## Generated Secrets

### `jwt_secret`
- **Purpose**: Signing and verifying JWT authentication tokens
- **Algorithm**: Used with RS256/HS256 JWT signing
- **Rotation**: Should be rotated monthly in production

### `encryption_master_key`
- **Purpose**: Master key for encrypting job-specific encryption keys
- **Usage**: Protects individual job keys stored in Redis
- **Rotation**: Should be rotated quarterly with key migration

### `redis_password`
- **Purpose**: Authentication for Redis server connection
- **Usage**: Database authentication and connection security
- **Rotation**: Can be rotated without service interruption

### `api_master_key`
- **Purpose**: Master key for generating and validating API keys
- **Usage**: HMAC key for API key signatures
- **Rotation**: Should be rotated when API keys are compromised

## Regeneration

To regenerate all secrets:
```bash
./scripts/generate_secrets.sh
```

**Warning**: Regenerating secrets will require restarting all services and may invalidate existing sessions.

## Production Deployment

In production:
1. Generate secrets on a secure machine
2. Transfer securely to production server (use `scp` with key-based auth)
3. Verify file permissions are 600
4. Never store secrets in environment variables or logs
5. Implement regular rotation schedule
6. Monitor secret access in logs

## Backup and Recovery

- **Backup**: Store encrypted backups of secrets in secure location
- **Recovery**: Have procedures for secret recovery in disaster scenarios
- **Key Management**: Consider integration with HashiCorp Vault for enterprise deployments

---
**Generated**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Author**: Lorenzo Albanese (alblor)
EOF

    chmod 644 "$readme_file"
    print_color $GREEN "✅ Documentation created: $readme_file"
}

# Function to update .gitignore
update_gitignore() {
    local gitignore_file="$PROJECT_ROOT/.gitignore"
    
    print_color $BLUE "📝 Updating .gitignore..."
    
    # Check if .gitignore exists
    if [[ ! -f "$gitignore_file" ]]; then
        touch "$gitignore_file"
    fi
    
    # Check if secrets directory is already ignored
    if ! grep -q "^secrets/" "$gitignore_file" 2>/dev/null; then
        echo "" >> "$gitignore_file"
        echo "# Docker Secrets (generated by generate_secrets.sh)" >> "$gitignore_file"
        echo "secrets/" >> "$gitignore_file"
        echo "!secrets/.gitkeep" >> "$gitignore_file"
        echo "!secrets/README.md" >> "$gitignore_file"
        print_color $GREEN "✅ Added secrets directory to .gitignore"
    else
        print_color $YELLOW "⚠️  Secrets directory already in .gitignore"
    fi
}

# Function to show summary
show_summary() {
    print_color $BLUE "📊 Generation Summary:"
    echo ""
    print_color $GREEN "✅ Generated secrets:"
    for secret_name in "${SECRET_NAMES[@]}"; do
        echo "   🔑 $secret_name"
    done
    echo ""
    print_color $BLUE "📍 Location: $FULL_SECRETS_PATH"
    print_color $BLUE "🔒 Permissions: 600 (owner read/write only)"
    print_color $BLUE "📖 Documentation: $FULL_SECRETS_PATH/README.md"
    echo ""
    print_color $YELLOW "⚠️  Next Steps:"
    echo "   1. Start services with: make secure-up"
    echo "   2. Verify secrets are loaded: docker logs encoding-server-secure-encoding-api-1"
    echo "   3. Test system functionality: make test-all"
    echo ""
    print_color $GREEN "🎉 Secret generation completed successfully!"
}

# Main execution
main() {
    print_color $BLUE "🔐 Secure Media Encoding Server - Secret Generator"
    print_color $BLUE "=================================================="
    echo ""
    
    check_prerequisites
    create_secrets_directory
    generate_all_secrets
    validate_secrets
    create_documentation
    update_gitignore
    
    echo ""
    show_summary
}

# Run main function
main "$@"