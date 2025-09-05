#!/bin/sh
# Secure Docker Entrypoint for Docker-in-LXC Environments
# Handles Docker secrets with graceful fallback to tmpfs copying
# Author: Lorenzo Albanese (alblor)

set -e

SECURE_SECRETS_DIR="/tmp/secure-secrets"
DOCKER_SECRETS_DIR="/run/secrets"
LOCAL_SECRETS_DIR="./secrets"

# Log function for consistent output
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Check if running as root (needed for initialization)
if [ "$(id -u)" = "0" ]; then
    log "INIT: Starting secure initialization as root..."
    
    # Create secure secrets directory in tmpfs
    mkdir -p "$SECURE_SECRETS_DIR"
    chmod 700 "$SECURE_SECRETS_DIR"
    log "INIT: Created secure secrets directory: $SECURE_SECRETS_DIR"
    
    # Define required secrets
    REQUIRED_SECRETS="jwt_secret encryption_master_key redis_password api_master_key"
    COPIED_COUNT=0
    FAILED_COUNT=0
    
    # Process each secret with multiple fallback paths
    for secret in $REQUIRED_SECRETS; do
        SECRET_COPIED=false
        
        # Try Docker secrets first (standard deployment)
        if [ -f "$DOCKER_SECRETS_DIR/$secret" ]; then
            if cp "$DOCKER_SECRETS_DIR/$secret" "$SECURE_SECRETS_DIR/$secret" 2>/dev/null; then
                # Set permissions readable by user 1000 (fallback to 644 if 440 fails)
                chmod 440 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || chmod 644 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || true
                # Try to set ownership, but make readable by all if that fails
                if ! chown 1000:1000 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null; then
                    chmod 644 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || true
                    log "INIT: ⚠️  Could not change ownership of $secret, using world-readable permissions"
                fi
                log "INIT: ✅ Copied Docker secret: $secret"
                SECRET_COPIED=true
                COPIED_COUNT=$((COPIED_COUNT + 1))
            else
                log "INIT: ⚠️  Permission denied copying Docker secret: $secret"
            fi
        fi
        
        # Try local secrets fallback (development/LXC fallback)
        if [ "$SECRET_COPIED" = false ] && [ -f "$LOCAL_SECRETS_DIR/$secret" ]; then
            if cp "$LOCAL_SECRETS_DIR/$secret" "$SECURE_SECRETS_DIR/$secret" 2>/dev/null; then
                # Set permissions readable by user 1000 (fallback to 644 if 440 fails)
                chmod 440 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || chmod 644 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || true
                # Try to set ownership, but make readable by all if that fails
                if ! chown 1000:1000 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null; then
                    chmod 644 "$SECURE_SECRETS_DIR/$secret" 2>/dev/null || true
                    log "INIT: ⚠️  Could not change ownership of $secret, using world-readable permissions"
                fi
                log "INIT: ✅ Copied local secret: $secret"
                SECRET_COPIED=true
                COPIED_COUNT=$((COPIED_COUNT + 1))
            else
                log "INIT: ⚠️  Permission denied copying local secret: $secret"
            fi
        fi
        
        # Log if secret was not found anywhere
        if [ "$SECRET_COPIED" = false ]; then
            log "INIT: ❌ Secret not found: $secret (checked Docker secrets and local)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
        fi
    done
    
    # Set final ownership and permissions on directory (non-fatal if restricted)
    if ! chown -R 1000:1000 "$SECURE_SECRETS_DIR" 2>/dev/null; then
        # If we can't set ownership, make directory world-readable/accessible
        chmod 755 "$SECURE_SECRETS_DIR" 2>/dev/null || true
        log "INIT: ⚠️  Could not change directory ownership, using world-accessible permissions"
    else
        # If ownership succeeded, use restrictive permissions
        chmod 750 "$SECURE_SECRETS_DIR" 2>/dev/null || true
    fi
    
    log "INIT: Secret copying complete - Success: $COPIED_COUNT, Failed: $FAILED_COUNT"
    
    # Verify we have critical secrets for startup
    if [ ! -f "$SECURE_SECRETS_DIR/jwt_secret" ]; then
        log "INIT: ❌ CRITICAL: jwt_secret not available - application may fail to start"
        log "INIT: 💡 Generate secrets with: ./scripts/generate_secrets.sh"
    fi
    
    # Export environment variable to tell SecretManager where to look
    export SECURE_SECRETS_PATH="$SECURE_SECRETS_DIR"
    
    # Check if su-exec is available (Alpine Linux)
    if command -v su-exec >/dev/null 2>&1; then
        log "INIT: Dropping privileges to user 1000 using su-exec..."
        exec su-exec 1000:1000 "$0" "$@"
    else
        # Fallback to su (less secure but compatible)
        log "INIT: Dropping privileges to user 1000 using su..."
        exec su encodinguser -c "$0 $*"
    fi
fi

# Now running as non-root user (encodinguser, UID 1000)
log "APP: Starting application as user $(id -u):$(id -g) ($(whoami))"

# Verify we can access the secrets directory
if [ -d "$SECURE_SECRETS_DIR" ]; then
    SECRET_COUNT=$(find "$SECURE_SECRETS_DIR" -type f | wc -l)
    log "APP: Found $SECRET_COUNT secrets in secure directory"
else
    log "APP: ⚠️  Secure secrets directory not found - using environment fallback"
fi

# Start the main Python application
log "APP: Executing main application..."
exec python3 main.py "$@"