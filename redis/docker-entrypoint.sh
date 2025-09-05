#!/bin/sh
# Secure Redis Entrypoint for Docker-in-LXC Environments
# Handles Redis password from Docker secrets with fallback
# Author: Lorenzo Albanese (alblor)

set -e

SECURE_PASSWORD_FILE="/tmp/redis_password"
DOCKER_SECRET_FILE="/run/secrets/redis_password"
LOCAL_SECRET_FILE="/secrets/redis_password"

# Log function for consistent output
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] REDIS: $1"
}

log "Starting Redis with secure password handling..."

# Try to copy Redis password to accessible location
PASSWORD_LOADED=false

# Try Docker secrets first
if [ -f "$DOCKER_SECRET_FILE" ]; then
    if cp "$DOCKER_SECRET_FILE" "$SECURE_PASSWORD_FILE" 2>/dev/null; then
        chmod 400 "$SECURE_PASSWORD_FILE"
        log "✅ Loaded password from Docker secrets"
        PASSWORD_LOADED=true
    else
        log "⚠️  Permission denied accessing Docker secret password"
    fi
fi

# Try local secrets fallback
if [ "$PASSWORD_LOADED" = false ] && [ -f "$LOCAL_SECRET_FILE" ]; then
    if cp "$LOCAL_SECRET_FILE" "$SECURE_PASSWORD_FILE" 2>/dev/null; then
        chmod 400 "$SECURE_PASSWORD_FILE"
        log "✅ Loaded password from local secrets"
        PASSWORD_LOADED=true
    else
        log "⚠️  Permission denied accessing local secret password"
    fi
fi

# Check for environment variable fallback
if [ "$PASSWORD_LOADED" = false ] && [ -n "$REDIS_PASSWORD" ]; then
    echo "$REDIS_PASSWORD" > "$SECURE_PASSWORD_FILE"
    chmod 400 "$SECURE_PASSWORD_FILE"
    log "✅ Loaded password from environment variable"
    PASSWORD_LOADED=true
fi

# Start Redis with or without authentication
if [ "$PASSWORD_LOADED" = true ] && [ -f "$SECURE_PASSWORD_FILE" ]; then
    PASSWORD=$(cat "$SECURE_PASSWORD_FILE")
    if [ -n "$PASSWORD" ]; then
        log "Starting Redis with authentication enabled"
        # Clean up password file from tmpfs after reading
        rm -f "$SECURE_PASSWORD_FILE"
        exec redis-server --requirepass "$PASSWORD"
    else
        log "⚠️  Password file empty, starting without authentication"
        exec redis-server
    fi
else
    log "⚠️  No password found, starting Redis without authentication"
    log "💡 Generate secrets with: ./scripts/generate_secrets.sh"
    exec redis-server
fi