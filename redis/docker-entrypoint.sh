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

# Restoration workers get their own Redis user. It sees only the restore queues, the job and cancel records and its own
# heartbeat key, and may run only the six commands the worker uses: no KEYS, CONFIG or FLUSH, no `key:*` or `restore:pw:*`
# records, so a compromised ffmpeg worker cannot read an encryption key or a wrapped password. The default user keeps
# the main password for the API. Without the worker secret no such user exists and the workers cannot connect.
WORKER_PASSWORD=""
for candidate in /run/secrets/restore_worker_redis_password /secrets/restore_worker_redis_password; do
    if [ -f "$candidate" ]; then
        WORKER_PASSWORD=$(cat "$candidate" 2>/dev/null || true)
        [ -n "$WORKER_PASSWORD" ] && break
    fi
done
# A shredded host copy holds a marker text, not a secret: as a password it would be guessable, so it is refused.
case "$WORKER_PASSWORD" in
    SHREDDED_FOR_SECURITY*)
        log "⚠️  restore_worker_redis_password is a shred marker, not a secret: no worker user is created"
        WORKER_PASSWORD="" ;;
esac

# Start Redis with or without authentication
if [ "$PASSWORD_LOADED" = true ] && [ -f "$SECURE_PASSWORD_FILE" ]; then
    PASSWORD=$(cat "$SECURE_PASSWORD_FILE")
    case "$PASSWORD" in
        SHREDDED_FOR_SECURITY*)
            log "❌ redis_password is a shred marker, not a secret: restore the secrets (make secure-down) or regenerate them"
            exit 1 ;;
    esac
    if [ -n "$PASSWORD" ]; then
        log "Starting Redis with authentication enabled"
        # Clean up password file from tmpfs after reading
        rm -f "$SECURE_PASSWORD_FILE"
        if [ -n "$WORKER_PASSWORD" ]; then
            log "Adding the restricted restore-worker user"
            exec redis-server --requirepass "$PASSWORD" \
                --user restore-worker on ">$WORKER_PASSWORD" \
                "~restore:queue:*" "~restore:job:*" "~restore:cancel:*" "~restore:worker:*" \
                -@all +brpop +hset +hgetall +get +expire +ping "+client|setinfo"
        fi
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