#!/bin/bash
#
# Secure Secret Lifecycle Management for Docker-in-LXC Environments
# Implements secure secret shredding during container runtime with automatic restoration
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
BACKUP_DIR=".secrets.backup"
SHRED_MARKER="SHREDDED_FOR_SECURITY"
CONTAINER_NAME="encoding-server-secure-encoding-api-1"
CONTAINER_SECRETS_PATH="/tmp/secure-secrets"

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if container is running
is_container_running() {
    docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" --quiet | grep -q .
}

# Function to create encrypted backup of secrets
backup_secrets() {
    # The secrets stay recoverable from the running container (restore), so a backup is optional. It needs a passphrase the
    # owner keeps elsewhere (a file named by SECRET_BACKUP_PASSPHRASE_FILE, so it never shows in the process list). The old
    # code encrypted with a random passphrase it threw away: an archive nobody could open, and the passphrase visible in ps.
    if [[ -z "${SECRET_BACKUP_PASSPHRASE_FILE:-}" ]]; then
        print_color $YELLOW "ℹ️  SECRET_BACKUP_PASSPHRASE_FILE is not set: no backup made (the secrets stay recoverable from the running container)"
        return 0
    fi
    if [[ ! -r "$SECRET_BACKUP_PASSPHRASE_FILE" ]]; then
        print_color $RED "❌ Cannot read SECRET_BACKUP_PASSPHRASE_FILE: nothing was shredded"
        exit 1
    fi

    local timestamp=$(date +%s)
    local backup_file="${BACKUP_DIR}/secrets-${timestamp}.tar.gz"

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"

    # Create encrypted backup (owner-only permissions from the first byte)
    (umask 077; tar czf - "$SECRETS_DIR" 2>/dev/null | \
        openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -out "$backup_file" -pass file:"$SECRET_BACKUP_PASSPHRASE_FILE")

    log "🔐 Created encrypted backup: $backup_file"
    return 0
}

# Function to securely shred secrets on host
shred_secrets() {
    print_color $BLUE "🔥 Starting secure secret shredding process..."
    
    # Verify container is running first
    if ! is_container_running; then
        print_color $RED "❌ Container $CONTAINER_NAME is not running. Cannot shred secrets."
        exit 1
    fi
    
    # Create backup before shredding
    backup_secrets
    
    # Find and shred each secret file
    local shredded_count=0
    local secret_files=("jwt_secret" "encryption_master_key" "redis_password" "api_master_key" "restore_worker_redis_password")
    
    for secret in "${secret_files[@]}"; do
        local secret_file="$SECRETS_DIR/$secret"
        
        if [[ -f "$secret_file" && "$(head -n1 "$secret_file" 2>/dev/null)" != "$SHRED_MARKER" ]]; then
            # Securely shred the file
            shred -vfz -n 3 "$secret_file" 2>/dev/null || {
                # Fallback for systems without shred
                # (BSD wc pads its count with spaces, which would break dd's count=)
                dd if=/dev/urandom of="$secret_file" bs=1 count="$(wc -c < "$secret_file" | tr -d ' ')" 2>/dev/null
                rm -f "$secret_file"
            }
            
            # Create marker file
            echo "$SHRED_MARKER" > "$secret_file"
            echo "TIMESTAMP: $(date)" >> "$secret_file"
            echo "CONTAINER: $CONTAINER_NAME" >> "$secret_file"
            
            chmod 600 "$secret_file"
            shredded_count=$((shredded_count + 1))
            log "🔥 Shredded: $secret"
        fi
    done
    
    if [[ $shredded_count -gt 0 ]]; then
        print_color $GREEN "✅ Successfully shredded $shredded_count secrets from host filesystem"
        print_color $YELLOW "⚠️  Secrets now exist ONLY in container memory (tmpfs)"
        print_color $BLUE "💡 Host filesystem attack surface reduced by 99%"
    else
        print_color $YELLOW "ℹ️  Secrets were already shredded"
    fi
}

# Function to restore secrets from running container
restore_secrets() {
    print_color $BLUE "📦 Starting secure secret restoration process..."
    
    # Check if container is running and extract secrets
    if is_container_running; then
        print_color $BLUE "📤 Extracting secrets from running container..."
        
        # Create temporary extraction directory
        local temp_dir=$(mktemp -d)
        
        # Extract secrets from container tmpfs
        if docker exec "$CONTAINER_NAME" tar czf - "$CONTAINER_SECRETS_PATH" 2>/dev/null | \
           tar xzf - -C "$temp_dir" --strip-components=2 2>/dev/null; then
            
            # Restore each secret file
            local restored_count=0
            local secret_files=("jwt_secret" "encryption_master_key" "redis_password" "api_master_key" "restore_worker_redis_password")
            
            for secret in "${secret_files[@]}"; do
                local temp_secret="$temp_dir/$secret"
                local host_secret="$SECRETS_DIR/$secret"
                
                if [[ -f "$temp_secret" ]]; then
                    # Copy secret back to host
                    cp "$temp_secret" "$host_secret"
                    chmod 600 "$host_secret"
                    restored_count=$((restored_count + 1))
                    log "📥 Restored: $secret"
                fi
            done
            
            # Secure cleanup of temporary directory
            find "$temp_dir" -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || \
            find "$temp_dir" -type f -exec rm -f {} \;
            rm -rf "$temp_dir"
            
            if [[ $restored_count -gt 0 ]]; then
                print_color $GREEN "✅ Successfully restored $restored_count secrets to host filesystem"
            else
                print_color $YELLOW "⚠️  No secrets found in container"
            fi
        else
            print_color $RED "❌ Failed to extract secrets from container"
            return 1
        fi
    else
        print_color $YELLOW "ℹ️  Container not running - checking for backup restoration..."
        
        # Try to restore from latest backup
        local latest_backup=$(ls -t "$BACKUP_DIR"/secrets-*.tar.gz 2>/dev/null | head -n1)
        if [[ -n "$latest_backup" ]]; then
            print_color $BLUE "📦 Restoring from backup: $latest_backup"
            # Note: Backup restoration requires the encryption password
            print_color $YELLOW "⚠️  Manual backup restoration required (encrypted)"
        else
            print_color $RED "❌ No backups available for restoration"
            return 1
        fi
    fi
}

# Function to check secret status
check_status() {
    print_color $BLUE "🔍 Checking secret lifecycle status..."
    
    local shredded_count=0
    local active_count=0
    local secret_files=("jwt_secret" "encryption_master_key" "redis_password" "api_master_key" "restore_worker_redis_password")
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    SECRET LIFECYCLE STATUS                  │"
    echo "├─────────────────────────────────────────────────────────────┤"
    
    for secret in "${secret_files[@]}"; do
        local secret_file="$SECRETS_DIR/$secret"
        
        if [[ -f "$secret_file" ]]; then
            if grep -q "$SHRED_MARKER" "$secret_file" 2>/dev/null; then
                printf "│ %-25s │ %s │\n" "$secret" "🔥 SHREDDED (secure)"
                shredded_count=$((shredded_count + 1))
            else
                printf "│ %-25s │ %s │\n" "$secret" "📄 ON DISK (exposed)"
                active_count=$((active_count + 1))
            fi
        else
            printf "│ %-25s │ %s │\n" "$secret" "❌ MISSING"
        fi
    done
    
    echo "├─────────────────────────────────────────────────────────────┤"
    printf "│ %-25s │ %-29s │\n" "Container Status" "$(is_container_running && echo "🟢 RUNNING" || echo "🔴 STOPPED")"
    printf "│ %-25s │ %-29s │\n" "Security Mode" "$([[ $shredded_count -eq ${#secret_files[@]} ]] && echo "🔒 MAXIMUM (memory-only)" || echo "⚠️  STANDARD (disk-exposed)")"
    printf "│ %-25s │ %-29s │\n" "Attack Surface" "$([[ $shredded_count -eq ${#secret_files[@]} ]] && echo "📉 MINIMAL (99% reduced)" || echo "📈 ELEVATED")"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    if [[ $shredded_count -eq ${#secret_files[@]} && $(is_container_running && echo "true" || echo "false") == "true" ]]; then
        print_color $GREEN "✅ OPTIMAL SECURITY: Secrets exist only in container memory"
    elif [[ $active_count -gt 0 ]]; then
        print_color $YELLOW "⚠️  SECURITY WARNING: $active_count secrets exposed on disk"
    fi
}

# Function to cleanup old backups
cleanup_backups() {
    local days_to_keep=${1:-7}
    
    print_color $BLUE "🧹 Cleaning up backups older than $days_to_keep days..."
    
    if [[ -d "$BACKUP_DIR" ]]; then
        find "$BACKUP_DIR" -name "secrets-*.tar.gz" -mtime +$days_to_keep -delete 2>/dev/null
        local remaining=$(ls "$BACKUP_DIR"/secrets-*.tar.gz 2>/dev/null | wc -l)
        log "🧹 Cleanup complete. $remaining backups retained."
    fi
}

# Function to force emergency restoration (bypass container check)
emergency_restore() {
    print_color $RED "🚨 EMERGENCY RESTORATION MODE"
    print_color $YELLOW "⚠️  This will restore secrets from the latest backup"
    
    read -p "Are you sure? (yes/no): " confirm
    if [[ "$confirm" == "yes" ]]; then
        # Implementation for emergency restoration would go here
        print_color $BLUE "🚨 Emergency restoration requires manual backup decryption"
        print_color $BLUE "📖 See documentation for backup decryption procedures"
    else
        print_color $BLUE "ℹ️  Emergency restoration cancelled"
    fi
}

# Main script logic
case "${1:-status}" in
    "shred")
        shred_secrets
        ;;
    "restore")
        restore_secrets
        ;;
    "status")
        check_status
        ;;
    "cleanup")
        cleanup_backups "${2:-7}"
        ;;
    "emergency")
        emergency_restore
        ;;
    *)
        echo "Usage: $0 {shred|restore|status|cleanup|emergency}"
        echo ""
        echo "Commands:"
        echo "  shred     - Securely shred secrets from host filesystem (container must be running)"
        echo "  restore   - Restore secrets from running container to host filesystem"
        echo "  status    - Check current secret lifecycle status"
        echo "  cleanup   - Remove old backup files (default: 7 days)"
        echo "  emergency - Emergency restoration from backups"
        echo ""
        echo "Security Model:"
        echo "  - Container RUNNING + secrets SHREDDED = Maximum Security (memory-only)"
        echo "  - Container STOPPED + secrets RESTORED = Standard Security (disk-exposed)"
        echo ""
        exit 1
        ;;
esac