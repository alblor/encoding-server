#!/bin/sh
# Restore worker entrypoint. Same pattern as the API's: start as root just long enough to move the restricted Redis
# secret into RAM with the right owner, then drop every privilege before any Python runs.
#
#   1. copy the secret from /run/secrets (Docker) or /secrets (the Docker-in-LXC fallback) into tmpfs
#   2. hand the copy to the worker user, mode 0400
#   3. exec the worker as that user: no capabilities, an emptied bounding set (needs SETPCAP) and no way to gain privileges
#
# The host files are shredded by the secret lifecycle after start-up, so a restarted container finds nothing
# to copy and refuses to start: restart the stack through `make secure-down` and `make gpu-up`, as for the API.
set -eu

DEST=/tmp/secure-secrets
UID_GID=10001

mkdir -p "$DEST"
chmod 700 "$DEST"
found=0
for src in /run/secrets/restore_worker_redis_password /secrets/restore_worker_redis_password; do
    if [ -f "$src" ]; then
        cp "$src" "$DEST/restore_worker_redis_password"
        found=1
        break
    fi
done
if [ "$found" -ne 1 ]; then
    echo "restore-worker: no restore_worker_redis_password secret found" >&2
    exit 1
fi
# Order matters: root has no DAC_OVERRIDE (cap_drop ALL), so it must finish everything it needs on the file and the
# directory BEFORE the directory changes owner: chmod the file, hand over the file, and only then hand over the directory.
# A shredded host copy holds a marker text instead of a secret: refuse to run with it.
if head -c 20 "$DEST/restore_worker_redis_password" | grep -q "^SHREDDED_FOR_SEC"; then
    echo "restore-worker: the Redis secret is a shred marker, not a secret: restart through make gpu-down and make gpu-up" >&2
    exit 1
fi
chmod 400 "$DEST/restore_worker_redis_password"
chown "$UID_GID:$UID_GID" "$DEST/restore_worker_redis_password"
chown "$UID_GID:$UID_GID" "$DEST"

export REDIS_PASSWORD_FILE="$DEST/restore_worker_redis_password"
export REDIS_USERNAME=restore-worker
exec setpriv --reuid="$UID_GID" --regid="$UID_GID" --clear-groups --bounding-set=-all --no-new-privs "$@"
