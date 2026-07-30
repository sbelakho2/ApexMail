#!/bin/sh
# Redis ACL setup for load-test-infra
set -e

REDIS_PASSWORD_FILE="${REDIS_PASSWORD_FILE:-/run/secrets/redis_password}"

if [ -f "$REDIS_PASSWORD_FILE" ]; then
    REDIS_PASSWORD="$(tr -d '\r\n' < "$REDIS_PASSWORD_FILE")"
else
    echo "ERROR: Redis password secret not found at $REDIS_PASSWORD_FILE" >&2
    exit 1
fi

ACL_DIR="/tmp/redis-acl"
ACL_FILE="${ACL_DIR}/users.acl"
mkdir -p "$ACL_DIR"
echo "user default on >${REDIS_PASSWORD} ~* &* +@all" > "$ACL_FILE"
chmod 600 "$ACL_FILE"
unset REDIS_PASSWORD

exec redis-server \
    --maxmemory 512mb \
    --maxmemory-policy allkeys-lru \
    --aclfile "$ACL_FILE" \
    "$@"
