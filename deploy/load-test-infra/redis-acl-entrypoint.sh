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
# Audit fix: default user keeps only the data plane — the destructive/
# reconfiguration commands (FLUSHALL/FLUSHDB/CONFIG/DEBUG/SHUTDOWN/ACL/
# REPLICAOF/MODULE/MIGRATE/RESTORE) are removed; load generators (k6 etc.)
# auth as default with the password only. A full-privilege admin user is
# declared but disabled unless REDIS_ADMIN_PASSWORD(_FILE) is provided.
echo "user default on >${REDIS_PASSWORD} ~* &* +@all -flushall -flushdb -config -debug -shutdown -acl -slaveof -replicaof -module -migrate -restore" > "$ACL_FILE"
REDIS_ADMIN_PASSWORD=""
if [ -n "${REDIS_ADMIN_PASSWORD_FILE:-}" ] && [ -f "${REDIS_ADMIN_PASSWORD_FILE}" ]; then
    REDIS_ADMIN_PASSWORD="$(tr -d '\r\n' < "${REDIS_ADMIN_PASSWORD_FILE}")"
fi
if [ -n "${REDIS_ADMIN_PASSWORD:-}" ]; then
    echo "user admin on >${REDIS_ADMIN_PASSWORD} ~* &* +@all" >> "$ACL_FILE"
else
    echo "user admin off ~* &* +@all" >> "$ACL_FILE"
fi
chmod 600 "$ACL_FILE"
unset REDIS_PASSWORD REDIS_ADMIN_PASSWORD

exec redis-server \
    --maxmemory 512mb \
    --maxmemory-policy allkeys-lru \
    --aclfile "$ACL_FILE" \
    "$@"
