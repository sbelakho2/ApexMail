#!/bin/sh
# Redis entrypoint wrapper that reads password from Docker secret file.
# Avoids exposing the password via `docker inspect` environment variables.
set -e

REDIS_PASSWORD_FILE="${REDIS_PASSWORD_FILE:-/run/secrets/redis_password}"

if [ -f "$REDIS_PASSWORD_FILE" ]; then
    REDIS_PASSWORD="$(tr -d '\r\n' < "$REDIS_PASSWORD_FILE")"
    if [ -z "$REDIS_PASSWORD" ]; then
        echo "ERROR: Redis password secret at $REDIS_PASSWORD_FILE is empty" >&2
        exit 1
    fi
else
    REDIS_PASSWORD="${REDIS_PASSWORD:-}"
    if [ -z "$REDIS_PASSWORD" ]; then
        echo "ERROR: Redis password secret not found at $REDIS_PASSWORD_FILE and REDIS_PASSWORD is unset" >&2
        exit 1
    fi
fi

exec redis-server \
    --appendonly yes \
    --maxmemory "${REDIS_MAXMEMORY:-256mb}" \
    --maxmemory-policy "${REDIS_MAXMEMORY_POLICY:-allkeys-lru}" \
    --requirepass "$REDIS_PASSWORD"