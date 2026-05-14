#!/bin/sh
# =============================================================================
# Redis entrypoint wrapper
# =============================================================================
# Reads password from Docker secret file and optionally configures TLS.
# H11: TLS configuration added for encrypted Redis traffic.
#
# Development: uses self-signed certs generated on startup.
# Production:  mount proper CA-signed certificates and set:
#   REDIS_TLS_ENABLED=true
#   REDIS_TLS_CERT_FILE=/path/to/tls.crt
#   REDIS_TLS_KEY_FILE=/path/to/tls.key
#   REDIS_TLS_CA_CERT_FILE=/path/to/ca.crt
# =============================================================================
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

# ── TLS Configuration ──────────────────────────────────────────────────────
# H11: If REDIS_TLS_ENABLED=true, configure TLS certificates.
# In dev, generate a self-signed cert if none provided.
TLS_ARGS=""
if [ "${REDIS_TLS_ENABLED:-false}" = "true" ]; then
    TLS_CERT="${REDIS_TLS_CERT_FILE:-/etc/redis/tls/redis.crt}"
    TLS_KEY="${REDIS_TLS_KEY_FILE:-/etc/redis/tls/redis.key}"
    TLS_CA="${REDIS_TLS_CA_CERT_FILE:-/etc/redis/tls/ca.crt}"

    # Generate self-signed cert for development if files don't exist
    if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
        echo "WARNING: TLS enabled but no certificate found at $TLS_CERT" >&2
        echo "Generating self-signed certificate for development use only." >&2
        mkdir -p "$(dirname "$TLS_CERT")" "$(dirname "$TLS_KEY")"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$TLS_KEY" \
            -out "$TLS_CERT" \
            -subj "/CN=redis/O=ApexMail Dev/OU=Engineering" \
            2>/dev/null
        echo "Self-signed certificate generated at $TLS_CERT" >&2
    fi

    TLS_ARGS="--tls-port 6380 --port 0 \
        --tls-cert-file $TLS_CERT \
        --tls-key-file $TLS_KEY \
        --tls-ca-cert-file $TLS_CA \
        --tls-auth-clients yes \
        --tls-replication yes"

    if [ -f "$TLS_CA" ]; then
        echo "TLS configured with CA: $TLS_CA" >&2
    else
        echo "WARNING: No CA certificate at $TLS_CA — disabling client auth for dev" >&2
        TLS_ARGS="--tls-port 6380 --port 0 \
            --tls-cert-file $TLS_CERT \
            --tls-key-file $TLS_KEY \
            --tls-auth-clients no"
    fi
    echo "Redis TLS enabled on port 6380" >&2
fi

exec redis-server \
    --appendonly yes \
    --maxmemory "${REDIS_MAXMEMORY:-256mb}" \
    --maxmemory-policy "${REDIS_MAXMEMORY_POLICY:-noeviction}" \
    --requirepass "$REDIS_PASSWORD" \
    $TLS_ARGS
