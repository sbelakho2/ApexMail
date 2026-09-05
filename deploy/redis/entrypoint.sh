#!/bin/sh
# =============================================================================
# Redis entrypoint wrapper
# =============================================================================
# Reads password from Docker secret file and configures Redis authentication
# using an ACL file (avoiding --requirepass which leaks via /proc/<pid>/cmdline).
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

# ── ACL file setup ──────────────────────────────────────────────────────────
# SECURITY (SEC-103): Use ACL file instead of --requirepass to prevent the
# password from being visible via /proc/<pid>/cmdline.
#
# SECURITY (audit §2): passwords are written to the ACL file in their
# sha256-HASHED form (`#<hex>`, the Redis ACL convention — AUTH with the
# plaintext still works; only the stored form is a hash), so the plaintext
# secret never lands in the acl file either. The hash is computed at
# entrypoint runtime from the Docker secret/env value.
#
# Audit fix (default user was +@all): every application container (api-server,
# worker, mta, enterprise, billing-service, sales-autopilot, tracking,
# observability) authenticates as the DEFAULT user — the Rust redis clients
# are configured with REDIS_PASSWORD only and have no username plumbing — so
# a per-app ACL username would require app-code changes. Instead the DEFAULT
# user is kept as the application user with the dangerous commands REMOVED
# from it:
#   FLUSHALL FLUSHDB CONFIG DEBUG SHUTDOWN ACL SLAVEOF REPLICAOF MODULE
#   MIGRATE RESTORE
# Data-plane commands (read/write/pubsub/streams/Lua scripts) and the reads
# the monitoring needs (INFO for redis-exporter + the observability monitor,
# PING for the healthcheck, TYPE/GET/LLEN for check-keys) stay available.
# A full-privilege `admin` user is declared for break-glass operator access
# and stays DISABLED unless REDIS_ADMIN_PASSWORD (or
# REDIS_ADMIN_PASSWORD_FILE) is set; enable with:
#   docker compose exec redis redis-cli --user admin
ACL_DIR="/tmp/redis-acl"
ACL_FILE="${ACL_DIR}/users.acl"
mkdir -p "$ACL_DIR"

# sha256 hex of the password — the Redis ACL `#hash` stored form.
acl_hash() {
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

# Application user (default) — password hash from the Docker secret.
echo "user default on #$(acl_hash "$REDIS_PASSWORD") ~* &* +@all -flushall -flushdb -config -debug -shutdown -acl -slaveof -replicaof -module -migrate -restore" > "$ACL_FILE"

# Administrator user — full access, on only when its own credential exists.
REDIS_ADMIN_PASSWORD=""
if [ -n "${REDIS_ADMIN_PASSWORD_FILE:-}" ] && [ -f "${REDIS_ADMIN_PASSWORD_FILE}" ]; then
    REDIS_ADMIN_PASSWORD="$(tr -d '\r\n' < "${REDIS_ADMIN_PASSWORD_FILE}")"
elif [ -n "${REDIS_ADMIN_PASSWORD:-}" ]; then
    REDIS_ADMIN_PASSWORD="${REDIS_ADMIN_PASSWORD}"
fi
if [ -n "$REDIS_ADMIN_PASSWORD" ]; then
    echo "user admin on #$(acl_hash "$REDIS_ADMIN_PASSWORD") ~* &* +@all" >> "$ACL_FILE"
    echo "Redis ACL: admin user ENABLED (full access)" >&2
else
    echo "user admin off ~* &* +@all" >> "$ACL_FILE"
    echo "Redis ACL: admin user disabled (set REDIS_ADMIN_PASSWORD or REDIS_ADMIN_PASSWORD_FILE to enable)" >&2
fi

chmod 600 "$ACL_FILE"
unset REDIS_PASSWORD REDIS_ADMIN_PASSWORD

# ── TLS Configuration ──────────────────────────────────────────────────────
# If REDIS_TLS_ENABLED=true, configure TLS certificates.
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
    --aclfile "$ACL_FILE" \
    $TLS_ARGS
