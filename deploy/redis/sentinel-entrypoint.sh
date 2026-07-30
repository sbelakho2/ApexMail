#!/bin/sh
# Generate Sentinel config at startup so master host and auth come from env/secrets.
set -eu

master_name="${REDIS_MASTER_NAME:-apexmail-primary}"
master_host="${REDIS_MASTER_HOST:-redis}"
master_port="${REDIS_MASTER_PORT:-6379}"
quorum="${REDIS_SENTINEL_QUORUM:-2}"
port="${REDIS_SENTINEL_PORT:-26379}"
down_after_ms="${REDIS_SENTINEL_DOWN_AFTER_MS:-5000}"
failover_timeout_ms="${REDIS_SENTINEL_FAILOVER_TIMEOUT_MS:-30000}"
parallel_syncs="${REDIS_SENTINEL_PARALLEL_SYNCS:-1}"
resolve_timeout_secs="${REDIS_SENTINEL_RESOLVE_TIMEOUT_SECS:-30}"

password_file="${REDIS_PASSWORD_FILE:-/run/secrets/redis_password}"
password="${REDIS_PASSWORD:-}"

if [ -z "$password" ] && [ -f "$password_file" ]; then
    password="$(tr -d '\r\n' < "$password_file")"
fi

resolved_master_host="$master_host"
if command -v getent >/dev/null 2>&1; then
    start_ts="$(date +%s)"
    while :; do
        candidate="$(getent hosts "$master_host" 2>/dev/null | awk 'NR==1 {print $1}')"
        if [ -n "$candidate" ]; then
            resolved_master_host="$candidate"
            break
        fi

        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        if [ "$elapsed" -ge "$resolve_timeout_secs" ]; then
            # Fall back to the configured hostname if DNS resolution is still pending.
            break
        fi

        sleep 1
    done
fi

config_dir="/tmp/redis-sentinel"
config_file="${config_dir}/sentinel.conf"
mkdir -p "$config_dir"

cat > "$config_file" <<EOF
port ${port}
daemonize no
logfile ""
pidfile /tmp/redis-sentinel.pid
sentinel monitor ${master_name} ${resolved_master_host} ${master_port} ${quorum}
sentinel down-after-milliseconds ${master_name} ${down_after_ms}
sentinel failover-timeout ${master_name} ${failover_timeout_ms}
sentinel parallel-syncs ${master_name} ${parallel_syncs}
EOF

if [ -n "$password" ]; then
    printf 'sentinel auth-pass %s %s\n' "$master_name" "$password" >> "$config_file"
fi

unset password REDIS_PASSWORD
exec redis-sentinel "$config_file"
