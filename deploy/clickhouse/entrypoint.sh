#!/bin/sh
# Build a users.d file from Docker secrets without exporting password env vars.
# Audit I: the application password (CLICKHOUSE_PASSWORD) and the admin
# password (CLICKHOUSE_ADMIN_PASSWORD[_FILE]) are SEPARATE secrets. The
# default user is passwordless and loopback-only without access_management.
# NOTE: the compose stack currently uses users.xml `from_env` directly (see
# deploy/clickhouse/users.xml); this generator is kept for parity/standalone
# use and must not diverge from that policy.
set -eu

password_file="${CLICKHOUSE_PASSWORD_FILE:-/run/secrets/clickhouse_password}"
admin_password_file="${CLICKHOUSE_ADMIN_PASSWORD_FILE:-/run/secrets/clickhouse_admin_password}"
password="${CLICKHOUSE_PASSWORD:-}"
admin_password="${CLICKHOUSE_ADMIN_PASSWORD:-}"

if [ -z "$password" ] && [ -f "$password_file" ]; then
    password="$(tr -d '\r\n' < "$password_file")"
fi
if [ -z "$admin_password" ] && [ -f "$admin_password_file" ]; then
    admin_password="$(tr -d '\r\n' < "$admin_password_file")"
fi

if [ -z "$password" ]; then
    echo "ERROR: ClickHouse app password is required via CLICKHOUSE_PASSWORD or CLICKHOUSE_PASSWORD_FILE" >&2
    exit 1
fi
if [ -z "$admin_password" ]; then
    echo "ERROR: ClickHouse admin password is required via CLICKHOUSE_ADMIN_PASSWORD or CLICKHOUSE_ADMIN_PASSWORD_FILE" >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum is required to generate ClickHouse password hashes" >&2
    exit 1
fi

password_hash="$(printf '%s' "$password" | sha256sum | awk '{print $1}')"
admin_password_hash="$(printf '%s' "$admin_password" | sha256sum | awk '{print $1}')"
unset password admin_password CLICKHOUSE_PASSWORD CLICKHOUSE_ADMIN_PASSWORD

users_dir="/etc/clickhouse-server/users.d"
users_file="${users_dir}/apexmail-users.xml"
mkdir -p "$users_dir"

cat > "$users_file" <<EOF
<clickhouse>
    <users>
        <default>
            <password></password>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>0</access_management>
        </default>
        <apexmail>
            <password_sha256_hex>${password_hash}</password_sha256_hex>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
                <ip>172.16.0.0/12</ip>
                <ip>10.0.0.0/8</ip>
                <ip>192.168.0.0/16</ip>
            </networks>
            <profile>readwrite</profile>
            <quota>default</quota>
            <access_management>0</access_management>
        </apexmail>
        <apexmail_admin>
            <password_sha256_hex>${admin_password_hash}</password_sha256_hex>
            <networks>
                <ip>::1</ip>
                <ip>127.0.0.1</ip>
                <ip>172.16.0.0/12</ip>
                <ip>10.0.0.0/8</ip>
                <ip>192.168.0.0/16</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </apexmail_admin>
    </users>
    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
    <profiles>
        <default>
            <max_memory_usage>10000000000</max_memory_usage>
            <load_balancing>random</load_balancing>
            <log_queries>0</log_queries>
        </default>
        <readwrite>
            <max_memory_usage>10000000000</max_memory_usage>
            <load_balancing>random</load_balancing>
            <log_queries>1</log_queries>
        </readwrite>
        <readonly>
            <max_memory_usage>10000000000</max_memory_usage>
            <load_balancing>random</load_balancing>
            <log_queries>0</log_queries>
            <readonly>1</readonly>
        </readonly>
    </profiles>
</clickhouse>
EOF

chmod 600 "$users_file"
exec /entrypoint.sh "$@"
