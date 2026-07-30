#!/bin/sh
# Build a users.d file from Docker secrets without exporting password env vars.
set -eu

password_file="${CLICKHOUSE_PASSWORD_FILE:-/run/secrets/clickhouse_password}"
password="${CLICKHOUSE_PASSWORD:-}"

if [ -z "$password" ] && [ -f "$password_file" ]; then
    password="$(tr -d '\r\n' < "$password_file")"
fi

if [ -z "$password" ]; then
    echo "ERROR: ClickHouse password is required via CLICKHOUSE_PASSWORD or CLICKHOUSE_PASSWORD_FILE" >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum is required to generate ClickHouse password hash" >&2
    exit 1
fi

password_hash="$(printf '%s' "$password" | sha256sum | awk '{print $1}')"
unset password CLICKHOUSE_PASSWORD

users_dir="/etc/clickhouse-server/users.d"
users_file="${users_dir}/apexmail-users.xml"
mkdir -p "$users_dir"

cat > "$users_file" <<EOF
<clickhouse>
    <users>
        <default>
            <password_sha256_hex>${password_hash}</password_sha256_hex>
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
        </apexmail>
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
