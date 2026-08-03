#!/bin/bash
set -euo pipefail

STATUS_DIR="${STATUS_DIR:-/var/www/status}"
STATUS_FILE="${STATUS_DIR}/status.json"
mkdir -p "$STATUS_DIR"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ─── Probe api-server ──────────────────────────────────────
AUTH_STATUS="degraded"
AUTH_DETAIL=""
if curl -sf --max-time 5 http://localhost:3000/v1/health > /tmp/auth_health.json 2>/dev/null; then
    AUTH_STATUS=$(jq -r '.status // "degraded"' /tmp/auth_health.json 2>/dev/null || echo "degraded")
    AUTH_DETAIL=$(jq -c '.services // []' /tmp/auth_health.json 2>/dev/null || echo "[]")
else
    AUTH_STATUS="down"
    AUTH_DETAIL='"unreachable"'
fi

# ─── Probe mail-server API ──────────────────────────────────
MAIL_STATUS="degraded"
if curl -sf --max-time 5 http://localhost:3000/health >/dev/null 2>&1; then
    MAIL_STATUS="operational"
else
    MAIL_STATUS="down"
fi

# ─── Probe ClickHouse ──────────────────────────────────────
CLICKHOUSE_STATUS="degraded"
if curl -sf --max-time 5 http://localhost:8123/ping >/dev/null 2>&1; then
    CLICKHOUSE_STATUS="operational"
else
    CLICKHOUSE_STATUS="down"
fi

# ─── Probe Redis ───────────────────────────────────────────
REDIS_STATUS="degraded"
if redis-cli -a "${REDIS_PASSWORD:-}" ping >/dev/null 2>&1; then
    REDIS_STATUS="operational"
else
    REDIS_STATUS="down"
fi

# ─── Compute overall status ─────────────────────────────────
OVERALL="degraded"
declare -a STATUSES=("$AUTH_STATUS" "$MAIL_STATUS" "$CLICKHOUSE_STATUS" "$REDIS_STATUS")
ALL_UP=true
for s in "${STATUSES[@]}"; do
    if [ "$s" != "operational" ]; then
        ALL_UP=false
    fi
done
if $ALL_UP; then
    OVERALL="operational"
fi

ANY_DOWN=false
for s in "${STATUSES[@]}"; do
    if [ "$s" = "down" ]; then
        ANY_DOWN=true
    fi
done
if $ANY_DOWN; then
    OVERALL="major_outage"
fi

# ─── Write status file ─────────────────────────────────────
cat > "$STATUS_FILE" <<EOF
{
  "status": "$OVERALL",
  "updated": "$NOW",
  "services": [
    {"name": "api-server", "status": "$AUTH_STATUS", "detail": $AUTH_DETAIL},
    {"name": "mail-server", "status": "$MAIL_STATUS"},
    {"name": "clickhouse", "status": "$CLICKHOUSE_STATUS"},
    {"name": "redis", "status": "$REDIS_STATUS"}
  ],
  "region": "eu-hel1"
}
EOF

# ─── Log if degraded ────────────────────────────────────────
if [ "$OVERALL" != "operational" ]; then
    echo "[$NOW] WARNING: Health check overall status = $OVERALL" >&2
fi
