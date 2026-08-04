#!/bin/bash
set -euo pipefail

STATUS_DIR="${STATUS_DIR:-/var/www/status}"
STATUS_FILE="${STATUS_DIR}/status.json"
mkdir -p "$STATUS_DIR"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Deployment region (reported in the status payload). Override via env; the
# Hetzner datacenter e.g. fsn1/hel1/nbg1. Do not hardcode a single region.
REGION="${APEXMAIL_REGION:-eu-hel1}"

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

# ─── Probe MTA (SMTP) ───────────────────────────────────────
# The mail server (MTA) is an SMTP listener on ports 25/587/465 — it does NOT
# serve HTTP, so probe the SMTP port directly rather than hitting localhost:3000.
# Prefer 587 (submission); fall back to 25 (MX). The check only needs a TCP
# connect — we don't complete an SMTP transaction.
MTA_SMTP_PORT="${MTA_SMTP_PORT:-587}"
MAIL_STATUS="degraded"
if (exec 3<>/dev/tcp/127.0.0.1/${MTA_SMTP_PORT}) 2>/dev/null; then
    MAIL_STATUS="operational"
    exec 3>&- 3<&- 2>/dev/null || true
elif (exec 3<>/dev/tcp/127.0.0.1/25) 2>/dev/null; then
    MAIL_STATUS="operational"
    exec 3>&- 3<&- 2>/dev/null || true
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
    {"name": "mta", "status": "$MAIL_STATUS"},
    {"name": "clickhouse", "status": "$CLICKHOUSE_STATUS"},
    {"name": "redis", "status": "$REDIS_STATUS"}
  ],
  "region": "$REGION"
}
EOF

# ─── Log if degraded ────────────────────────────────────────
if [ "$OVERALL" != "operational" ]; then
    echo "[$NOW] WARNING: Health check overall status = $OVERALL" >&2
fi
