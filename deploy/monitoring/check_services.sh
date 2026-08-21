#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_services.sh — ApexMail Production Service Health Probe
# =============================================================================
# Probes: REST API, SMTP relay, message queue, dashboard, auth, domains,
#         templates, inbound email, analytics, grader, dedicated IP,
#         support portal, and status page.
#
# Outputs JSON health report. Non-zero exit on any critical failure.
#
# Environment:
#   BASE_URL      — API base URL (default: https://api.apexmail.ee)
#   DASHBOARD_URL — Dashboard URL (default: https://app.apexmail.ee)
#   SUPPORT_URL   — Support portal URL (default: https://status.apexmail.ee)
#   STATUS_URL    — Public status page URL (default: https://status.apexmail.ee)
#   SMTP_HOST     — SMTP relay host (default: mail.apexmail.ee)
#   SMTP_PORT     — SMTP relay port (default: 587)
#   TIMEOUT       — Per-probe timeout in seconds (default: 10)
# =============================================================================

readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HISTORY_FILE="${SCRIPT_DIR}/.check_history.json"

# Audit P — apexmail.com is NOT this deployment's domain; every default now
# points at the real apexmail.ee hostnames.
: "${BASE_URL:=https://api.apexmail.ee}"
: "${DASHBOARD_URL:=https://app.apexmail.ee}"
: "${SUPPORT_URL:=https://status.apexmail.ee}"
: "${STATUS_URL:=https://status.apexmail.ee}"
: "${SMTP_HOST:=mail.apexmail.ee}"
: "${SMTP_PORT:=587}"
: "${TIMEOUT:=10}"

# --- Helpers ---
http_status() {
    curl -sS -o /dev/null -w '%{http_code}' \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "$1" 2>/dev/null || echo "000"
}

http_time() {
    curl -sS -o /dev/null -w '%{time_total}' \
        --connect-timeout "$TIMEOUT" \
        --max-time "$TIMEOUT" \
        "$1" 2>/dev/null || echo "0"
}

smtp_check() {
    local host="$1" port="$2"
    timeout "$TIMEOUT" bash -c "echo QUIT | openssl s_client -connect ${host}:${port} -starttls smtp -quiet 2>/dev/null" && echo "ok" || echo "fail"
}

update_history() {
    local service="$1" status="$2" ms="$3"
    local tmp
    tmp="${HISTORY_FILE}.tmp"

    local entry
    entry="$(jq -n --arg svc "$service" --arg st "$status" --arg ts "$TIMESTAMP" --argjson ms "$ms" \
        '{service: $svc, status: $st, timestamp: $ts, response_ms: $ms}')"

    if [[ -f "$HISTORY_FILE" ]]; then
        jq --argjson entry "$entry" \
            '.checks = ([$entry] + .checks[0:89])' \
            "$HISTORY_FILE" > "$tmp" && mv "$tmp" "$HISTORY_FILE"
    else
        jq -n --argjson entry "$entry" '{checks: [$entry]}' > "$HISTORY_FILE"
    fi
}

compute_uptime() {
    local service="$1"
    if [[ ! -f "$HISTORY_FILE" ]]; then
        echo "0"
        return
    fi
    jq -r --arg svc "$service" \
        '[.checks[] | select(.service == $svc)] |
         if length == 0 then "0"
         else ((map(select(.status == "ok")) | length) / length * 100 | floor | tostring)
         end' \
        "$HISTORY_FILE" 2>/dev/null || echo "0"
}

# --- Probes ---
probe() {
    local service="$1" endpoint="$2" type="${3:-http}"
    local code ms status uptime

    case "$type" in
        http)
            code="$(http_status "$endpoint")"
            ms="$(http_time "$endpoint")"
            if [[ "$code" =~ ^2 ]]; then status="ok"; else status="fail"; fi
            ;;
        smtp)
            ms="0"
            local result
            result="$(smtp_check "$SMTP_HOST" "$SMTP_PORT")"
            if [[ "$result" == "ok" ]]; then status="ok"; else status="fail"; fi
            ;;
        *)
            status="unknown"
            ms="0"
            ;;
    esac

    update_history "$service" "$status" "$ms"
    uptime="$(compute_uptime "$service")"

    jq -n \
        --arg service "$service" \
        --arg status "$status" \
        --arg endpoint "$endpoint" \
        --argjson response_ms "$ms" \
        --arg checked_at "$TIMESTAMP" \
        --argjson uptime_pct "$uptime" \
        '{service: $service, status: $status, endpoint: $endpoint, response_ms: $response_ms, checked_at: $checked_at, uptime_90d_pct: $uptime_pct}'
}

# --- Main ---
main() {
    local results="[]" overall="ok" count=0 failures=0

    # REST API
    local r
    r="$(probe "REST API" "${BASE_URL}/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # SMTP Relay
    r="$(probe "SMTP Relay" "smtp://${SMTP_HOST}:${SMTP_PORT}" "smtp")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Message Queue (internal health endpoint)
    r="$(probe "Message Queue" "${BASE_URL}/health/queue")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Dashboard
    r="$(probe "Dashboard" "${DASHBOARD_URL}/api/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Authentication Service
    r="$(probe "Auth Service" "${BASE_URL}/auth/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Domain Verification Service
    r="$(probe "Domain Service" "${BASE_URL}/domains/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Template Service
    r="$(probe "Template Service" "${BASE_URL}/templates/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Inbound Email Processing
    r="$(probe "Inbound Email" "${BASE_URL}/inbound/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Analytics Service
    r="$(probe "Analytics" "${BASE_URL}/analytics/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Email Grader
    r="$(probe "Email Grader" "${BASE_URL}/grader/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Dedicated IP Service
    r="$(probe "Dedicated IP" "${BASE_URL}/dedicated-ips/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    # Support Portal
    r="$(probe "Support Portal" "${SUPPORT_URL}/health")"
    results="$(echo "$results" | jq ". + [$r]")"
    [[ "$(echo "$r" | jq -r '.status')" == "fail" ]] && { failures=$((failures+1)); }
    count=$((count+1))

    if [[ "$failures" -gt 0 ]]; then
        overall="degraded"
    fi

    jq -n \
        --arg overall "$overall" \
        --argjson probes "$results" \
        --arg checked_at "$TIMESTAMP" \
        --argjson total "$count" \
        --argjson failures "$failures" \
        '{
            overall_status: $overall,
            checked_at: $checked_at,
            total_probes: $total,
            failures: $failures,
            probes: $probes
        }'

    [[ "$failures" -eq 0 ]]
}

main
