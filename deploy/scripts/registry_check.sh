#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# registry_check.sh — Monthly Estonian Business Register verification
# =============================================================================
# Queries the Estonian Business Register (Äriregister) API and updates
# the compliance database with current registry status, annual report
# filing status, and contact person validity.
#
# Cron: 0 2 1 * *  (first day of each month at 02:00)
#
# Environment variables:
#   DATABASE_URL          — PostgreSQL connection string (required)
#   REGISTRY_CODE         — Estonian registry code to check (default: 16588745)
#   REGISTRY_API_BASE_URL — Äriregister API base URL (default: https://ariregister.rik.ee/api)
#   ALERT_EMAIL           — Email to notify on discrepancies (default: legal@apexmail.ee)
#   LOG_LEVEL             — Log verbosity: error|warn|info|debug (default: info)
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly PID="$$"

# --- Configurable defaults ---
: "${REGISTRY_CODE:=16588745}"
: "${REGISTRY_API_BASE_URL:=https://ariregister.rik.ee/api}"
: "${ALERT_EMAIL:=legal@apexmail.ee}"
: "${LOG_LEVEL:=info}"
: "${TMPDIR:=/tmp}"

readonly CHECK_ID="registry-check-$(date -u +%Y%m%d-%H%M%S)"
readonly RESULT_FILE="${TMPDIR}/${CHECK_ID}.json"
readonly LOCK_FILE="${TMPDIR}/registry_check.lock"

# --- Logging ---
log() {
    local level="$1"; shift
    local msg="$*"
    case "$LOG_LEVEL" in
        error) [[ "$level" != "error" ]] && return ;;
        warn)  [[ "$level" == "error" || "$level" == "warn" ]] || return ;;
        info)  [[ "$level" == "debug" ]] && return ;;
    esac
    printf '[%s] [%s] [%s] %s\n' "$TIMESTAMP" "$level" "$SCRIPT_NAME" "$msg" >&2
}

# --- Cleanup ---
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# --- Locking ---
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid="$(cat "$LOCK_FILE")"
        if kill -0 "$pid" 2>/dev/null; then
            log error "Another instance is running (PID $pid)"
            exit 1
        fi
        log warn "Stale lock found, removing"
        rm -f "$LOCK_FILE"
    fi
    echo "$PID" > "$LOCK_FILE"
}

# --- HTTP helpers ---
check_dependency() {
    if ! command -v curl &>/dev/null; then
        log error "curl is required but not installed"
        exit 2
    fi
    if ! command -v jq &>/dev/null; then
        log error "jq is required but not installed"
        exit 2
    fi
    if ! command -v psql &>/dev/null; then
        log error "psql (PostgreSQL client) is required but not installed"
        exit 2
    fi
}

# --- API queries ---
query_company_info() {
    local code="$1"
    local url="${REGISTRY_API_BASE_URL}/legal-entities/${code}"
    log info "Querying: $url"

    local http_code body
    body="$(curl -sS -w '\n%{http_code}' \
        -H "Accept: application/json" \
        -H "User-Agent: ApexMail-RegistryMonitor/1.0" \
        --connect-timeout 15 \
        --max-time 30 \
        "$url" 2>/dev/null)" || {
        log error "Failed to query registry API for code $code"
        return 1
    }

    http_code="$(echo "$body" | tail -1)"
    body="$(echo "$body" | sed '$d')"

    if [[ "$http_code" != "200" ]]; then
        log error "Registry API returned HTTP $http_code for code $code"
        echo "{}"
        return 1
    fi

    echo "$body"
}

query_annual_report_status() {
    local code="$1"
    local url="${REGISTRY_API_BASE_URL}/legal-entities/${code}/annual-reports"
    log info "Querying annual reports: $url"

    curl -sS \
        -H "Accept: application/json" \
        -H "User-Agent: ApexMail-RegistryMonitor/1.0" \
        --connect-timeout 15 \
        --max-time 30 \
        "$url" 2>/dev/null || {
        log error "Failed to query annual reports for code $code"
        echo "[]"
        return 1
    }
}

query_contact_person() {
    local code="$1"
    local url="${REGISTRY_API_BASE_URL}/legal-entities/${code}/contact-person"
    log info "Querying contact person: $url"

    curl -sS \
        -H "Accept: application/json" \
        -H "User-Agent: ApexMail-RegistryMonitor/1.0" \
        --connect-timeout 15 \
        --max-time 30 \
        "$url" 2>/dev/null || {
        log error "Failed to query contact person for code $code"
        echo "{}"
        return 1
    }
}

# --- Database operations ---
db_upsert_registry_status() {
    local check_json="$1"
    local code active last_report contact_person contact_changed status

    code="$(echo "$check_json" | jq -r '.registry_code // empty')"
    active="$(echo "$check_json" | jq -r '.is_active // false')"
    last_report="$(echo "$check_json" | jq -r '.last_annual_report_date // ""')"
    contact_person="$(echo "$check_json" | jq -r '.contact_person_name // ""')"
    contact_changed="$(echo "$check_json" | jq -r '.contact_person_changed // false')"

    if [[ "$active" == "true" ]]; then
        status="active"
    else
        status="inactive"
    fi

    [[ -z "$code" ]] && { log error "Cannot upsert: missing registry_code"; return 1; }

    psql "$DATABASE_URL" <<SQL 2>&1 | tail -5
INSERT INTO registry_checks (check_id, registry_code, status, checked_at,
    last_annual_report_date, contact_person_name, contact_person_changed)
VALUES ('$CHECK_ID', '$code', '$status', NOW(),
    ${last_report:+'$last_report'}${last_report:-, NULL},
    ${contact_person:+'$contact_person'}${contact_person:-, NULL},
    $contact_changed)
ON CONFLICT (registry_code) DO UPDATE SET
    status = EXCLUDED.status,
    checked_at = EXCLUDED.checked_at,
    last_annual_report_date = COALESCE(EXCLUDED.last_annual_report_date, registry_checks.last_annual_report_date),
    contact_person_name = EXCLUDED.contact_person_name,
    contact_person_changed = EXCLUDED.contact_person_changed;
SQL
}

# --- Alerting ---
send_alert() {
    local subject="$1"
    local body="$2"

    if [[ -n "${SMTP_HOST:-}" ]]; then
        log info "Sending alert to $ALERT_EMAIL: $subject"
        printf 'Subject: %s\n\n%s\n' "$subject" "$body" | \
            curl -sS --mail-from "monitoring@apexmail.ee" --mail-rcpt "$ALERT_EMAIL" \
            "smtp://${SMTP_HOST}:${SMTP_PORT:-587}" 2>/dev/null || \
            log error "Failed to send email alert"
    else
        log info "SMTP not configured; alert would be: $subject"
    fi
}

# --- Main ---
main() {
    log info "Starting registry check for code $REGISTRY_CODE"
    acquire_lock
    check_dependency

    local company_info annual_reports contact_person
    local is_active last_report_date contact_name contact_changed warnings errors
    errors="[]"
    warnings="[]"

    # Query company info
    company_info="$(query_company_info "$REGISTRY_CODE")" || true
    if [[ "$company_info" == "{}" || -z "$company_info" ]]; then
        log error "No company info returned for registry code $REGISTRY_CODE"
        is_active="false"
    else
        is_active="$(echo "$company_info" | jq -r '.status // "unknown"')"
        if [[ "$is_active" != "inactive" && "$is_active" != "deleted" && "$is_active" != "liquidated" ]]; then
            is_active="true"
        else
            is_active="false"
        fi
    fi

    # Query annual report status
    annual_reports="$(query_annual_report_status "$REGISTRY_CODE")" || true
    if [[ "$annual_reports" == "[]" || -z "$annual_reports" ]]; then
        last_report_date=""
        warnings="$(echo "$warnings" | jq '. + ["No annual reports found in registry"]')"
    else
        last_report_date="$(echo "$annual_reports" | jq -r '.[0].submission_date // ""')"
        if [[ -z "$last_report_date" || "$last_report_date" == "null" ]]; then
            last_report_date=""
            warnings="$(echo "$warnings" | jq '. + ["Annual report data incomplete"]')"
        fi
    fi

    # Query contact person
    contact_person="$(query_contact_person "$REGISTRY_CODE")" || true
    if [[ "$contact_person" == "{}" || -z "$contact_person" ]]; then
        contact_name=""
        contact_changed="false"
        warnings="$(echo "$warnings" | jq '. + ["Contact person not found in registry"]')"
    else
        contact_name="$(echo "$contact_person" | jq -r '.name // ""')"
        local previous_name
        previous_name="$(psql "$DATABASE_URL" -tAc \
            "SELECT contact_person_name FROM registry_checks WHERE registry_code = '$REGISTRY_CODE' ORDER BY checked_at DESC LIMIT 1" \
            2>/dev/null || echo "")"
        if [[ -n "$previous_name" && "$previous_name" != "$contact_name" && -n "$contact_name" ]]; then
            contact_changed="true"
            warnings="$(echo "$warnings" | jq '. + ["Contact person has changed"]')"
        else
            contact_changed="false"
        fi
    fi

    # Build result
    jq -n \
        --arg registry_code "$REGISTRY_CODE" \
        --arg company_name "$(echo "$company_info" | jq -r '.name // "Unknown"')" \
        --arg status "checked" \
        --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson is_active "$is_active" \
        --arg last_annual_report_date "${last_report_date:-null}" \
        --arg contact_person_name "${contact_name:-null}" \
        --argjson contact_person_changed "$contact_changed" \
        --argjson errors "$errors" \
        --argjson warnings "$warnings" \
        '{
            registry_code: $registry_code,
            company_name: $company_name,
            status: $status,
            checked_at: $checked_at,
            is_active: $is_active,
            last_annual_report_date: $last_annual_report_date,
            contact_person_name: $contact_person_name,
            contact_person_changed: $contact_person_changed,
            errors: $errors,
            warnings: $warnings
        }' > "$RESULT_FILE"

    log info "Check result written to $RESULT_FILE"

    # Update database
    if [[ -n "${DATABASE_URL:-}" ]]; then
        db_upsert_registry_status "$(cat "$RESULT_FILE")"
        log info "Database updated"
    else
        log warn "DATABASE_URL not set; skipping database update"
    fi

    # Alert on issues
    if [[ "$is_active" == "false" ]]; then
        send_alert "[URGENT] Registry Code $REGISTRY_CODE is INACTIVE" \
            "Company with registry code $REGISTRY_CODE appears inactive or deleted in the Estonian Business Register.\n\nCheck performed at: $TIMESTAMP\nCheck ID: $CHECK_ID"
    fi

    # Summary
    local warning_count error_count
    warning_count="$(echo "$warnings" | jq 'length')"
    error_count="$(echo "$errors" | jq 'length')"

    log info "Registry check complete: active=$is_active warnings=$warning_count errors=$error_count"

    if [[ "$warning_count" -gt 0 || "$error_count" -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
