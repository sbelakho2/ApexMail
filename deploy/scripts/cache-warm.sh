#!/usr/bin/env bash
# =============================================================================
# ApexMail Cache Warming Script
# =============================================================================
# Pre-warms application caches after deployment to prevent cold-start latency
# spikes. This script is designed to run as a Kubernetes post-start hook or
# as an init container.
#
# Usage:
#   ./scripts/cache-warm.sh                    # Default: warm all caches
#   ./scripts/cache-warm.sh --dns-only         # Only warm DNS cache
#   ./scripts/cache-warm.sh --rate-limiter     # Only warm rate limiter cache
#   ./scripts/cache-warm.sh --db-query-cache   # Only warm DB query cache
#   ./scripts/cache-warm.sh --all              # Warm all caches
#   ./scripts/cache-warm.sh --dry-run          # Print what would be done
#   ./scripts/cache-warm.sh --verbose          # Verbose output
#
# Environment:
#   DATABASE_URL             - PostgreSQL connection string
#   REDIS_URL                - Redis connection string
#   API_BASE_URL             - API base URL (for health check)
#   CACHE_WARM_TIMEOUT       - Max time for warming (default: 30)
#   TOP_DOMAINS_FILE         - Path to top domains file
#   WARM_DNS                 - Enable DNS warming (default: true)
#   WARM_RATE_LIMITER        - Enable rate limiter warming (default: true)
#   WARM_DB_QUERY_CACHE      - Enable DB query cache warming (default: true)
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOP_DOMAINS_FILE="${TOP_DOMAINS_FILE:-$PROJECT_ROOT/config/top-email-domains.txt}"
CACHE_WARM_TIMEOUT="${CACHE_WARM_TIMEOUT:-30}"
API_BASE_URL="${API_BASE_URL:-http://localhost:3000}"
START_TIME=$(date +%s)
WARM_ITEMS=0
WARM_FAILURES=0

# ── Parse arguments ──────────────────────────────────────────────────────────
WARM_DNS="${WARM_DNS:-true}"
WARM_RATE_LIMITER="${WARM_RATE_LIMITER:-true}"
WARM_DB_QUERY_CACHE="${WARM_DB_QUERY_CACHE:-true}"
DRY_RUN=false
VERBOSE=false

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --dns-only           Only warm DNS cache
  --rate-limiter       Only warm rate limiter cache
  --db-query-cache     Only warm database query cache
  --all                Warm all caches (default)
  --dry-run            Print what would be done without executing
  --verbose            Verbose output
  --help               Show this help message

Environment variables:
  DATABASE_URL         PostgreSQL connection string
  REDIS_URL            Redis connection string
  API_BASE_URL         API base URL (default: http://localhost:3000)
  CACHE_WARM_TIMEOUT   Max time for warming in seconds (default: 30)
  TOP_DOMAINS_FILE     Path to top domains file
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dns-only)         WARM_DNS=true; WARM_RATE_LIMITER=false; WARM_DB_QUERY_CACHE=false; shift ;;
        --rate-limiter)     WARM_DNS=false; WARM_RATE_LIMITER=true; WARM_DB_QUERY_CACHE=false; shift ;;
        --db-query-cache)   WARM_DNS=false; WARM_RATE_LIMITER=false; WARM_DB_QUERY_CACHE=true; shift ;;
        --all)              WARM_DNS=true; WARM_RATE_LIMITER=true; WARM_DB_QUERY_CACHE=true; shift ;;
        --dry-run)          DRY_RUN=true; shift ;;
        --verbose)          VERBOSE=true; shift ;;
        --help)             usage ;;
        *)                  echo "Unknown option: $1"; usage ;;
    esac
done

log() {
    local level="$1"
    shift
    echo "[$(date +%H:%M:%S)] [${level}] $*"
}

# ── Prerequisites ────────────────────────────────────────────────────────────
check_prereqs() {
    local missing=false

    if [[ "$WARM_RATE_LIMITER" == "true" && -z "${REDIS_URL:-}" ]]; then
        log "WARN" "REDIS_URL not set. Rate limiter cache warming will be skipped."
        WARM_RATE_LIMITER=false
    fi

    if [[ "$WARM_DB_QUERY_CACHE" == "true" && -z "${DATABASE_URL:-}" ]]; then
        log "WARN" "DATABASE_URL not set. DB query cache warming will be skipped."
        WARM_DB_QUERY_CACHE=false
    fi

    if [[ "$WARM_DNS" == "true" ]]; then
        if ! command -v dig &>/dev/null && ! command -v host &>/dev/null; then
            log "WARN" "Neither dig nor host found. DNS cache warming will be skipped."
            WARM_DNS=false
        fi
    fi

    if [[ "$DRY_RUN" == "false" ]]; then
        # Wait for API server to be ready
        log "INFO" "Waiting for API server to be ready..."
        local retries=30
        while [[ $retries -gt 0 ]]; do
            if curl -sf "$API_BASE_URL/health" >/dev/null 2>&1; then
                log "INFO" "API server is ready."
                break
            fi
            sleep 1
            retries=$((retries - 1))
        done
        if [[ $retries -eq 0 ]]; then
            log "WARN" "API server not ready after 30s. Continuing anyway..."
        fi
    fi
}

# ── DNS Cache Warming ────────────────────────────────────────────────────────
warm_dns_cache() {
    log "INFO" "Starting DNS cache warming..."

    # Default top email provider domains (100 domains)
    local -a DOMAINS=(
        gmail.com outlook.com yahoo.com proton.me protonmail.com
        mail.com aol.com icloud.com gmx.com gmx.net web.de
        t-online.de orange.fr sfr.fr free.fr libero.it tin.it
        hotmail.com live.com msn.com office365.com exchange.com
        yandex.com yandex.ru mail.ru rambler.ru list.ru
        qq.com 163.com 126.com sina.com sohu.com yeah.net
        naver.com hanmail.net daum.net korea.com nate.com
        rediffmail.com indiatimes.com yahoo.co.in hotmail.co.uk
        btinternet.com ntlworld.com virginmedia.com blueyonder.co.uk
        zonnet.nl xs4all.nl planet.nl hetnet.nl
        chello.at gmx.at aon.at tele2.at
        swisscom.ch bluewin.ch sunrise.ch gmx.ch
        telenet.be skynet.be proximus.be belgacom.be
        telefonica.net terra.es ya.com hotmail.es
        virgilio.it alice.it fastwebnet.it libero.it
        o2.pl wp.pl interia.pl poczta.onet.pl
        centrum.cz seznam.cz atlas.cz volny.cz
        freemail.hu citromail.hu mailbox.hu t-online.hu
        mail.bg abv.bg dir.bg gmail.ru
        mail.com.ua ukr.net bigmir.net i.ua
        optonline.net verizon.net att.net bellsouth.net
        comcast.net charter.net cox.net earthlink.net
    )

    # Load from file if it exists
    if [[ -f "$TOP_DOMAINS_FILE" ]]; then
        mapfile -t DOMAINS < "$TOP_DOMAINS_FILE"
        log "INFO" "Loaded $((${#DOMAINS[@]})) domains from $TOP_DOMAINS_FILE"
    fi

    local total=0
    local success=0
    local failed=0

    for domain in "${DOMAINS[@]}"; do
        domain="$(echo "$domain" | tr -d '[:space:]')"
        [[ -z "$domain" ]] && continue
        total=$((total + 1))

        # Resolve MX records
        if command -v dig &>/dev/null; then
            if dig MX "$domain" +short +timeout=2 >/dev/null 2>&1; then
                success=$((success + 1))
                [[ "$VERBOSE" == "true" ]] && log "INFO" "  ✓ $domain (MX resolved)"
            else
                failed=$((failed + 1))
                [[ "$VERBOSE" == "true" ]] && log "WARN" "  ✗ $domain (MX failed)"
            fi
        elif command -v host &>/dev/null; then
            if host -t MX "$domain" >/dev/null 2>&1; then
                success=$((success + 1))
                [[ "$VERBOSE" == "true" ]] && log "INFO" "  ✓ $domain (MX resolved)"
            else
                failed=$((failed + 1))
                [[ "$VERBOSE" == "true" ]] && log "WARN" "  ✗ $domain (MX failed)"
            fi
        fi

        # Also warm A/AAAA records for the domain
        if command -v dig &>/dev/null; then
            dig "$domain" +short +timeout=2 >/dev/null 2>&1 || true
        fi
    done

    WARM_ITEMS=$((WARM_ITEMS + success))
    log "INFO" "DNS cache warming: $success/$total domains resolved ($failed failed)"
}

# ── Rate Limiter Cache Warming ──────────────────────────────────────────────
warm_rate_limiter_cache() {
    log "INFO" "Starting rate limiter cache warming..."

    if [[ -z "${REDIS_URL:-}" ]]; then
        log "WARN" "REDIS_URL not set. Skipping rate limiter cache warming."
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would warm rate limiter cache via Redis: $REDIS_URL"
        return
    fi

    # Warm rate limiter configs via API
    local api_key="${API_KEY:-test-api-key-00000000000000000000000000000}"
    local tenants=()

    # Try to fetch active tenants from API
    local tenant_response
    tenant_response=$(curl -sf -H "Authorization: Bearer $api_key" \
        "$API_BASE_URL/v1/admin/tenants?limit=100" 2>/dev/null || echo "")

    if [[ -n "$tenant_response" ]]; then
        # Parse tenant IDs from response (assumes JSON array with 'id' field)
        while IFS= read -r tenant_id; do
            tenants+=("$tenant_id")
        done < <(echo "$tenant_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, dict):
        items = data.get('data', data.get('tenants', data.get('items', [])))
    else:
        items = data
    for item in items:
        if isinstance(item, dict):
            tid = item.get('id', item.get('tenant_id', item.get('tenantId', '')))
            if tid:
                print(tid)
except: pass
" 2>/dev/null || true)
    fi

    # If API didn't return tenants, use a default warm-up set
    if [[ ${#tenants[@]} -eq 0 ]]; then
        tenants=("default-tenant")
        log "INFO" "No tenants from API. Warming default tenant config."
    fi

    local warmed=0
    for tenant_id in "${tenants[@]}"; do
        tenant_id="$(echo "$tenant_id" | tr -d '[:space:]')"
        [[ -z "$tenant_id" ]] && continue

        # Warm rate limit config via API (triggers Redis cache population)
        if curl -sf -X PUT \
            -H "Authorization: Bearer $api_key" \
            -H "Content-Type: application/json" \
            -d '{"action":"warm"}' \
            "$API_BASE_URL/v1/admin/rate-limits/$tenant_id/warm" >/dev/null 2>&1; then
            warmed=$((warmed + 1))
            [[ "$VERBOSE" == "true" ]] && log "INFO" "  ✓ $tenant_id (rate limit config warmed)"
        else
            # Fallback: directly set Redis keys
            if command -v redis-cli &>/dev/null && [[ -n "${REDIS_URL:-}" ]]; then
                local redis_host="${REDIS_URL#redis://}"
                redis_host="${redis_host%:*}"
                local redis_port="${REDIS_URL##*:}"
                redis_port="${redis_port%/}"

                echo "RATE_LIMIT:CONFIG:$tenant_id" | \
                    redis-cli -h "$redis_host" -p "$redis_port" --pipe \
                    >/dev/null 2>&1 || true

                warmed=$((warmed + 1))
                [[ "$VERBOSE" == "true" ]] && log "INFO" "  ✓ $tenant_id (direct Redis warm)"
            fi
        fi
    done

    WARM_ITEMS=$((WARM_ITEMS + warmed))
    log "INFO" "Rate limiter cache warming: $warmed tenant configs warmed"
}

# ── Database Query Cache Warming ─────────────────────────────────────────────
warm_db_query_cache() {
    log "INFO" "Starting database query cache warming..."

    if [[ -z "${DATABASE_URL:-}" ]]; then
        log "WARN" "DATABASE_URL not set. Skipping DB query cache warming."
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Would warm DB query cache via: $DATABASE_URL"
        return
    fi

    if ! command -v psql &>/dev/null; then
        log "WARN" "psql not found. Skipping DB query cache warming."
        return
    fi

    # Queries to warm the PostgreSQL query planner cache
    local -a WARM_QUERIES=(
        # Tenant configuration lookup
        "SELECT 1 FROM tenant_configs LIMIT 0;"
        # Domain verification check
        "SELECT 1 FROM domains LIMIT 0;"
        # Email queue status check
        "SELECT 1 FROM email_queue LIMIT 0;"
        # Delivery log lookup
        "SELECT 1 FROM email_delivery_log LIMIT 0;"
        # Template lookup
        "SELECT 1 FROM templates LIMIT 0;"
        # Account lookup
        "SELECT 1 FROM mail_accounts LIMIT 0;"
        # Rate limit config lookup
        "SELECT 1 FROM tenant_rate_limit_configs LIMIT 0;"
        # Bounce analytics
        "SELECT 1 FROM bounce_analytics_daily LIMIT 0;"
    )

    local warmed=0
    for query in "${WARM_QUERIES[@]}"; do
        local query_name="${query%% *}"  # Get first word
        if echo "EXPLAIN (ANALYZE, TIMING false) $query" | \
            psql "$DATABASE_URL" -q -t -o /dev/null 2>/dev/null; then
            warmed=$((warmed + 1))
            [[ "$VERBOSE" == "true" ]] && log "INFO" "  ✓ Query: $query_name"
        else
            log "WARN" "  ✗ Query: $query_name (failed)"
        fi
    done

    # Also warm common index lookups
    local -a INDEX_WARMUPS=(
        "SELECT relname, relkind FROM pg_class WHERE relname LIKE '%idx_%' LIMIT 10;"
        "SELECT count(*) FROM pg_indexes WHERE tablename = 'email_queue';"
        "SELECT count(*) FROM pg_indexes WHERE tablename = 'email_delivery_log';"
    )

    for query in "${INDEX_WARMUPS[@]}"; do
        echo "$query" | psql "$DATABASE_URL" -q -t -o /dev/null 2>/dev/null || true
    done

    WARM_ITEMS=$((WARM_ITEMS + warmed))
    log "INFO" "Database query cache warming: $warmed query plans warmed"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║       ApexMail Cache Warming                             ║"
    echo "║       Started: $(date)                    ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "Running in DRY RUN mode. No changes will be made."
    fi

    check_prereqs

    # Warm caches based on configuration
    if [[ "$WARM_DNS" == "true" ]]; then
        warm_dns_cache
    fi

    if [[ "$WARM_RATE_LIMITER" == "true" ]]; then
        warm_rate_limiter_cache
    fi

    if [[ "$WARM_DB_QUERY_CACHE" == "true" ]]; then
        warm_db_query_cache
    fi

    # Summary
    local elapsed=$(( $(date +%s) - START_TIME ))
    echo ""
    echo "════════════════════════════════════════════════════════════"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN COMPLETE — $WARM_ITEMS items would be warmed in ${elapsed}s"
    else
        log "INFO" "CACHE WARMING COMPLETE — $WARM_ITEMS items warmed in ${elapsed}s"
    fi
    echo "════════════════════════════════════════════════════════════"

    if [[ "$WARM_FAILURES" -gt 0 ]]; then
        log "WARN" "$WARM_FAILURES items failed to warm"
    fi
}

main "$@"
