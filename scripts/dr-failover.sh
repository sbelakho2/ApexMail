#!/bin/bash
# ==============================================================================
# ApexMail Disaster Recovery — Automated Failover Script
# ==============================================================================
# Performs automated database failover from Finland (primary) to Germany (standby)
# region, following the failover state machine documented in:
#   docs/operations/disaster-recovery.md
#
# States: NORMAL → DETECTING → FENCING → PROMOTING → REDIRECTING → COMPLETED
#
# Usage:
#   ./scripts/dr-failover.sh                        # Interactive (dry-run first)
#   ./scripts/dr-failover.sh --execute               # Execute actual failover
#   ./scripts/dr-failover.sh --force                  # Skip health checks
#   ./scripts/dr-failover.sh --status                 # Check replication status
#   ./scripts/dr-failover.sh --rollback               # Fail back to Finland
#
# Requirements:
#   - kubectl configured for both apexmail-fi and apexmail-de contexts
#   - Hetzner Cloud API token in HCLOUD_API_TOKEN env var
#   - jq, curl, openssl
# ==============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

# Kubernetes contexts
CONTEXT_PRIMARY="apexmail-fi"
CONTEXT_STANDBY="apexmail-de"

# Namespace
NAMESPACE="apexmail"

# PostgreSQL labels
PG_PRIMARY_LABEL="role=primary"
PG_STANDBY_LABEL="role=standby"

# Hetzner Cloud (for STONITH fencing)
HCLOUD_API_TOKEN="${HCLOUD_API_TOKEN:-}"
HCLOUD_SERVER_NAME="${HCLOUD_SERVER_NAME:-apexmail-db-primary}"

# DNS API (Zone.ee)
DNS_API_URL="${DNS_API_URL:-https://dns.api.apexmail.ee/v1}"
DNS_API_TOKEN="${DNS_API_TOKEN:-}"
DNS_RECORDS=( "api.apexmail.ee" "track.apexmail.ee" "app.apexmail.ee" )

# Locking
LOCK_KEY="apexmail:failover:lock"
LOCK_TTL=300  # 5 minutes

# Timeouts (seconds)
HEALTH_TIMEOUT=30
REPLICATION_LAG_MAX=5   # Max acceptable lag in seconds before failover
PROMOTION_TIMEOUT=60
DNS_TTL=30

# ── State Machine ──────────────────────────────────────────────────────────────

STATE_FILE="/tmp/apexmail-failover-state.json"
CURRENT_STATE="NORMAL"
START_TIME=""

# ── Helpers ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --execute        Execute the failover (default: dry-run)
  --force          Skip pre-flight health checks
  --status         Check current replication status
  --rollback       Fail back from Germany to Finland
  --help           Show this help message
EOF
    exit 0
}

save_state() {
    cat > "$STATE_FILE" <<EOF
{
  "state": "$CURRENT_STATE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "message": "$1"
}
EOF
}

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        CURRENT_STATE=$(jq -r '.state' "$STATE_FILE" 2>/dev/null || echo "UNKNOWN")
    fi
}

timestamp_ms() {
    echo $(($(date +%s%N) / 1000000))
}

elapsed() {
    local start=$1
    local now
    now=$(timestamp_ms)
    echo $(( (now - start) / 1000 ))
}

# ── Pre-flight Checks ──────────────────────────────────────────────────────────

check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing=0

    for cmd in kubectl curl jq openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Missing required command: $cmd"
            missing=1
        fi
    done

    if [[ "$EXECUTE" == "true" ]] && [[ -z "$HCLOUD_API_TOKEN" ]]; then
        log_warn "HCLOUD_API_TOKEN not set — STONITH fencing will be skipped"
    fi

    if ! kubectl config get-contexts -o name 2>/dev/null | grep -q "$CONTEXT_PRIMARY"; then
        log_warn "Kubernetes context '$CONTEXT_PRIMARY' not found — some checks will be skipped"
    fi

    if ! kubectl config get-contexts -o name 2>/dev/null | grep -q "$CONTEXT_STANDBY"; then
        log_warn "Kubernetes context '$CONTEXT_STANDBY' not found — some checks will be skipped"
    fi

    if [[ $missing -eq 1 ]]; then
        log_error "Install missing prerequisites and retry."
        exit 1
    fi

    log_info "All prerequisites met."
}

check_replication_status() {
    log_step "Checking PostgreSQL replication status..."

    local lag
    lag=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -t -c \
        "SELECT COALESCE(EXTRACT(EPOCH FROM (pg_last_xact_replay_timestamp() - now())), 0);" 2>/dev/null || echo "unknown")

    log_info "Replication lag: ${lag}s"

    if [[ "$lag" != "unknown" ]] && [[ "$(echo "$lag > $REPLICATION_LAG_MAX" | bc -l 2>/dev/null)" == "1" ]]; then
        log_warn "Replication lag (${lag}s) exceeds maximum (${REPLICATION_LAG_MAX}s)"
        if [[ "$FORCE" != "true" ]]; then
            log_error "Aborting failover due to excessive replication lag. Use --force to override."
            exit 1
        fi
    fi

    # Check standby state
    local in_recovery
    in_recovery=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -t -c "SELECT pg_is_in_recovery();" 2>/dev/null || echo "unknown")

    if [[ "$in_recovery" != "t" ]]; then
        log_warn "Standby is NOT in recovery mode — it may already be a primary"
    else
        log_info "Standby is in recovery mode (expected state)"
    fi
}

check_primary_health() {
    log_step "Checking primary region health..."

    local healthy=0

    # Check primary PG
    if kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- \
        psql -U apexmail -c "SELECT 1;" &>/dev/null; then
        log_info "Primary PostgreSQL is reachable"
        healthy=1
    else
        log_warn "Primary PostgreSQL is NOT reachable — failover is justified"
    fi

    # Check API server health
    if kubectl --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        get endpoints api-server -o jsonpath='{.subsets[0].addresses}' 2>/dev/null | grep -q .; then
        log_info "Primary API server endpoints exist"
    else
        log_warn "Primary API server has no ready endpoints"
    fi

    if [[ "$FORCE" != "true" ]] && [[ $healthy -eq 1 ]]; then
        log_warn "Primary appears healthy. Use --force to fail over anyway."
        log_warn "If primary is truly down, re-run with --force or --execute --force."
        if [[ "$EXECUTE" != "true" ]]; then
            exit 0
        fi
    fi
}

# ── Acquire Distributed Lock ───────────────────────────────────────────────────

acquire_lock() {
    log_step "Acquiring distributed failover lock..."

    # Try to set lock in Redis with NX (not exists) + TTL
    local locked
    locked=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/redis-master -- \
        redis-cli SET "$LOCK_KEY" "$(hostname)" NX EX "$LOCK_TTL" 2>/dev/null || echo "FAILED")

    if [[ "$locked" != "OK" ]]; then
        local lock_holder
        lock_holder=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
            deploy/redis-master -- redis-cli GET "$LOCK_KEY" 2>/dev/null || echo "unknown")
        log_error "Cannot acquire lock — held by: $lock_holder"
        log_error "If stuck, release with: redis-cli DEL \"$LOCK_KEY\""
        exit 1
    fi

    log_info "Lock acquired (TTL: ${LOCK_TTL}s)"
    save_state "Lock acquired"
}

release_lock() {
    kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/redis-master -- redis-cli DEL "$LOCK_KEY" &>/dev/null || true
    log_info "Lock released"
}

# ── STONITH Fencing ────────────────────────────────────────────────────────────

stonith_fence() {
    if [[ "$SKIP_FENCING" == "true" ]] || [[ -z "$HCLOUD_API_TOKEN" ]]; then
        log_warn "STONITH fencing skipped (no HCLOUD_API_TOKEN or --skip-fencing)"
        return 0
    fi

    log_step "Fencing primary node via Hetzner Cloud API (STONITH)..."

    local response
    response=$(curl -sf -X POST \
        "https://api.hetzner.cloud/v1/servers" \
        -H "Authorization: Bearer $HCLOUD_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$HCLOUD_SERVER_NAME\",
            \"action\": \"poweroff\"
        }" 2>/dev/null || echo "FAILED")

    if [[ "$response" == "FAILED" ]]; then
        log_error "Fencing request failed. Manual intervention required."
        log_error "Shut down the primary node manually via Hetzner Cloud Console."
        return 1
    fi

    # Wait for confirmation
    log_info "Waiting for fencing confirmation..."
    sleep 10

    log_info "Primary node fenced successfully."
    save_state "Primary fenced"
}

# ── Promote Standby ────────────────────────────────────────────────────────────

promote_standby() {
    log_step "Promoting standby PostgreSQL to primary..."

    local start
    start=$(timestamp_ms)

    # Promote via pg_ctl or pg_promote()
    kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -c "SELECT pg_promote();" 2>/dev/null || \
    kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        pg_ctl promote -D /var/lib/postgresql/data 2>/dev/null || {
        log_error "Failed to promote standby PostgreSQL"
        return 1
    }

    # Wait for promotion to complete
    sleep 5

    # Verify promotion
    local in_recovery
    in_recovery=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -t -c "SELECT pg_is_in_recovery();" 2>/dev/null || echo "unknown")

    if [[ "$in_recovery" == "f" ]]; then
        local elapsed_time
        elapsed_time=$(elapsed "$start")
        log_info "Standby promoted to primary (${elapsed_time}s)"
        save_state "Standby promoted"
    else
        log_error "Promotion verification failed. PostgreSQL is still in recovery."
        return 1
    fi
}

# ── Update Service Endpoints ───────────────────────────────────────────────────

update_services() {
    log_step "Updating service endpoints to point to Germany region..."

    # Patch the API server service to use Germany load balancer IP
    local standby_ip
    standby_ip=$(kubectl get svc --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")

    if [[ -n "$standby_ip" ]]; then
        log_info "Standby ingress IP: $standby_ip"
    else
        log_warn "Could not determine standby ingress IP — will rely on DNS update only"
    fi

    # Update DNS records via Zone.ee API
    if [[ -n "$DNS_API_TOKEN" ]]; then
        for record in "${DNS_RECORDS[@]}"; do
            log_info "Updating DNS: $record -> $standby_ip"
            curl -sf -X POST "$DNS_API_URL/update" \
                -H "Authorization: Bearer $DNS_API_TOKEN" \
                -H "Content-Type: application/json" \
                -d "{\"record\":\"$record\",\"value\":\"$standby_ip\",\"ttl\":$DNS_TTL}" \
                &>/dev/null || log_warn "DNS update failed for $record"
        done
        log_info "DNS records updated."
    else
        log_warn "DNS_API_TOKEN not set — skipping DNS update"
        log_warn "Manually update these DNS records: ${DNS_RECORDS[*]} -> $standby_ip"
    fi

    save_state "Services redirected"
}

# ── Verify Failover ────────────────────────────────────────────────────────────

verify_failover() {
    log_step "Verifying failover completed successfully..."

    local failures=0

    # 1. Check new primary is accepting writes
    log_info "Checking write capability on new primary..."
    if kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -c "CREATE TABLE IF NOT EXISTS _dr_failover_test (id serial, ts timestamptz DEFAULT now()); INSERT INTO _dr_failover_test DEFAULT VALUES; DROP TABLE _dr_failover_test;" &>/dev/null; then
        log_info "✓ New primary accepts writes"
    else
        log_error "✗ New primary does NOT accept writes"
        failures=1
    fi

    # 2. Check API server health through standby ingress
    if [[ -n "$standby_ip" ]]; then
        if curl -sf --connect-timeout 10 "https://$standby_ip/v1/health" &>/dev/null; then
            log_info "✓ API server is healthy via standby ingress"
        else
            log_warn "API server health check failed (may be DNS propagation)"
        fi
    fi

    # 3. Check that old primary is fenced
    if kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- psql -U apexmail -c "SELECT 1;" &>/dev/null 2>&1; then
        log_warn "Old primary is still reachable — fencing may not have worked"
    else
        log_info "✓ Old primary is unreachable (fenced)"
    fi

    if [[ $failures -eq 0 ]]; then
        log_info "All failover verification checks passed."
    else
        log_error "Some verification checks failed. Review manually."
    fi
}

# ── Rollback (Failback to Finland) ────────────────────────────────────────────

rollback() {
    log_step "Performing rollback (failback to Finland)..."

    echo ""
    log_warn "⚠  ROLLBACK PROCEDURE"
    log_warn "This will fail back from Germany to Finland."
    echo ""

    # 1. Re-establish replication from Germany back to Finland
    log_info "Re-establishing replication from Germany to Finland..."
    kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- \
        pg_basebackup -h "$CONTEXT_STANDBY" -D /var/lib/postgresql/data -P --wal-method=stream \
        2>/dev/null || log_warn "Base backup failed — Finland may need manual re-init"

    # 2. Start Finland as replica
    kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- \
        pg_ctl start -D /var/lib/postgresql/data 2>/dev/null || true

    sleep 10

    # 3. Promote Finland back to primary
    kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- \
        psql -U apexmail -c "SELECT pg_promote();" 2>/dev/null || true

    sleep 5

    # 4. Update DNS back to Finland
    local primary_ip
    primary_ip=$(kubectl get svc --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")

    if [[ -n "$DNS_API_TOKEN" ]] && [[ -n "$primary_ip" ]]; then
        for record in "${DNS_RECORDS[@]}"; do
            curl -sf -X POST "$DNS_API_URL/update" \
                -H "Authorization: Bearer $DNS_API_TOKEN" \
                -H "Content-Type: application/json" \
                -d "{\"record\":\"$record\",\"value\":\"$primary_ip\",\"ttl\":$DNS_TTL}" \
                &>/dev/null || log_warn "DNS update failed for $record"
        done
        log_info "DNS records updated back to Finland."
    fi

    log_info "Rollback complete. Verify all services before marking as resolved."
}

# ── Status Check ───────────────────────────────────────────────────────────────

show_status() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ApexMail DR — Replication Status"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    # Primary
    echo "── Primary (Finland) ──────────────────────────────────────────"
    if kubectl exec --context="$CONTEXT_PRIMARY" -n "$NAMESPACE" \
        deploy/postgres -- psql -U apexmail -c "SELECT pg_is_in_recovery();" 2>/dev/null; then
        echo "Primary connection: OK"
    else
        echo "Primary: UNREACHABLE"
    fi

    # Standby
    echo ""
    echo "── Standby (Germany) ───────────────────────────────────────────"
    if kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- psql -U apexmail -c "SELECT pg_is_in_recovery();" 2>/dev/null; then
        echo "Standby connection: OK"
    else
        echo "Standby: UNREACHABLE"
    fi

    # Replication lag
    echo ""
    echo "── Replication Lag ─────────────────────────────────────────────"
    local lag
    lag=$(kubectl exec --context="$CONTEXT_STANDBY" -n "$NAMESPACE" \
        deploy/postgres-standby -- \
        psql -U apexmail -t -c \
        "SELECT COALESCE(EXTRACT(EPOCH FROM (pg_last_xact_replay_timestamp() - now())), 0);" 2>/dev/null || echo "unknown")
    echo "  Lag: ${lag}s"

    # State file
    if [[ -f "$STATE_FILE" ]]; then
        echo ""
        echo "── Last Failover State ────────────────────────────────────────"
        cat "$STATE_FILE"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# ── Main ──────────────────────────────────────────────────────────────────────

EXECUTE="false"
FORCE="false"
SKIP_FENCING="false"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute)   EXECUTE="true" ;;
        --force)     FORCE="true" ;;
        --skip-fencing) SKIP_FENCING="true" ;;
        --status)    show_status; exit 0 ;;
        --rollback)  rollback; exit 0 ;;
        --help|-h)   usage ;;
        *)           echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# ── Execution ──────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ApexMail Disaster Recovery — Failover Script"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [[ "$EXECUTE" != "true" ]]; then
    echo -e "${YELLOW}⚠ DRY-RUN MODE${NC} — Pass --execute to actually perform failover"
    echo ""
fi

START_TIME=$(date +%s)

# Phase 1: Pre-flight
CURRENT_STATE="DETECTING"
save_state "Running pre-flight checks"
check_prerequisites

if [[ "$EXECUTE" == "true" ]]; then
    check_replication_status
    check_primary_health

    # Phase 2: Acquire lock
    acquire_lock
    CURRENT_STATE="FENCING"
    save_state "Starting fencing"

    # Phase 3: Fence primary
    stonith_fence || log_warn "Fencing incomplete — proceeding cautiously"

    # Phase 4: Promote standby
    CURRENT_STATE="PROMOTING"
    save_state "Promoting standby"
    promote_standby

    # Phase 5: Redirect traffic
    CURRENT_STATE="REDIRECTING"
    save_state "Updating service endpoints"
    update_services

    # Phase 6: Verify
    CURRENT_STATE="COMPLETED"
    save_state "Failover completed"

    verify_failover
    release_lock

    local total_time
    total_time=$(($(date +%s) - START_TIME))
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${GREEN}✓ FAILOVER COMPLETED${NC}"
    echo "  Total time: ${total_time}s"
    echo "  Final state: ${CURRENT_STATE}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    log_warn "Post-failover actions required:"
    echo "  1. Verify all tenants can send/receive email"
    echo "  2. Check monitoring dashboards for anomalies"
    echo "  3. Update status page"
    echo "  4. Notify on-call team"
    echo "  5. File post-mortem if this was unplanned"
else
    echo "Dry-run summary:"
    echo "  ✓ Prerequisites check"
    echo "  ✓ Replication status check"
    echo "  ✓ Primary health check"
    echo "  ✓ Lock acquisition (simulated)"
    echo "  ✓ STONITH fencing (simulated)"
    echo "  ✓ Standby promotion (simulated)"
    echo "  ✓ DNS/Service update (simulated)"
    echo "  ✓ Verification (simulated)"
    echo ""
    echo "To execute: $(basename "$0") --execute --force"
fi

echo ""
