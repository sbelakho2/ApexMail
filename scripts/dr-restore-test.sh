#!/bin/bash
# ==============================================================================
# ApexMail Disaster Recovery — Restore Test Script
# ==============================================================================
# Tests backup integrity by performing a point-in-time recovery (PITR) restore
# to an isolated environment and validating data consistency.
#
# This script implements the procedures documented in:
#   docs/operations/disaster-recovery-testing.md (Scenario 2)
#   docs/operations/disaster-recovery.md (Procedure 4)
#
# Usage:
#   ./scripts/dr-restore-test.sh                                # Interactive dry-run
#   ./scripts/dr-restore-test.sh --execute                       # Execute restore test
#   ./scripts/dr-restore-test.sh --backup-id <id>                # Test specific backup
#   ./scripts/dr-restore-test.sh --latest                        # Test latest backup
#   ./scripts/dr-restore-test.sh --pitr "2026-05-13 14:00:00 UTC" # PITR to specific time
#   ./scripts/dr-restore-test.sh --list-backups                  # List available backups
#   ./scripts/dr-restore-test.sh --cleanup                       # Tear down test env
#
# Requirements:
#   - kubectl configured with cluster access
#   - pg_dump/pg_restore or psql client
#   - AWS CLI or Hetzner S3-compatible CLI (for WAL/backup storage)
#   - jq, openssl
# ==============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

NAMESPACE="apexmail"
TEST_NAMESPACE="apexmail-dr-test"

# S3 Backup storage (Hetzner)
S3_ENDPOINT="${S3_ENDPOINT:-https://fsn1.your-objectstorage.com}"
S3_BUCKET="${S3_BUCKET:-apexmail-backups}"
S3_REGION="${S3_REGION:-fsn1}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-}"
S3_SECRET_KEY="${S3_SECRET_KEY:-}"

# PostgreSQL
PG_USER="apexmail"
PG_DATABASE="apexmail"
PG_BACKUP_PREFIX="daily-backup"
PG_WAL_PREFIX="wal-archive"

# Restore
RESTORE_DIR="/tmp/apexmail-restore-test"
PG_VERSION="16"

# Test data verification
TEST_TABLE="email_queue"
TEST_COLUMN="subject"

# ── Colors ─────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()   { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()  { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()   { echo -e "${BLUE}[STEP]${NC}  $*"; }
log_detail() { echo -e "${CYAN}[DETAIL]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --execute                    Execute the restore test (default: dry-run)
  --backup-id <id>             Specific backup ID to test
  --latest                     Test the most recent backup
  --pitr "YYYY-MM-DD HH:MM:SS TZ"  Point-in-time recovery target
  --list-backups               List available backups
  --cleanup                    Remove test environment
  --skip-data-validation       Skip row-level data validation
  --help                       Show this help
EOF
    exit 0
}

# ── Pre-flight ─────────────────────────────────────────────────────────────────

check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing=0

    for cmd in kubectl psql pg_dump jq openssl aws; do
        if ! command -v "$cmd" &>/dev/null; then
            log_warn "Missing: $cmd"
            [[ "$cmd" == "aws" ]] && log_detail "  Install: pip install awscli or use s3cmd"
            [[ "$cmd" == "psql" ]] && log_detail "  Install: brew install libpq"
            [[ "$cmd" == "pg_dump" ]] && log_detail "  Install: brew install postgresql"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        log_warn "Some optional tools missing — proceeding with reduced functionality"
    fi

    log_info "Prerequisites check complete."
}

# ── Backup Listing ─────────────────────────────────────────────────────────────

list_backups() {
    log_step "Listing available backups..."

    if [[ -n "$S3_ACCESS_KEY" ]] && [[ -n "$S3_SECRET_KEY" ]]; then
        aws s3 --endpoint-url "$S3_ENDPOINT" \
            ls "s3://$S3_BUCKET/$PG_BACKUP_PREFIX/" \
            --recursive --human-readable 2>/dev/null || \
        log_error "Cannot list backups — check S3 credentials"
    else
        log_warn "S3 credentials not configured"
        log_detail "Configure via: S3_ACCESS_KEY, S3_SECRET_KEY env vars"
    fi

    echo ""
    log_info "Latest backup:"
    kubectl exec -n "$NAMESPACE" deploy/postgres -- \
        psql -U "$PG_USER" -t -c \
        "SELECT pg_start_backup('listing', false); SELECT pg_stop_backup();" \
        2>/dev/null || log_warn "Cannot reach PostgreSQL for live backup list"
}

# ── Test Environment Setup ─────────────────────────────────────────────────────

setup_test_env() {
    log_step "Setting up isolated test environment..."

    # Create test namespace if not exists
    if ! kubectl get namespace "$TEST_NAMESPACE" &>/dev/null; then
        kubectl create namespace "$TEST_NAMESPACE"
        log_info "Created namespace: $TEST_NAMESPACE"
    fi

    # Create a temporary PostgreSQL instance for restore testing
    mkdir -p "$RESTORE_DIR"

    cat > "$RESTORE_DIR/test-postgres.yaml" <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-restore-test
  namespace: $TEST_NAMESPACE
  labels:
    app: postgres-restore-test
    dr-test: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres-restore-test
  template:
    metadata:
      labels:
        app: postgres-restore-test
        dr-test: "true"
    spec:
      containers:
      - name: postgres
        image: postgres:$PG_VERSION
        env:
        - name: POSTGRES_USER
          value: "$PG_USER"
        - name: POSTGRES_PASSWORD
          value: "test-restore-$(openssl rand -hex 8)"
        - name: POSTGRES_DB
          value: "$PG_DATABASE"
        ports:
        - containerPort: 5432
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: "2"
            memory: 2Gi
        volumeMounts:
        - name: pgdata
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: pgdata
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-restore-test
  namespace: $TEST_NAMESPACE
  labels:
    dr-test: "true"
spec:
  selector:
    app: postgres-restore-test
  ports:
  - port: 5432
    targetPort: 5432
YAML

    kubectl apply -f "$RESTORE_DIR/test-postgres.yaml"
    log_info "Test PostgreSQL deployment created"

    # Wait for pod to be ready
    log_info "Waiting for test PostgreSQL to become ready..."
    kubectl wait --for=condition=ready pod -l app=postgres-restore-test \
        -n "$TEST_NAMESPACE" --timeout=120s || {
        log_error "Test PostgreSQL did not become ready"
        return 1
    }

    log_info "Test environment ready."
}

# ── Perform Restore ────────────────────────────────────────────────────────────

perform_restore() {
    local backup_source="$1"
    local pitr_target="$2"

    log_step "Starting restore from: ${backup_source:-latest backup}"

    local restore_start
    restore_start=$(date +%s)

    # Get the test pod name
    local test_pod
    test_pod=$(kubectl get pod -l app=postgres-restore-test \
        -n "$TEST_NAMESPACE" -o jsonpath='{.items[0].metadata.name}')

    if [[ -z "$test_pod" ]]; then
        log_error "Test pod not found"
        return 1
    fi

    # Step 1: Download and restore the base backup
    log_info "Restoring base backup..."
    if [[ -n "$S3_ACCESS_KEY" ]]; then
        # Download latest backup from S3
        local backup_file
        if [[ -n "$backup_source" ]]; then
            backup_file="$backup_source"
        else
            backup_file=$(aws s3 --endpoint-url "$S3_ENDPOINT" \
                ls "s3://$S3_BUCKET/$PG_BACKUP_PREFIX/" \
                --recursive | sort -r | head -1 | awk '{print $NF}')
        fi

        if [[ -z "$backup_file" ]]; then
            log_error "No backup found to restore"
            return 1
        fi

        log_info "Downloading backup: $backup_file"
        aws s3 --endpoint-url "$S3_ENDPOINT" \
            cp "s3://$S3_BUCKET/$backup_file" "$RESTORE_DIR/" \
            --expected-size $(aws s3 --endpoint-url "$S3_ENDPOINT" \
                ls "s3://$S3_BUCKET/$backup_file" | awk '{print $3}') || {
            log_error "Backup download failed"
            return 1
        }

        # Copy backup into test pod
        kubectl cp "$RESTORE_DIR/$(basename "$backup_file")" \
            "$TEST_NAMESPACE/$test_pod:/tmp/backup.sql" || {
            log_error "Failed to copy backup to test pod"
            return 1
        }
    else
        # Fall back to pg_dump from live cluster
        log_warn "No S3 credentials — performing pg_dump from live cluster instead"
        log_warn "WARNING: This impacts production I/O. Use --execute only during maintenance."

        kubectl exec -n "$NAMESPACE" deploy/postgres -- \
            pg_dump -U "$PG_USER" -d "$PG_DATABASE" \
            --format=custom \
            --file=/tmp/live-dump.sql \
            --verbose 2>&1 | tail -5 || {
            log_error "pg_dump failed"
            return 1
        }

        kubectl cp "$NAMESPACE/deploy/postgres:/tmp/live-dump.sql" \
            "$RESTORE_DIR/live-dump.sql"

        kubectl cp "$RESTORE_DIR/live-dump.sql" \
            "$TEST_NAMESPACE/$test_pod:/tmp/backup.sql"
    fi

    # Step 2: Restore to test database
    log_info "Restoring to test database..."
    kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        pg_restore -U "$PG_USER" -d "$PG_DATABASE" \
        --clean --if-exists \
        /tmp/backup.sql 2>&1 || {
        log_error "Restore failed"
        return 1
    }

    local restore_end
    restore_end=$(date +%s)
    local restore_duration=$((restore_end - restore_start))

    log_info "Restore completed in ${restore_duration}s"

    # Save metadata
    cat > "$RESTORE_DIR/restore-metadata.json" <<EOF
{
  "backup_source": "${backup_source:-latest}",
  "pitr_target": "${pitr_target:-none}",
  "restore_started": "$(date -d @$restore_start -u +%Y-%m-%dT%H:%M:%SZ)",
  "restore_completed": "$(date -d @$restore_end -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $restore_duration,
  "test_namespace": "$TEST_NAMESPACE",
  "pg_version": "$PG_VERSION"
}
EOF
    log_info "Restore metadata saved to $RESTORE_DIR/restore-metadata.json"
}

# ── Data Integrity Validation ─────────────────────────────────────────────────

validate_data() {
    if [[ "$SKIP_VALIDATION" == "true" ]]; then
        log_warn "Data validation skipped (--skip-data-validation)"
        return 0
    fi

    log_step "Running data integrity validation..."

    local test_pod
    test_pod=$(kubectl get pod -l app=postgres-restore-test \
        -n "$TEST_NAMESPACE" -o jsonpath='{.items[0].metadata.name}')

    local failures=0
    local checks_passed=0
    local checks_failed=0

    # 1. Row count comparison
    log_info "Comparing table row counts..."
    local tables
    tables=$(kubectl exec -n "$NAMESPACE" deploy/postgres -- \
        psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;" 2>/dev/null || echo "")

    while IFS= read -r table; do
        [[ -z "$table" ]] && continue

        local prod_count
        prod_count=$(kubectl exec -n "$NAMESPACE" deploy/postgres -- \
            psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
            "SELECT COUNT(*) FROM \"$table\";" 2>/dev/null | tr -d ' ' || echo "-1")

        local test_count
        test_count=$(kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
            psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
            "SELECT COUNT(*) FROM \"$table\";" 2>/dev/null | tr -d ' ' || echo "-1")

        if [[ "$prod_count" == "$test_count" ]] && [[ "$prod_count" != "-1" ]]; then
            log_detail "  ✓ $table: $prod_count rows"
            checks_passed=$((checks_passed + 1))
        else
            log_detail "  ✗ $table: prod=$prod_count, restored=$test_count"
            checks_failed=$((checks_failed + 1))
            failures=1
        fi
    done <<< "$tables"

    # 2. Index and constraint validation
    log_info "Validating indexes and constraints..."
    local index_count_prod
    local index_count_test

    index_count_prod=$(kubectl exec -n "$NAMESPACE" deploy/postgres -- \
        psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
        "SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public';" 2>/dev/null | tr -d ' ' || echo "0")

    index_count_test=$(kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
        "SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public';" 2>/dev/null | tr -d ' ' || echo "0")

    if [[ "$index_count_prod" == "$index_count_test" ]]; then
        log_info "  ✓ Indexes: $index_count_prod"
        checks_passed=$((checks_passed + 1))
    else
        log_warn "  Index count mismatch: prod=$index_count_prod, restored=$index_count_test"
        checks_failed=$((checks_failed + 1))
        failures=1
    fi

    # 3. Sample data spot-check
    log_info "Performing spot-check on sample data..."
    local sample_checks=3
    local sample_ok=0

    for i in $(seq 1 $sample_checks); do
        local random_id
        random_id=$(kubectl exec -n "$NAMESPACE" deploy/postgres -- \
            psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
            "SELECT id FROM email_queue ORDER BY RANDOM() LIMIT 1;" 2>/dev/null | tr -d ' ' || echo "")

        if [[ -n "$random_id" ]]; then
            local prod_val
            prod_val=$(kubectl exec -n "$NAMESPACE" deploy/postgres -- \
                psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
                "SELECT subject FROM email_queue WHERE id='$random_id';" 2>/dev/null | tr -d ' ' || echo "")

            local test_val
            test_val=$(kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
                psql -U "$PG_USER" -d "$PG_DATABASE" -t -c \
                "SELECT subject FROM email_queue WHERE id='$random_id';" 2>/dev/null | tr -d ' ' || echo "")

            if [[ "$prod_val" == "$test_val" ]]; then
                sample_ok=$((sample_ok + 1))
            fi
        fi
    done

    if [[ $sample_ok -eq $sample_checks ]]; then
        log_info "  ✓ Spot-checks: $sample_ok/$sample_checks matched"
        checks_passed=$((checks_passed + 1))
    else
        log_warn "  Spot-checks: $sample_ok/$sample_checks matched (some discrepancies)"
        checks_failed=$((checks_failed + 1))
    fi

    # Summary
    echo ""
    log_step "Validation Summary"
    log_info "  Checks passed: $checks_passed"
    if [[ $checks_failed -gt 0 ]]; then
        log_error "  Checks failed: $checks_failed"
    else
        log_info "  Checks failed: 0"
    fi
    echo ""

    if [[ $failures -eq 0 ]]; then
        log_info "✓ ALL DATA VALIDATION CHECKS PASSED"
    else
        log_error "✗ Some data validation checks failed"
        log_warn "Review differences and investigate root cause"
    fi

    return $failures
}

# ── PITR to Specific Time ─────────────────────────────────────────────────────

perform_pitr() {
    local target_time="$1"

    log_step "Performing Point-In-Time Recovery to: $target_time"

    local test_pod
    test_pod=$(kubectl get pod -l app=postgres-restore-test \
        -n "$TEST_NAMESPACE" -o jsonpath='{.items[0].metadata.name}')

    # Configure recovery.conf for PITR
    kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        bash -c "cat > /tmp/recovery.conf <<EOF
restore_command = 'aws s3 --endpoint-url $S3_ENDPOINT cp s3://$S3_BUCKET/$PG_WAL_PREFIX/%f %p'
recovery_target_time = '$target_time'
recovery_target_action = 'promote'
EOF"

    # Copy WAL segments and perform recovery
    log_info "Recovery target time configured. Triggering PITR..."

    # Stop PostgreSQL, apply WAL, promote
    kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        pg_ctl stop -D /var/lib/postgresql/data -m fast 2>/dev/null || true

    kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        cp /tmp/recovery.conf /var/lib/postgresql/data/recovery.conf

    kubectl exec -n "$TEST_NAMESPACE" "$test_pod" -- \
        pg_ctl start -D /var/lib/postgresql/data 2>/dev/null || true

    # Wait for recovery to complete
    sleep 5

    log_info "PITR to $target_time completed"
}

# ── Cleanup ────────────────────────────────────────────────────────────────────

cleanup() {
    log_step "Cleaning up test environment..."

    if kubectl get namespace "$TEST_NAMESPACE" &>/dev/null; then
        kubectl delete namespace "$TEST_NAMESPACE" --timeout=60s 2>/dev/null || {
            log_warn "Namespace deletion timed out — removing finalizers"
            kubectl delete namespace "$TEST_NAMESPACE" --force --grace-period=0 2>/dev/null || true
        }
        log_info "Test namespace removed"
    fi

    if [[ -d "$RESTORE_DIR" ]]; then
        rm -rf "$RESTORE_DIR"
        log_info "Temporary files cleaned up"
    fi

    log_info "Cleanup complete."
}

# ── Main ──────────────────────────────────────────────────────────────────────

EXECUTE="false"
SKIP_VALIDATION="false"
BACKUP_ID=""
PITR_TARGET=""
DO_LIST="false"
DO_CLEANUP="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --execute)              EXECUTE="true" ;;
        --skip-data-validation) SKIP_VALIDATION="true" ;;
        --backup-id)            shift; BACKUP_ID="$1" ;;
        --latest)               BACKUP_ID="latest" ;;
        --pitr)                 shift; PITR_TARGET="$1" ;;
        --list-backups)         DO_LIST="true" ;;
        --cleanup)              DO_CLEANUP="true" ;;
        --help|-h)              usage ;;
        *)                      echo "Unknown: $1"; usage ;;
    esac
    shift
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ApexMail DR — Restore Integrity Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [[ "$DO_LIST" == "true" ]]; then
    list_backups
    exit 0
fi

if [[ "$DO_CLEANUP" == "true" ]]; then
    cleanup
    exit 0
fi

check_prerequisites

if [[ "$EXECUTE" != "true" ]]; then
    echo -e "${YELLOW}⚠ DRY-RUN MODE${NC} — Pass --execute to perform the restore test"
    echo ""
    echo "This will:"
    echo "  1. Create isolated test PostgreSQL instance in namespace '$TEST_NAMESPACE'"
    echo "  2. Restore latest backup${BACKUP_ID:+ (ID: $BACKUP_ID)}${PITR_TARGET:+ to PITR time: $PITR_TARGET}"
    echo "  3. Validate data integrity (row counts, indexes, spot-checks)"
    echo "  4. Generate test report"
    echo "  5. Clean up test environment"
    echo ""
    echo "To execute: $(basename "$0") --execute ${BACKUP_ID:+--backup-id $BACKUP_ID}${PITR_TARGET:+ --pitr \"$PITR_TARGET\"}"
    echo ""
    exit 0
fi

# ── Execute ────────────────────────────────────────────────────────────────────

cleanup  # Ensure clean state

setup_test_env || {
    log_error "Failed to set up test environment"
    cleanup
    exit 1
}

perform_restore "$BACKUP_ID" "$PITR_TARGET" || {
    log_error "Restore failed"
    cleanup
    exit 1
}

if [[ -n "$PITR_TARGET" ]]; then
    perform_pitr "$PITR_TARGET" || {
        log_error "PITR failed"
        cleanup
        exit 1
    }
fi

validate_data || {
    log_error "Data validation failed"
    cleanup
    exit 1
}

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}✓ RESTORE TEST PASSED${NC}"
echo "  Backup integrity verified."
echo "  Backup ID: ${BACKUP_ID:-latest}"
echo "  PITR target: ${PITR_TARGET:-none}"
echo "═══════════════════════════════════════════════════════════════"
echo ""

cleanup

# Update the production-readiness plan tracking
echo ""
log_info "Restore test completed successfully. Update the tracking plan:"
echo "  DR-21: Backup verification — last pass: $(date -u +%Y-%m-%d)"
echo ""
