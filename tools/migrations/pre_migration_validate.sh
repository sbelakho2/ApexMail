#!/usr/bin/env bash
# =============================================================================
# Pre-Migration Validation
# =============================================================================
# Run before applying any migration to verify:
#   1. Database connectivity — target DB is reachable
#   2. Current schema version — matches expected version
#   3. Disk space — sufficient free space for migration operations
#   4. Advisory lock — acquired to prevent concurrent migrations
#
# Usage:
#   ./pre_migration_validate.sh <expected_version> [--pg-url <url>]
#
# Environment variables:
#   DATABASE_URL         Postgres connection string (default: postgres://apexmail@127.0.0.1:5432/apexmail?sslmode=disable)
#   PG_CONTAINER         Docker container name (fallback if psql not found)
#   MIN_DISK_MB          Minimum free disk space in MB (default: 1024)
#   LOCK_TIMEOUT_MS      Advisory lock timeout in ms (default: 5000)
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
EXPECTED_VERSION="${1:-}"
DATABASE_URL="${DATABASE_URL:-postgres://apexmail@127.0.0.1:5432/apexmail?sslmode=disable}"
PG_CONTAINER="${PG_CONTAINER:-}"
MIN_DISK_MB="${MIN_DISK_MB:-1024}"
LOCK_TIMEOUT_MS="${LOCK_TIMEOUT_MS:-5000}"
ADVISORY_LOCK_ID=20260613  # Unique project-wide lock ID

PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }

# ── Helpers ──────────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
Usage: pre_migration_validate.sh <expected_version> [--pg-url <url>]

Validates database readiness before running a migration.

Arguments:
  expected_version      The schema version expected BEFORE migration (e.g., "014")
  --pg-url <url>        PostgreSQL connection URL (overrides DATABASE_URL)

Environment:
  DATABASE_URL          Connection string (default: postgres://apexmail@127.0.0.1:5432/apexmail)
  PG_CONTAINER          Docker container name (fallback if psql not in PATH)
  MIN_DISK_MB           Minimum free disk in MB (default: 1024)
  LOCK_TIMEOUT_MS       Advisory lock acquire timeout in ms (default: 5000)

Exit codes:
  0   All checks passed
  1   One or more checks failed
EOF
    exit 0
}

# Execute a SQL query, preferring local psql but falling back to docker exec
run_sql() {
    local query="$1"
    if command -v psql &>/dev/null; then
        PGCONNECT_TIMEOUT=3 psql "$DATABASE_URL" -tAc "$query" 2>/dev/null
    elif [[ -n "$PG_CONTAINER" ]] && command -v docker &>/dev/null; then
        docker exec "$PG_CONTAINER" psql -U apexmail -d apexmail -tAc "$query" 2>/dev/null
    else
        echo ""
    fi
}

# ── Parse args ───────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage ;;
        --pg-url) DATABASE_URL="$2"; shift 2 ;;
        *) EXPECTED_VERSION="$1"; shift ;;
    esac
done

if [[ -z "$EXPECTED_VERSION" ]]; then
    echo "ERROR: expected_version argument is required" >&2
    usage
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  PRE-MIGRATION VALIDATION  —  expects v$EXPECTED_VERSION"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── Check 1: Database connectivity ───────────────────────────────────────────

echo "─── [1/4] Database Connectivity ───"

DB_CHECK=$(run_sql "SELECT 1 AS ok;" 2>/dev/null || echo "")
if [[ "$DB_CHECK" == "1" || "$DB_CHECK" == "1 " ]]; then
    pass "Database reachable at ${DATABASE_URL}"
else
    fail "Cannot reach database at ${DATABASE_URL}"
    # No point continuing if DB is unreachable
    echo ""
    echo "RESULTS: $PASS passed, $FAIL failed"
    exit 1
fi

# ── Check 2: Schema version ──────────────────────────────────────────────────

echo "─── [2/4] Schema Version ───"

# Check if _sqlx_migrations table exists
TABLE_EXISTS=$(run_sql "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '_sqlx_migrations');" 2>/dev/null || echo "")
if [[ "$TABLE_EXISTS" != "t" ]]; then
    # Fallback: check for our migration tracking table
    TABLE_EXISTS=$(run_sql "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'schema_migrations');" 2>/dev/null || echo "")
fi

if [[ "$TABLE_EXISTS" == "t" ]]; then
    # Try sqlx format first, then our custom format
    CURRENT_VER=$(run_sql "SELECT MAX(version) FROM _sqlx_migrations;" 2>/dev/null || echo "")
    if [[ -z "$CURRENT_VER" ]]; then
        CURRENT_VER=$(run_sql "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null || echo "")
    fi
    if [[ -n "$CURRENT_VER" ]]; then
        # Trim whitespace
        CURRENT_VER=$(echo "$CURRENT_VER" | xargs)
        if [[ "$CURRENT_VER" == "$EXPECTED_VERSION" ]]; then
            pass "Schema at version $CURRENT_VER (expected $EXPECTED_VERSION)"
        else
            fail "Schema at version $CURRENT_VER, expected $EXPECTED_VERSION — aborting"
        fi
    else
        fail "Cannot determine current schema version from migration tracking table"
    fi
else
    fail "No migration tracking table found (_sqlx_migrations or schema_migrations)"
fi

# ── Check 3: Disk space ──────────────────────────────────────────────────────

echo "─── [3/4] Disk Space ───"

if command -v df &>/dev/null; then
    # Check PGDATA or default data directory
    PG_DATA=$(run_sql "SHOW data_directory;" 2>/dev/null || echo "")
    if [[ -n "$PG_DATA" ]]; then
        AVAIL_KB=$(df "$PG_DATA" 2>/dev/null | awk 'NR==2 {print $4}')
    else
        AVAIL_KB=$(df /var/lib/postgresql 2>/dev/null | awk 'NR==2 {print $4}')
    fi

    if [[ -z "$AVAIL_KB" ]]; then
        AVAIL_KB=$(df / 2>/dev/null | awk 'NR==2 {print $4}')
    fi

    if [[ -n "$AVAIL_KB" ]]; then
        AVAIL_MB=$((AVAIL_KB / 1024))
        if [[ "$AVAIL_MB" -ge "$MIN_DISK_MB" ]]; then
            pass "Disk space: ${AVAIL_MB}MB available (minimum ${MIN_DISK_MB}MB)"
        else
            fail "Low disk space: ${AVAIL_MB}MB available, need at least ${MIN_DISK_MB}MB"
        fi
    else
        pass "Disk space check skipped (could not determine data directory)"
    fi
else
    pass "Disk space check skipped (df not available)"
fi

# ── Check 4: Advisory lock ───────────────────────────────────────────────────

echo "─── [4/4] Advisory Lock ───"

LOCK_RESULT=$(run_sql "SELECT pg_try_advisory_lock($ADVISORY_LOCK_ID);" 2>/dev/null || echo "")
if [[ "$LOCK_RESULT" == "t" || "$LOCK_RESULT" == "t " ]]; then
    pass "Advisory lock $ADVISORY_LOCK_ID acquired (pid $$)"
    # Release the lock — the migration script should re-acquire it
    run_sql "SELECT pg_advisory_unlock($ADVISORY_LOCK_ID);" >/dev/null 2>&1 || true
    echo ""
    echo "  ⚠  The migration script MUST acquire lock $ADVISORY_LOCK_ID"
    echo "     at the start of the migration transaction:"
    echo ""
    echo "       SELECT pg_advisory_lock($ADVISORY_LOCK_ID);"
    echo ""
elif [[ "$LOCK_RESULT" == "f" || "$LOCK_RESULT" == "f " ]]; then
    fail "Advisory lock $ADVISORY_LOCK_ID is held by another process — possible concurrent migration"
else
    fail "Cannot acquire advisory lock — check database permissions"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "One or more pre-migration checks failed. Fix issues before applying migration."
    exit 1
fi

echo "All checks passed. Safe to proceed with migration."
exit 0
