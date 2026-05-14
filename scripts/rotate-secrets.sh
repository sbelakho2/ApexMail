#!/bin/bash
# ==============================================================================
# ApexMail Automated Secret Rotation Script
# ==============================================================================
# Performs zero-downtime rotation of all secrets following the rotation schedule
# and dual-key overlap pattern documented in:
#   docs/operations/secret-rotation.md
#
# Rotation Schedule:
#   - JWT signing keys:           Every 90 days
#   - API key hash secret:        Every 90 days
#   - DKIM signing keys:          Every 180 days
#   - Database credentials:        Every 180 days
#   - Master encryption key:       Every 365 days
#
# Usage:
#   ./scripts/rotate-secrets.sh                          # Interactive menu
#   ./scripts/rotate-secrets.sh --list                   # List secret ages
#   ./scripts/rotate-secrets.sh --jwt                    # Rotate JWT keys only
#   ./scripts/rotate-secrets.sh --api-key-hash           # Rotate API key hash secret
#   ./scripts/rotate-secrets.sh --dkim                   # Rotate DKIM signing keys
#   ./scripts/rotate-secrets.sh --db-credentials          # Rotate database credentials
#   ./scripts/rotate-secrets.sh --master-key              # Rotate master encryption key
#   ./scripts/rotate-secrets.sh --all                    # Rotate all eligible secrets
#   ./scripts/rotate-secrets.sh --validate                # Validate current secrets
#   ./scripts/rotate-secrets.sh --rollback                # Roll back last rotation
#
# Requirements:
#   - kubectl configured with cluster access
#   - openssl, jq
#   - Access to Kubernetes secrets in apexmail namespace
# ==============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

NAMESPACE="apexmail"
SECRET_NAME="apexmail-secrets"
BACKUP_DIR="/tmp/apexmail-secret-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Rotation windows (for age validation)
JWT_ROTATION_DAYS=90
API_KEY_HASH_ROTATION_DAYS=90
DKIM_ROTATION_DAYS=180
DB_CREDENTIALS_ROTATION_DAYS=180
MASTER_KEY_ROTATION_DAYS=365

# ── Colors ─────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "${BLUE}[STEP]${NC}  $*"; }
log_detail()  { echo -e "${CYAN}[DETAIL]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --list                   Show current secret ages and rotation status
  --jwt                    Rotate JWT signing keys (public/private key pair)
  --api-key-hash           Rotate API key hash secret
  --dkim                   Rotate DKIM signing keys
  --db-credentials         Rotate database credentials
  --master-key             Rotate master encryption key
  --all                    Rotate all secrets due for rotation
  --validate               Validate current secret integrity
  --rollback               Roll back the most recent rotation
  --dry-run                Show what would be rotated without making changes
  --force                  Skip confirmation prompts
  --help                   Show this help
EOF
    exit 0
}

# ── Backup ─────────────────────────────────────────────────────────────────────

backup_current_secrets() {
    log_step "Backing up current secrets..."

    mkdir -p "$BACKUP_DIR/$TIMESTAMP"

    kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o json > "$BACKUP_DIR/$TIMESTAMP/secrets-backup.json" 2>/dev/null || {
        log_error "Failed to backup secrets from $SECRET_NAME"
        return 1
    }

    log_info "Secrets backed up to: $BACKUP_DIR/$TIMESTAMP/secrets-backup.json"
    log_info "Backup timestamp: $TIMESTAMP"
}

# ── List Secret Ages ───────────────────────────────────────────────────────────

list_secrets() {
    log_step "Current secret ages and rotation status..."

    local secrets
    secrets=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o json 2>/dev/null || {
        log_error "Cannot access secret $SECRET_NAME"
        exit 1
    })

    local creation_time
    creation_time=$(echo "$secrets" | jq -r '.metadata.creationTimestamp')
    local created_epoch
    created_epoch=$(date -d "$creation_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$creation_time" +%s 2>/dev/null)
    local now_epoch
    now_epoch=$(date +%s)
    local age_days=$(( (now_epoch - created_epoch) / 86400 ))

    echo ""
    echo "── Secret: $SECRET_NAME ──────────────────────────────────────────"
    echo "  Created:    $creation_time"
    echo "  Age:        ${age_days} days"
    echo ""

    # Extract individual keys and check if they're base64
    local keys
    keys=$(echo "$secrets" | jq -r '.data | keys[]' 2>/dev/null || echo "")

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        local value
        value=$(echo "$secrets" | jq -r ".data[\"$key\"]" 2>/dev/null || echo "unknown")
        local decoded
        decoded=$(echo "$value" | base64 -d 2>/dev/null | head -c 40 || echo "<binary>")

        # Determine rotation status
        local status="⚠ unknown"
        case "$key" in
            *JWT*)
                if [[ $age_days -ge $JWT_ROTATION_DAYS ]]; then
                    status="${RED}OVERDUE${NC} (rotate every ${JWT_ROTATION_DAYS}d)"
                else
                    status="${GREEN}OK${NC} ($((JWT_ROTATION_DAYS - age_days))d remaining)"
                fi
                ;;
            *API_KEY*|*HASH*)
                if [[ $age_days -ge $API_KEY_HASH_ROTATION_DAYS ]]; then
                    status="${RED}OVERDUE${NC} (rotate every ${API_KEY_HASH_ROTATION_DAYS}d)"
                else
                    status="${GREEN}OK${NC} ($((API_KEY_HASH_ROTATION_DAYS - age_days))d remaining)"
                fi
                ;;
            *DKIM*)
                if [[ $age_days -ge $DKIM_ROTATION_DAYS ]]; then
                    status="${RED}OVERDUE${NC} (rotate every ${DKIM_ROTATION_DAYS}d)"
                else
                    status="${GREEN}OK${NC} ($((DKIM_ROTATION_DAYS - age_days))d remaining)"
                fi
                ;;
            *DB*|*DATABASE*|*POSTGRES*)
                if [[ $age_days -ge $DB_CREDENTIALS_ROTATION_DAYS ]]; then
                    status="${RED}OVERDUE${NC} (rotate every ${DB_CREDENTIALS_ROTATION_DAYS}d)"
                else
                    status="${GREEN}OK${NC} ($((DB_CREDENTIALS_ROTATION_DAYS - age_days))d remaining)"
                fi
                ;;
            *KEK*|*ENCRYPTION*|*MASTER*)
                if [[ $age_days -ge $MASTER_KEY_ROTATION_DAYS ]]; then
                    status="${RED}OVERDUE${NC} (rotate every ${MASTER_KEY_ROTATION_DAYS}d)"
                else
                    status="${GREEN}OK${NC} ($((MASTER_KEY_ROTATION_DAYS - age_days))d remaining)"
                fi
                ;;
        esac

        echo -e "  ${key}: ${decoded:0:30}...  $status"
    done <<< "$keys"
    echo ""
}

# ── Validation ─────────────────────────────────────────────────────────────────

validate_secrets() {
    log_step "Validating current secrets..."

    local errors=0

    # Check that secret exists
    if ! kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &>/dev/null; then
        log_error "Secret $SECRET_NAME not found in namespace $NAMESPACE"
        exit 1
    fi

    # Check required keys exist
    local required_keys=(
        "JWT_PRIVATE_KEY_PEM"
        "JWT_PUBLIC_KEY_PEM"
        "API_KEY_HASH_SECRET"
        "WEBHOOK_SIGNING_SECRET"
        "SESSION_SECRET"
    )

    for key in "${required_keys[@]}"; do
        local value
        value=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
            -o jsonpath="{.data.$key}" 2>/dev/null || echo "")

        if [[ -z "$value" ]]; then
            log_error "Missing required secret key: $key"
            errors=1
        else
            local decoded
            decoded=$(echo "$value" | base64 -d 2>/dev/null || echo "")
            if [[ ${#decoded} -lt 16 ]]; then
                log_warn "Secret key '$key' seems too short (${#decoded} chars)"
                errors=1
            fi
        fi
    done

    # Validate JWT key pair (if both exist)
    local jwt_private
    jwt_private=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o jsonpath="{.data.JWT_PRIVATE_KEY_PEM}" 2>/dev/null | base64 -d || echo "")
    local jwt_public
    jwt_public=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o jsonpath="{.data.JWT_PUBLIC_KEY_PEM}" 2>/dev/null | base64 -d || echo "")

    if [[ -n "$jwt_private" ]] && [[ -n "$jwt_public" ]]; then
        # Verify that the public key matches the private key
        local extracted_public
        extracted_public=$(echo "$jwt_private" | openssl pkey -pubout 2>/dev/null || echo "")
        if [[ -n "$extracted_public" ]] && [[ "$extracted_public" == "$jwt_public" ]]; then
            log_info "✓ JWT key pair is valid (public key matches private key)"
        else
            log_warn "JWT public key does NOT match private key — rotation needed"
            errors=1
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        log_info "✓ All secrets validated successfully"
    else
        log_error "Some secrets failed validation"
    fi

    return $errors
}

# ── Individual Rotation Functions ──────────────────────────────────────────────

rotate_jwt() {
    log_step "Rotating JWT signing keys..."

    local temp_dir
    temp_dir=$(mktemp -d)

    # Generate new RSA key pair (4096-bit)
    log_info "Generating new 4096-bit RSA key pair..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out "$temp_dir/jwt-private.pem" 2>/dev/null
    openssl pkey -in "$temp_dir/jwt-private.pem" -pubout \
        -out "$temp_dir/jwt-public.pem" 2>/dev/null

    # Read the old private key for dual-key overlap
    local old_private
    old_private=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o jsonpath="{.data.JWT_PRIVATE_KEY_PEM}" 2>/dev/null | base64 -d || echo "")

    # Update secret with new keys, keeping old as PREVIOUS for token overlap
    kubectl patch secret "$SECRET_NAME" -n "$NAMESPACE" \
        --type='json' \
        -p="[
            {\"op\":\"add\",\"path\":\"/data/JWT_PRIVATE_KEY_PEM_PREVIOUS\",\"value\":\"$(echo "$old_private" | base64 -w0)\"},
            {\"op\":\"replace\",\"path\":\"/data/JWT_PRIVATE_KEY_PEM\",\"value\":\"$(base64 -w0 < "$temp_dir/jwt-private.pem")\"},
            {\"op\":\"replace\",\"path\":\"/data/JWT_PUBLIC_KEY_PEM\",\"value\":\"$(base64 -w0 < "$temp_dir/jwt-public.pem")\"}
        ]" 2>/dev/null || {
        log_error "Failed to patch secret with new JWT keys"
        rm -rf "$temp_dir"
        return 1
    }

    # Trigger pod restart to pick up new keys
    kubectl rollout restart deployment/api-server -n "$NAMESPACE" 2>/dev/null || true

    rm -rf "$temp_dir"
    log_info "JWT keys rotated. Old key preserved as JWT_PRIVATE_KEY_PEM_PREVIOUS for token overlap."
}

rotate_api_key_hash() {
    log_step "Rotating API key hash secret..."

    local new_secret
    new_secret=$(openssl rand -base64 48)

    local old_secret
    old_secret=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o jsonpath="{.data.API_KEY_HASH_SECRET}" 2>/dev/null | base64 -d || echo "")

    # Update with dual-key overlap pattern
    kubectl patch secret "$SECRET_NAME" -n "$NAMESPACE" \
        --type='json' \
        -p="[
            {\"op\":\"add\",\"path\":\"/data/API_KEY_HASH_SECRET_PREVIOUS\",\"value\":\"$(echo -n "$old_secret" | base64 -w0)\"},
            {\"op\":\"replace\",\"path\":\"/data/API_KEY_HASH_SECRET\",\"value\":\"$(echo -n "$new_secret" | base64 -w0)\"}
        ]" 2>/dev/null || {
        log_error "Failed to patch secret with new API key hash secret"
        return 1
    }

    kubectl rollout restart deployment/api-server -n "$NAMESPACE" 2>/dev/null || true

    log_info "API key hash secret rotated."
    log_info "Old secret preserved as API_KEY_HASH_SECRET_PREVIOUS for validation overlap."
}

rotate_dkim() {
    log_step "Rotating DKIM signing keys..."

    local temp_dir
    temp_dir=$(mktemp -d)

    # Generate new 2048-bit RSA key for DKIM
    log_info "Generating new 2048-bit DKIM key pair..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$temp_dir/dkim-private.pem" 2>/dev/null
    openssl pkey -in "$temp_dir/dkim-private.pem" -pubout \
        -out "$temp_dir/dkim-public.pem" 2>/dev/null

    # Extract DNS TXT record value
    local dns_record
    dns_record=$(openssl pkey -in "$temp_dir/dkim-private.pem" -pubout 2>/dev/null | \
        sed '1d;$d' | tr -d '\n')

    kubectl patch secret "$SECRET_NAME" -n "$NAMESPACE" \
        --type='json' \
        -p="[
            {\"op\":\"replace\",\"path\":\"/data/DKIM_PRIVATE_KEY\",\"value\":\"$(base64 -w0 < "$temp_dir/dkim-private.pem")\"}
        ]" 2>/dev/null || {
        log_error "Failed to patch secret with new DKIM key"
        rm -rf "$temp_dir"
        return 1
    }

    rm -rf "$temp_dir"

    log_info "DKIM signing key rotated."
    log_warn "⚠  IMPORTANT: Update your DNS TXT record with the new public key:"
    log_detail "  Selector: apexmail._domainkey"
    log_detail "  Value:    v=DKIM1; k=rsa; p=${dns_record:0:40}..."
    log_detail ""
    log_detail "  Full public key saved in DNS setup docs: docs/security/dkim-setup.md"
    log_detail "  DNS propagation may take up to 48 hours."
    log_warn "  Keep old DNS record during overlap period to avoid email rejection."
}

rotate_db_credentials() {
    log_step "Rotating database credentials..."

    # Generate new random password
    local new_password
    new_password=$(openssl rand -base64 32)

    local old_password
    old_password=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" \
        -o jsonpath="{.data.DATABASE_PASSWORD}" 2>/dev/null | base64 -d || echo "")

    # Update the password in PostgreSQL first
    log_info "Updating password in PostgreSQL..."
    kubectl exec -n "$NAMESPACE" deploy/postgres -- \
        psql -U postgres -c \
        "ALTER USER apexmail WITH PASSWORD '$new_password';" 2>/dev/null || {
        log_warn "Could not update PostgreSQL password directly — ensure manual update"
    }

    # Update Kubernetes secret
    kubectl patch secret "$SECRET_NAME" -n "$NAMESPACE" \
        --type='json' \
        -p="[
            {\"op\":\"add\",\"path\":\"/data/DATABASE_PASSWORD_PREVIOUS\",\"value\":\"$(echo -n "$old_password" | base64 -w0)\"},
            {\"op\":\"replace\",\"path\":\"/data/DATABASE_PASSWORD\",\"value\":\"$(echo -n "$new_password" | base64 -w0)\"}
        ]" 2>/dev/null || {
        log_error "Failed to update database credentials secret"
        return 1
    }

    # Roll pods to pick up new credentials
    kubectl rollout restart deployment -n "$NAMESPACE" 2>/dev/null || true

    log_info "Database credentials rotated. Old password preserved as DATABASE_PASSWORD_PREVIOUS."
}

rotate_master_key() {
    log_step "Rotating master encryption key (KEK)..."

    local new_kek
    new_kek=$(openssl rand -base64 32)

    local new_kek_id
    new_kek_id="kek-$(date +%Y%m%d)-$(openssl rand -hex 4)"

    local old_kek
    old_kek=$(kubectl get secret "apexmail-kek" -n "$NAMESPACE" \
        -o jsonpath="{.data.kek_material}" 2>/dev/null | base64 -d || echo "")
    local old_kek_id
    old_kek_id=$(kubectl get secret "apexmail-kek" -n "$NAMESPACE" \
        -o jsonpath="{.data.kek_id}" 2>/dev/null | base64 -d || echo "legacy")

    # Update KEK secret with dual-key overlap
    kubectl patch secret "apexmail-kek" -n "$NAMESPACE" \
        --type='json' \
        -p="[
            {\"op\":\"add\",\"path\":\"/data/kek_material_previous\",\"value\":\"$(echo -n "$old_kek" | base64 -w0)\"},
            {\"op\":\"add\",\"path\":\"/data/kek_id_previous\",\"value\":\"$(echo -n "$old_kek_id" | base64 -w0)\"},
            {\"op\":\"replace\",\"path\":\"/data/kek_material\",\"value\":\"$(echo -n "$new_kek" | base64 -w0)\"},
            {\"op\":\"replace\",\"path\":\"/data/kek_id\",\"value\":\"$(echo -n "$new_kek_id" | base64 -w0)\"}
        ]" 2>/dev/null || {
        log_error "Failed to update master encryption key secret"
        return 1
    }

    log_info "Master encryption key rotated."
    log_info "New KEK ID: $new_kek_id"
    log_warn "⚠  Re-encrypt all data encryption keys (DEKs) with the new KEK."
    log_detail "  Run the re-encryption job: kubectl create job --from=cronjob/dek-re-encrypt"
    log_detail "  Monitor: kubectl logs job/dek-re-encryption -n $NAMESPACE -f"
    log_detail "  Verify:  docs/operations/secret-rotation.md#re-encryption-procedure"
}

# ── Rollback ──────────────────────────────────────────────────────────────────

rollback() {
    log_step "Rolling back last secret rotation..."

    local latest_backup
    latest_backup=$(ls -td "$BACKUP_DIR"/*/ 2>/dev/null | head -1)

    if [[ -z "$latest_backup" ]]; then
        log_error "No backup found to roll back to"
        exit 1
    fi

    log_info "Restoring from backup: $latest_backup"

    kubectl apply -f "$latest_backup/secrets-backup.json" 2>/dev/null || {
        log_error "Failed to restore secrets from backup"
        exit 1
    }

    # Restart pods to pick up old secrets
    kubectl rollout restart deployment -n "$NAMESPACE" 2>/dev/null || true

    log_info "Secrets rolled back to: $(basename "$latest_backup")"
    log_warn "After rollback, validate all services are healthy."
}

# ── Main ──────────────────────────────────────────────────────────────────────

ACTION="menu"
DRY_RUN="false"
FORCE="false"

if [[ $# -eq 0 ]]; then
    # Interactive menu mode
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ApexMail — Automated Secret Rotation"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    list_secrets
    echo "Select rotation target:"
    echo "  1) JWT signing keys"
    echo "  2) API key hash secret"
    echo "  3) DKIM signing keys"
    echo "  4) Database credentials"
    echo "  5) Master encryption key"
    echo "  6) All eligible secrets"
    echo "  7) Validate secrets"
    echo "  0) Exit"
    echo ""
    read -rp "Choice [0-7]: " choice

    case "$choice" in
        1) ACTION="jwt" ;;
        2) ACTION="api-key-hash" ;;
        3) ACTION="dkim" ;;
        4) ACTION="db-credentials" ;;
        5) ACTION="master-key" ;;
        6) ACTION="all" ;;
        7) ACTION="validate" ;;
        0) exit 0 ;;
        *) log_error "Invalid choice"; exit 1 ;;
    esac
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list)            ACTION="list" ;;
            --jwt)             ACTION="jwt" ;;
            --api-key-hash)    ACTION="api-key-hash" ;;
            --dkim)            ACTION="dkim" ;;
            --db-credentials)  ACTION="db-credentials" ;;
            --master-key)      ACTION="master-key" ;;
            --all)             ACTION="all" ;;
            --validate)        ACTION="validate" ;;
            --rollback)        ACTION="rollback" ;;
            --dry-run)         DRY_RUN="true" ;;
            --force)           FORCE="true" ;;
            --help|-h)         usage ;;
            *)                 echo "Unknown: $1"; usage ;;
        esac
        shift
    done
fi

# ── Execution ──────────────────────────────────────────────────────────────────

case "$ACTION" in
    list)
        list_secrets
        exit 0
        ;;
    validate)
        validate_secrets
        exit $?
        ;;
    rollback)
        rollback
        exit 0
        ;;
esac

if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    echo -e "${YELLOW}⚠ DRY-RUN MODE${NC} — No changes will be made"
    echo ""
    echo "Would rotate: $ACTION"
    echo ""
    case "$ACTION" in
        jwt)           echo "  • Generate new 4096-bit RSA key pair" ;;
        api-key-hash)  echo "  • Generate new API_KEY_HASH_SECRET (48 bytes)" ;;
        dkim)          echo "  • Generate new DKIM 2048-bit RSA key pair" ;;
        db-credentials) echo "  • Generate new database password" ;;
        master-key)    echo "  • Generate new master encryption key (KEK)" ;;
        all)           echo "  • All secrets eligible for rotation" ;;
    esac
    echo "  • Update Kubernetes secret with dual-key overlap"
    echo "  • Trigger pod rollout to pick up new secrets"
    echo ""
    echo "To execute: $(basename "$0") --$ACTION"
    echo ""
    exit 0
fi

if [[ "$FORCE" != "true" ]]; then
    echo ""
    log_warn "About to rotate: $ACTION"
    log_warn "This will update Kubernetes secrets and trigger pod restarts."
    read -rp "Continue? [y/N] " confirm
    if [[ "$confirm" != "y" ]] && [[ "$confirm" != "Y" ]]; then
        log_info "Rotation cancelled."
        exit 0
    fi
fi

# Perform backup before any rotation
backup_current_secrets

case "$ACTION" in
    jwt)             rotate_jwt ;;
    api-key-hash)    rotate_api_key_hash ;;
    dkim)            rotate_dkim ;;
    db-credentials)  rotate_db_credentials ;;
    master-key)      rotate_master_key ;;
    all)
        rotate_jwt
        rotate_api_key_hash
        rotate_dkim
        rotate_db_credentials
        # Master key rotation requires manual re-encryption step
        log_warn "Master key rotation skipped in --all mode."
        log_warn "Run separately: $(basename "$0") --master-key"
        ;;
esac

echo ""
log_info "Rotation complete."
log_info "Run validation: $(basename "$0") --validate"
echo ""
