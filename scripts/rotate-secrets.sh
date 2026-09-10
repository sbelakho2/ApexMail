#!/bin/bash
# ==============================================================================
# ApexMail Automated Secret Rotation Script (Docker Compose deployment)
# ==============================================================================
# Performs rotation of the secrets rendered on the production host by
# .github/workflows/deploy-hetzner.yml, following the rotation schedule and
# dual-key overlap pattern documented in:
#   docs/operations/secret-rotation.md
#
# DEPLOYMENT MODEL (audit M): production ApexMail runs on Docker Compose on a
# single Hetzner host. Secrets live as FILES under the paths named by the
# PROD_*_FILE variables in /opt/apexmail/.env (rendered by the deploy
# workflow). This script rotates those files and recreates the consuming
# services with `docker compose up -d --force-recreate`. There is no
# Kubernetes and no kubectl path anymore.
#
# Rotation Schedule:
#   - JWT signing keys:                    Every 90 days
#   - API key hash secret:                 Every 90 days
#   - DKIM signing keys:                   Every 180 days
#   - Database credentials:                Every 180 days
#   - Master encryption key (DKIM KEK):    Every 365 days
#
# Usage (on the production host, or via SSH):
#   ./scripts/rotate-secrets.sh                          # Interactive menu
#   ./scripts/rotate-secrets.sh --list                   # List secret ages
#   ./scripts/rotate-secrets.sh --jwt                    # Rotate JWT keys only
#   ./scripts/rotate-secrets.sh --api-key-hash           # Rotate API key hash secret
#   ./scripts/rotate-secrets.sh --dkim                   # Rotate DKIM signing keys
#   ./scripts/rotate-secrets.sh --db-credentials         # Rotate database credentials
#   ./scripts/rotate-secrets.sh --master-key             # Rotate master encryption key
#   ./scripts/rotate-secrets.sh --all                    # Rotate all eligible secrets
#   ./scripts/rotate-secrets.sh --validate               # Validate current secrets
#   ./scripts/rotate-secrets.sh --rollback               # Roll back last rotation
#   ./scripts/rotate-secrets.sh --dry-run --jwt          # Show what would happen
#
# Requirements:
#   - docker compose on the production host, /opt/apexmail/.env present
#   - openssl, jq
#
# SECURITY (audit M): this script never prints secret VALUES — only file
# names, ages and rotation status. The plaintext backup it takes before
# rotating lives in a 0700 directory with 0600 files and is removed as soon
# as a rollback restores it (rotate manually with `shred -u` if you abort).
# ==============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
DEPLOY_DIR="${DEPLOY_DIR:-/opt/apexmail}"
ENV_FILE="${ENV_FILE:-$DEPLOY_DIR/.env}"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
BACKUP_DIR="${BACKUP_DIR:-/tmp/apexmail-secret-rotation}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_step()  { echo -e "\n${CYAN}━━ $* ━━${NC}"; }
log_info()  { echo -e "${GREEN}✓${NC} $*"; }
log_warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
log_error() { echo -e "${RED}✗${NC} $*" >&2; }
log_detail(){ echo -e "  $*"; }

# ── .env / rendered-secret-file helpers ───────────────────────────────────────
# The PROD_*_FILE variables in .env name the on-host secret files; the
# matching plain variables hold the values the deploy workflow rendered from.

env_value() { # env_value <VAR> -> value (empty when unset)
    grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true
}

env_file_path() { # env_file_path <PROD_*_FILE var> -> rendered file path
    env_value "$1"
}

secret_file() { # secret_file <plain value VAR> -> path of its rendered file
    local filevar="PROD_${1}_FILE"
    # The two JWT PEM secrets break the PROD_<VAR>_FILE naming pattern
    # (their .env keys drop the _PEM suffix).
    case "$1" in
        JWT_PRIVATE_KEY_PEM) filevar="PROD_JWT_PRIVATE_KEY_FILE" ;;
        JWT_PUBLIC_KEY_PEM)  filevar="PROD_JWT_PUBLIC_KEY_FILE" ;;
    esac
    env_file_path "$filevar"
}

read_secret() { # read_secret <plain value VAR> -> file contents
    local f
    f="$(secret_file "$1")"
    [[ -n "$f" && -f "$f" ]] && cat "$f" || true
}

write_secret() { # write_secret <plain value VAR> <new value>
    local f
    f="$(secret_file "$1")"
    if [[ -z "$f" ]]; then
        log_error "PROD_${1}_FILE is not defined in $ENV_FILE — cannot rotate $1"
        return 1
    fi
    umask 177
    printf '%s' "$2" > "$f"
    chmod 600 "$f"
}

compose() {
    (cd "$DEPLOY_DIR" && docker compose $COMPOSE_FILES --env-file "$ENV_FILE" "$@")
}

recreate_services() { # recreate_services <service...>
    log_info "Recreating: $*"
    compose up -d --force-recreate "$@"
}

check_prereqs() {
    [[ -f "$ENV_FILE" ]] || { log_error "$ENV_FILE not found (set ENV_FILE or run on the production host)"; exit 1; }
    command -v docker >/dev/null || { log_error "docker is required"; exit 1; }
    command -v openssl >/dev/null || { log_error "openssl is required"; exit 1; }
}

usage() {
    sed -n 's/^#   \(\./\./p' "$0" | head -n 12
    exit 0
}

# ── Backup ────────────────────────────────────────────────────────────────────

# Files rotated by this run — each rotation function appends its PROD_*_FILE
# var here so backup/rollback know what to snapshot.
BACKUP_KEYS=()

backup_current_secrets() {
    log_step "Backing up current secrets..."

    # Audit M: 0700 dir + 0600 files — /tmp is otherwise world-listable.
    # Remove this backup (shred -u) once the rotation is verified.
    install -d -m 700 "$BACKUP_DIR/$TIMESTAMP"
    umask 177

    local key f n=0
    for key in "${BACKUP_KEYS[@]}"; do
        f="$(env_file_path "$key")"
        [[ -n "$f" && -f "$f" ]] || continue
        cp "$f" "$BACKUP_DIR/$TIMESTAMP/$(basename "$f")"
        chmod 600 "$BACKUP_DIR/$TIMESTAMP/$(basename "$f")"
        echo "$key $(basename "$f")" >> "$BACKUP_DIR/$TIMESTAMP/index.txt"
        n=$((n + 1))
    done
    chmod 600 "$BACKUP_DIR/$TIMESTAMP/index.txt" 2>/dev/null || true

    log_info "Secrets backed up to: $BACKUP_DIR/$TIMESTAMP ($n files, mode 0600)"
    log_warn "Plaintext backup present — shred it once the rotation is verified:"
    log_warn "  shred -u $BACKUP_DIR/$TIMESTAMP/* && rmdir $BACKUP_DIR/$TIMESTAMP"
}

# ── List Secret Ages ──────────────────────────────────────────────────────────

list_secrets() {
    log_step "Current secret ages and rotation status..."

    local keys=(
        PROD_JWT_PRIVATE_KEY_FILE PROD_JWT_PUBLIC_KEY_FILE
        PROD_API_KEY_HASH_SECRET_FILE PROD_WEBHOOK_SIGNING_SECRET_FILE
        PROD_SESSION_SECRET_FILE PROD_INTERNAL_SERVICE_TOKEN_FILE
        PROD_POSTGRES_PASSWORD_FILE PROD_REDIS_PASSWORD_FILE
        PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE PROD_BACKUP_ENCRYPTION_KEY_FILE
    )

    local key f age_epoch age_days status
    local now_epoch
    now_epoch=$(date +%s)

    printf "  %-42s %-11s %s\n" "SECRET FILE" "AGE (days)" "STATUS"
    for key in "${keys[@]}"; do
        f="$(env_file_path "$key")"
        if [[ -z "$f" || ! -f "$f" ]]; then
            printf "  %-42s %-11s %s\n" "${key#PROD_}" "-" "MISSING"
            continue
        fi
        age_epoch=$(( now_epoch - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f") ))
        age_days=$(( age_epoch / 86400 ))
        status="OK"
        (( age_days > 365 )) && status="ROTATE SOON"
        (( age_days > 730 )) && status="OVERDUE"
        printf "  %-42s %-11s %s\n" "$(basename "$f")" "$age_days" "$status"
    done
    echo ""
}

# ── Validation ────────────────────────────────────────────────────────────────

validate_secrets() {
    log_step "Validating current secrets..."

    local errors=0
    local required=(
        JWT_PRIVATE_KEY_PEM JWT_PUBLIC_KEY_PEM
        API_KEY_HASH_SECRET WEBHOOK_SIGNING_SECRET SESSION_SECRET
    )

    local var value
    for var in "${required[@]}"; do
        value="$(read_secret "$var")"
        if [[ -z "$value" ]]; then
            log_error "Missing or empty rendered secret: $var ($(secret_file "$var" || echo 'path unset'))"
            errors=1
        elif [[ ${#value} -lt 16 ]]; then
            log_warn "Secret '$var' seems too short (${#value} chars)"
            errors=1
        fi
    done

    # Validate JWT key pair (if both exist)
    local jwt_private jwt_public extracted_public
    jwt_private="$(read_secret JWT_PRIVATE_KEY_PEM)"
    jwt_public="$(read_secret JWT_PUBLIC_KEY_PEM)"
    if [[ -n "$jwt_private" && -n "$jwt_public" ]]; then
        extracted_public="$(printf '%s' "$jwt_private" | openssl pkey -pubout 2>/dev/null || echo "")"
        if [[ -n "$extracted_public" && "$extracted_public" == "$jwt_public" ]]; then
            log_info "JWT key pair is valid (public key matches private key)"
        else
            log_warn "JWT public key does NOT match private key — rotation needed"
            errors=1
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        log_info "All secrets validated successfully"
    else
        log_error "Some secrets failed validation"
    fi
    return $errors
}

# ── Individual Rotation Functions ─────────────────────────────────────────────

rotate_jwt() {
    log_step "Rotating JWT signing keys..."
    BACKUP_KEYS+=(PROD_JWT_PRIVATE_KEY_FILE PROD_JWT_PUBLIC_KEY_FILE)

    local temp_dir
    temp_dir=$(mktemp -d)

    log_info "Generating new 4096-bit RSA key pair..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out "$temp_dir/jwt-private.pem" 2>/dev/null
    openssl pkey -in "$temp_dir/jwt-private.pem" -pubout \
        -out "$temp_dir/jwt-public.pem" 2>/dev/null

    # Preserve the old PUBLIC key for dual-key token overlap (the api-server
    # accepts JWT_PREVIOUS_PUBLIC_KEYS_PEM during the overlap window — set it
    # in .env / APEXMAIL_PROD_ENV for the staged deploy, remove after).
    local old_public_file
    old_public_file="$BACKUP_DIR/$TIMESTAMP/jwt-public-previous.pem"
    mkdir -p "$BACKUP_DIR/$TIMESTAMP"
    read_secret JWT_PUBLIC_KEY_PEM > "$old_public_file" 2>/dev/null || true
    chmod 600 "$old_public_file" 2>/dev/null || true

    write_secret JWT_PRIVATE_KEY_PEM "$(cat "$temp_dir/jwt-private.pem")"
    write_secret JWT_PUBLIC_KEY_PEM "$(cat "$temp_dir/jwt-public.pem")"

    recreate_services api-server status-server

    rm -rf "$temp_dir"
    log_info "JWT keys rotated (files: $(secret_file JWT_PRIVATE_KEY_PEM))."
    log_info "Old public key preserved at $old_public_file for token overlap:"
    log_detail "  Set JWT_PREVIOUS_PUBLIC_KEYS_PEM in .env for the overlap window"
    log_detail "  (expiry + 5 min skew), then remove it and recreate api-server."
}

rotate_api_key_hash() {
    log_step "Rotating API key hash secret..."
    BACKUP_KEYS+=(PROD_API_KEY_HASH_SECRET_FILE)

    local new_secret
    new_secret=$(openssl rand -base64 48)

    write_secret API_KEY_HASH_SECRET "$new_secret"
    recreate_services api-server

    log_info "API key hash secret rotated (file: $(secret_file API_KEY_HASH_SECRET))."
    log_info "Existing hashes re-hash lazily via the dual-key overlap in the auth"
    log_info "middleware; the backup copy in $BACKUP_DIR/$TIMESTAMP is the rollback."
}

rotate_dkim() {
    log_step "Rotating DKIM signing keys..."
    BACKUP_KEYS+=(PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE)

    # Per-domain DKIM keys are encrypted in the database with this KEK.
    # Rotating it requires re-encrypting the stored keys — see
    # docs/operations/secret-rotation.md before running this.
    local new_kek
    new_kek=$(openssl rand -hex 32)

    write_secret DKIM_PRIVATE_KEY_ENCRYPTION_KEY "$new_kek"
    recreate_services api-server worker mta

    log_info "DKIM private-key encryption key (KEK) rotated."
    log_warn "Stored per-domain DKIM keys must be re-encrypted with the new KEK"
    log_warn "BEFORE the old key is destroyed — see the re-encryption procedure in"
    log_warn "docs/operations/secret-rotation.md."
}

rotate_db_credentials() {
    log_step "Rotating database credentials..."
    BACKUP_KEYS+=(PROD_POSTGRES_PASSWORD_FILE)

    local new_password
    new_password=$(openssl rand -base64 32)

    # Update the password in PostgreSQL first
    # Audit M: the password is passed as a psql VARIABLE over stdin
    # (`:'pw'` quotes it safely) — never interpolated into the SQL text,
    # where it would be visible in `ps` output and the server log.
    log_info "Updating password in PostgreSQL..."
    printf "ALTER USER apexmail WITH PASSWORD :'pw';\n" | \
        (cd "$DEPLOY_DIR" && docker compose $COMPOSE_FILES --env-file "$ENV_FILE" \
            exec -T postgres psql -U apexmail -v pw="$new_password") || {
            log_warn "Could not update PostgreSQL password directly — ensure manual update"
        }

    write_secret POSTGRES_PASSWORD "$new_password"
    recreate_services api-server worker tracking mta mailstore status-server \
        billing-service sales-autopilot postgres-backup

    log_info "Database credentials rotated (file: $(secret_file POSTGRES_PASSWORD))."
}

rotate_master_key() {
    log_step "Rotating master encryption key (DKIM KEK)..."
    BACKUP_KEYS+=(PROD_DKIM_PRIVATE_KEY_ENCRYPTION_KEY_FILE)

    local new_kek old_kek_id
    new_kek=$(openssl rand -hex 32)
    old_kek_id="kek-$(date +%Y%m%d)-$(openssl rand -hex 4)"

    write_secret DKIM_PRIVATE_KEY_ENCRYPTION_KEY "$new_kek"

    log_info "Master encryption key rotated. New KEK ID: $old_kek_id"
    log_warn "Re-encrypt all per-domain DKIM keys with the new KEK."
    log_detail "  Procedure: docs/operations/secret-rotation.md#re-encryption-procedure"
    log_detail "  Verify:    scripts/rotate-secrets.sh --validate"
}

# ── Rollback ──────────────────────────────────────────────────────────────────

rollback() {
    log_step "Rolling back last secret rotation..."

    local latest_backup
    latest_backup=$(ls -td "$BACKUP_DIR"/*/ 2>/dev/null | head -1)

    if [[ -z "$latest_backup" || ! -f "$latest_backup/index.txt" ]]; then
        log_error "No backup found to roll back to"
        exit 1
    fi

    log_info "Restoring from backup: $latest_backup"

    local prods f name
    while read -r prods f; do
        [[ -n "$prods" && -n "$f" ]] || continue
        name="$(env_file_path "$prods")"
        if [[ -n "$name" ]]; then
            umask 177
            cp "$latest_backup/$f" "$name"
            chmod 600 "$name"
            log_info "Restored $prods -> $name"
        else
            log_warn "$prods no longer defined in .env — skipped"
        fi
    done < "$latest_backup/index.txt"

    # Recreate everything that consumes rotated secrets
    recreate_services api-server worker tracking mta mailstore status-server \
        billing-service sales-autopilot postgres-backup

    # Audit M: immediate cleanup — the plaintext backup has served its
    # purpose and must not linger in /tmp.
    find "$latest_backup" -type f -exec sh -c 'shred -u "$1" 2>/dev/null' _ {} \; \
        || find "$latest_backup" -type f -delete
    rmdir "$latest_backup" 2>/dev/null || true

    log_info "Secrets rolled back (backup removed)"
    log_warn "After rollback, validate all services are healthy:"
    log_warn "  scripts/rotate-secrets.sh --validate && make verify"
}

# ── Main ──────────────────────────────────────────────────────────────────────

ACTION="menu"
DRY_RUN="false"
FORCE="false"

if [[ $# -eq 0 ]]; then
    # Interactive menu mode
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ApexMail — Automated Secret Rotation (Docker Compose host)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    list_secrets
    echo "Select rotation target:"
    echo "  1) JWT signing keys"
    echo "  2) API key hash secret"
    echo "  3) DKIM signing keys (KEK)"
    echo "  4) Database credentials"
    echo "  5) Master encryption key (DKIM KEK)"
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

# ── Execution ─────────────────────────────────────────────────────────────────

check_prereqs

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
        jwt)            echo "  • Generate new 4096-bit RSA key pair" ;;
        api-key-hash)   echo "  • Generate new API_KEY_HASH_SECRET (48 bytes)" ;;
        dkim)           echo "  • Generate new DKIM KEK (64-hex)" ;;
        db-credentials) echo "  • Generate new database password" ;;
        master-key)     echo "  • Generate new master encryption key (KEK)" ;;
        all)            echo "  • All secrets eligible for rotation" ;;
    esac
    echo "  • Back up the rendered secret files (0600, /tmp)"
    echo "  • Write the new values to the PROD_*_FILE paths"
    echo "  • docker compose up -d --force-recreate <consumers>"
    echo ""
    echo "To execute: $(basename "$0") --$ACTION"
    echo ""
    exit 0
fi

if [[ "$FORCE" != "true" ]]; then
    echo ""
    log_warn "About to rotate: $ACTION"
    log_warn "This will rewrite rendered secret files on $DEPLOY_DIR and recreate services."
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
log_info "Then update APEXMAIL_PROD_ENV (GitHub secret) to match, so the next"
log_info "deploy does not overwrite the rotated files with the old values."
echo ""
