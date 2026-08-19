#!/bin/sh
# =============================================================================
# ApexMail — Entrypoint wrapper for Docker services
# =============================================================================
# Bridges Docker secrets (_FILE suffix env vars) to the native env vars
# expected by the ApexMail binaries.
#
# Usage:
#   /opt/apexmail/entrypoint-wrapper.sh                     -> runs "api-server" with CMD args
#   /opt/apexmail/entrypoint-wrapper.sh api-server          -> runs "api-server"
#   /opt/apexmail/entrypoint-wrapper.sh /usr/local/bin/tracking-service  -> runs full-path binary
#
# NOTE: If the first argument starts with '-', it is treated as a CMD flag
# (e.g. "--listen 0.0.0.0:3000" from Docker CMD) and the default binary
# (api-server) is used. Set BINARY_NAME env var to override the default.
# =============================================================================

set -e

# ── Determine which binary to run ──────────────────────────────────────────
# If $1 is empty or starts with '-', it's a CMD flag — use the default binary.
case "${1:-}" in
  -*|"")
    BINARY="${BINARY_NAME:-api-server}"
    ;;
  *)
    BINARY="$1"
    shift
    ;;
esac

# ── Helper: read a secret file and export as an env var ────────────────────
export_from_file() {
  _ef_env_name="$1"
  _ef_file_var="${_ef_env_name}_FILE"
  _ef_b64_var="${_ef_env_name}_B64"
  _ef_file_path="$(printenv "$_ef_file_var" 2>/dev/null || true)"

  if [ -n "$_ef_file_path" ] && [ -f "$_ef_file_path" ] && [ -r "$_ef_file_path" ]; then
    _ef_content="$(cat "$_ef_file_path")"
    export "${_ef_env_name}"="${_ef_content}"
    unset _ef_content _ef_file_path _ef_file_var _ef_b64_var _ef_env_name
    return 0
  fi

  _ef_b64="$(printenv "$_ef_b64_var" 2>/dev/null || true)"
  if [ -n "$_ef_b64" ]; then
    _ef_content="$(printf '%s' "$_ef_b64" | base64 -d 2>/dev/null || true)"
    if [ -n "$_ef_content" ]; then
      export "${_ef_env_name}"="${_ef_content}"
      unset _ef_content _ef_file_path _ef_file_var _ef_b64_var _ef_env_name
      return 0
    fi
  fi

  unset _ef_content _ef_file_path _ef_file_var _ef_b64_var _ef_env_name
  return 1
}

# Export all required env vars from _FILE or _B64 variants.
# Each call is guarded with '|| true' because export_from_file returns 1
# when a variable is not set (which is expected).  With set -e above, an
# unguarded return 1 would abort the entire script.
export_from_file JWT_PRIVATE_KEY_PEM      || true
export_from_file JWT_PUBLIC_KEY_PEM       || true
export_from_file API_KEY_HASH_SECRET      || true
export_from_file WEBHOOK_SIGNING_SECRET   || true
export_from_file TRACKING_SECRET_KEY      || true
export_from_file INTERNAL_SERVICE_TOKEN   || true
export_from_file SERVICE_AUTH_TOKEN       || true
export_from_file SESSION_SECRET           || true
export_from_file IMPERSONATION_SECRET     || true
export_from_file CSRF_SECRET              || true
export_from_file DKIM_PRIVATE_KEY_ENCRYPTION_KEY || true
export_from_file KIWI_SECRET_KEY          || true
export_from_file STRIPE_SECRET_KEY        || true
export_from_file STRIPE_WEBHOOK_SECRET    || true
export_from_file DB_PASSWORD              || true
export_from_file REDIS_PASSWORD           || true
export_from_file CLICKHOUSE_PASSWORD      || true

# Percent-encode a value used in a URI user-info component. Docker secret
# values are arbitrary and commonly contain characters such as `@` or `:`;
# interpolating them directly changes the host or otherwise corrupts the URL.
urlencode_userinfo() {
  printf '%s' "$1" | LC_ALL=C od -An -tx1 | tr -d ' \n' | sed 's/\(..\)/%\1/g'
}

# Direct fallback: if DB_PASSWORD wasn't exported by export_from_file (the
# indirect export can fail in some POSIX sh implementations), read the
# secret file directly.
if [ -z "${DB_PASSWORD:-}" ] && [ -n "${DB_PASSWORD_FILE:-}" ] && [ -f "${DB_PASSWORD_FILE}" ]; then
  DB_PASSWORD="$(cat "${DB_PASSWORD_FILE}")"
  export DB_PASSWORD
fi
if [ -z "${REDIS_PASSWORD:-}" ] && [ -n "${REDIS_PASSWORD_FILE:-}" ] && [ -f "${REDIS_PASSWORD_FILE}" ]; then
  REDIS_PASSWORD="$(cat "${REDIS_PASSWORD_FILE}")"
  export REDIS_PASSWORD
fi
if [ -z "${CLICKHOUSE_PASSWORD:-}" ] && [ -n "${CLICKHOUSE_PASSWORD_FILE:-}" ] && [ -f "${CLICKHOUSE_PASSWORD_FILE}" ]; then
  CLICKHOUSE_PASSWORD="$(cat "${CLICKHOUSE_PASSWORD_FILE}")"
  export CLICKHOUSE_PASSWORD
fi

# ── Construct DATABASE_URL from DB_* parts if not already set ──────────────
if [ -z "${DATABASE_URL:-}" ] && [ -n "${DB_HOST:-}" ]; then
  DB_PORT_VAL="${DB_PORT:-5432}"
  DB_NAME_VAL="${DB_NAME:-apexmail}"
  DB_USER_VAL="${DB_USER:-apexmail}"
  DB_USER_ENCODED="$(urlencode_userinfo "${DB_USER_VAL}")"
  if [ -n "${DB_PASSWORD:-}" ]; then
    DB_PASSWORD_ENCODED="$(urlencode_userinfo "${DB_PASSWORD}")"
    export DATABASE_URL="postgresql://${DB_USER_ENCODED}:${DB_PASSWORD_ENCODED}@${DB_HOST}:${DB_PORT_VAL}/${DB_NAME_VAL}?sslmode=disable"
    unset DB_PASSWORD_ENCODED
  else
    export DATABASE_URL="postgresql://${DB_USER_ENCODED}@${DB_HOST}:${DB_PORT_VAL}/${DB_NAME_VAL}?sslmode=disable"
  fi
  unset DB_USER_ENCODED
fi

# ── Construct REDIS_URL from REDIS_* parts if not already set ──────────────
if [ -z "${REDIS_URL:-}" ] && [ -n "${REDIS_HOST:-}" ]; then
  REDIS_PORT_VAL="${REDIS_PORT:-6379}"
  if [ -n "${REDIS_PASSWORD:-}" ]; then
    REDIS_PASSWORD_ENCODED="$(urlencode_userinfo "${REDIS_PASSWORD}")"
    export REDIS_URL="redis://:${REDIS_PASSWORD_ENCODED}@${REDIS_HOST}:${REDIS_PORT_VAL}"
    unset REDIS_PASSWORD_ENCODED
  else
    export REDIS_URL="redis://${REDIS_HOST}:${REDIS_PORT_VAL}"
  fi
fi

echo "[entrypoint-wrapper] Export complete. Starting binary: ${BINARY}"
echo "[entrypoint-wrapper] DB_PASSWORD is ${DB_PASSWORD:+set} (${#DB_PASSWORD} chars), DB_HOST=${DB_HOST:-unset}, DATABASE_URL is ${DATABASE_URL:+set}"

# Execute the binary
exec /usr/bin/tini -- "${BINARY}" "$@"
