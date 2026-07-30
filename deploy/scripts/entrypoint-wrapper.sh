
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
  local env_name="$1"      # e.g. JWT_PRIVATE_KEY_PEM
  local file_var="${env_name}_FILE"  # e.g. JWT_PRIVATE_KEY_PEM_FILE
  local b64_var="${env_name}_B64"    # e.g. JWT_PRIVATE_KEY_PEM_B64
  # Read the *_FILE / *_B64 env var's value via printenv (avoids eval, which
  # would be an injection risk if the variable names ever came from untrusted
  # input). printenv returns exit 1 when the variable is unset.
  local file_path
  file_path="$(printenv "$file_var" 2>/dev/null || true)"

  if [ -n "$file_path" ] && [ -f "$file_path" ] && [ -r "$file_path" ]; then
    local content
    content="$(cat "$file_path")"
    export "${env_name}"="${content}"
    return 0
  fi

  local b64
  b64="$(printenv "$b64_var" 2>/dev/null || true)"
  if [ -n "$b64" ]; then
    local content
    content="$(printf '%s' "$b64" | base64 -d 2>/dev/null || true)"
    if [ -n "$content" ]; then
      export "${env_name}"="${content}"
      return 0
    fi
  fi

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
export_from_file SESSION_SECRET           || true
export_from_file IMPERSONATION_SECRET     || true
export_from_file CSRF_SECRET              || true
export_from_file MCAPTCHA_SECRET_KEY      || true
export_from_file STRIPE_SECRET_KEY        || true
export_from_file STRIPE_WEBHOOK_SECRET    || true
export_from_file DB_PASSWORD              || true
export_from_file REDIS_PASSWORD           || true

echo "[entrypoint-wrapper] Export complete. Starting binary: ${BINARY}"

# Execute the binary
exec /usr/bin/tini -- "${BINARY}" "$@"
