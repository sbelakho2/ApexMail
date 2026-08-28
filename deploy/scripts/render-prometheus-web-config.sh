#!/bin/sh
# =============================================================================
# ApexMail — render the Prometheus web config and exec the server.
# =============================================================================
# deploy/prometheus-web.yml is a documented TEMPLATE (basic_auth_users
# commented out — see its header). Prometheus requires bcrypt hashes for
# basic_auth_users; this script renders a live config at container start:
#
#   PROMETHEUS_WEB_PASSWORD_HASH (preferred)
#     A pre-generated bcrypt hash. Generate it ONCE off-container:
#       htpasswd -nbBC 10 admin "$PROMETHEUS_WEB_PASSWORD" | cut -d: -f2
#     (or: python3 -c 'import bcrypt,getpass;print(bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt(10)).decode())')
#     then set PROMETHEUS_WEB_PASSWORD_HASH in .env.
#   PROMETHEUS_WEB_PASSWORD (plaintext)
#     If the container has a bcrypt tool (htpasswd / python3+bcrypt — the
#     stock prom/prometheus image has NEITHER) the hash is generated here;
#     otherwise the script refuses to start an auth-less remote-exposed
#     config and fails loudly with the generation instructions above.
#
# Neither var set: the web config is rendered WITHOUT auth and a loud warning
# is logged — remote exposure must then be refused by BINDING, which the
# compose files already do (host port mapping is 127.0.0.1-only). If you
# ever publish Prometheus beyond loopback, setting one of the vars is
# mandatory.
#
# Mounted read-only by the prometheus service in docker-compose.yml.
# =============================================================================
set -eu

TEMPLATE="${PROMETHEUS_WEB_TEMPLATE:-/etc/prometheus/web.yml.tmpl}"
RENDERED="${PROMETHEUS_WEB_RENDERED:-/tmp/prometheus-web.yml}"
ADMIN_USER="${PROMETHEUS_WEB_USER:-admin}"

log()  { echo "[prometheus-web-render] $*"; }
warn() { echo "[prometheus-web-render] WARNING: $*" >&2; }
die()  { echo "[prometheus-web-render] ERROR: $*" >&2; exit 1; }

[ -f "$TEMPLATE" ] || die "template not found at ${TEMPLATE}"

bcrypt_hash() {
    _pw="$1"
    if command -v htpasswd >/dev/null 2>&1; then
        htpasswd -nbBC 10 "$ADMIN_USER" "$_pw" | cut -d: -f2
        return 0
    fi
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import bcrypt' 2>/dev/null; then
        python3 -c 'import bcrypt,os,sys; sys.stdout.write(bcrypt.hashpw(os.environ["_PROM_PW"].encode(), bcrypt.gensalt(10)).decode())' \
            2>/dev/null && return 0
    fi
    return 1
}

HASH="${PROMETHEUS_WEB_PASSWORD_HASH:-}"

if [ -z "$HASH" ] && [ -n "${PROMETHEUS_WEB_PASSWORD:-}" ]; then
    HASH="$(bcrypt_hash "$PROMETHEUS_WEB_PASSWORD" || true)"
    [ -n "$HASH" ] || die "PROMETHEUS_WEB_PASSWORD is set but this container has no bcrypt tool \
(htpasswd / python3+bcrypt). Pre-generate the hash and set PROMETHEUS_WEB_PASSWORD_HASH instead:
  htpasswd -nbBC 10 ${ADMIN_USER} \"\$PROMETHEUS_WEB_PASSWORD\" | cut -d: -f2"
fi

if [ -n "$HASH" ]; then
    # Basic-auth enabled web config (rendered copy; the mounted template stays
    # read-only documentation).
    cat >"$RENDERED" <<EOF
# Rendered at container start by render-prometheus-web-config.sh
# (from PROMETHEUS_WEB_PASSWORD_HASH / PROMETHEUS_WEB_PASSWORD).
basic_auth_users:
  ${ADMIN_USER}: ${HASH}
EOF
    log "web config rendered with basic auth (user: ${ADMIN_USER}) at ${RENDERED}"
else
    cat >"$RENDERED" <<'EOF'
# Rendered at container start by render-prometheus-web-config.sh — NO AUTH.
# See deploy/prometheus-web.yml for how to enable basic_auth_users.
EOF
    warn "no PROMETHEUS_WEB_PASSWORD(_HASH) set — Prometheus web UI/API is UNAUTHENTICATED."
    warn "Exposure is refused by BINDING only: the compose files publish 9090 on 127.0.0.1."
    warn "Grafana scrapes over the compose network are unaffected. Do NOT publish 9090 off-loopback"
    warn "without setting a password (see deploy/DEPLOYMENT.md)."
fi

exec /bin/prometheus "$@"
