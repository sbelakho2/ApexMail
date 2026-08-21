#!/bin/sh
# =============================================================================
# ApexMail — render the Alertmanager config template and exec the binary.
# =============================================================================
# Alertmanager does not expand ${VAR} placeholders in its config file (it has
# no envsubst support), so deploy/alertmanager.yml.tmpl is rendered here at
# container start with plain sh + sed (prom/alertmanager is busybox-based).
#
# Required env (render fails fast when unset):
#   SMTP_HOST, INTERNAL_SERVICE_TOKEN
# Optional env (defaults applied below):
#   SMTP_PORT (587), ALERT_EMAIL_CRITICAL/ALERT_EMAIL_WARNING
#   (admin@apexmail.ee), everything else defaults to empty.
#
# Mounted read-only by the alertmanager services in:
#   docker-compose.yml, services/mail-server/docker-compose.yml
# =============================================================================
set -eu

TEMPLATE="${ALERTMANAGER_TEMPLATE:-/etc/alertmanager/alertmanager.yml.tmpl}"
RENDERED="${ALERTMANAGER_RENDERED:-/tmp/alertmanager.yml}"
STORAGE_PATH="${ALERTMANAGER_STORAGE_PATH:-/alertmanager}"

if [ ! -f "$TEMPLATE" ]; then
  echo "[alertmanager-render] ERROR: template not found at ${TEMPLATE}" >&2
  exit 1
fi

cp "$TEMPLATE" "$RENDERED"

default_for() {
  case "$1" in
    SMTP_PORT) echo "587" ;;
    ALERT_EMAIL_CRITICAL|ALERT_EMAIL_WARNING) echo "admin@apexmail.ee" ;;
    *) echo "" ;;
  esac
}

# Substitute ${VAR} in the rendered copy. Values are escaped for use in the
# sed replacement (backslash, ampersand and the '|' delimiter). A temp file +
# mv is used instead of `sed -i` because the -i syntax differs between BSD
# sed (requires a suffix argument) and busybox/GNU sed.
substitute() {
  _var="$1"
  _val="$2"
  _esc="$(printf '%s' "$_val" | sed -e 's/[\\|&]/\\&/g')"
  _tmp="${RENDERED}.tmp"
  sed "s|\${${_var}}|${_esc}|g" "$RENDERED" > "$_tmp" && mv "$_tmp" "$RENDERED"
}

for var in SMTP_HOST INTERNAL_SERVICE_TOKEN \
           SMTP_PORT SMTP_USERNAME SMTP_PASSWORD OPSGENIE_API_KEY \
           PAGERDUTY_ROUTING_KEY SLACK_WEBHOOK_PATH SLACK_WEBHOOK_PATH_LOW \
           ALERT_EMAIL_CRITICAL ALERT_EMAIL_WARNING; do
  val="$(printenv "$var" 2>/dev/null || true)"
  case "$var" in
    SMTP_HOST|INTERNAL_SERVICE_TOKEN)
      if [ -z "$val" ]; then
        echo "[alertmanager-render] ERROR: required variable ${var} is not set" >&2
        rm -f "$RENDERED"
        exit 1
      fi
      ;;
    *)
      if [ -z "$val" ]; then
        val="$(default_for "$var")"
      fi
      ;;
  esac
  substitute "$var" "$val"
done

# Fail fast on a malformed render (unsubstituted placeholders, bad YAML).
# Header comments legitimately mention '${VAR}', so only non-comment lines
# are checked.
if sed '/^[[:space:]]*#/d' "$RENDERED" | grep -q '${'; then
  echo "[alertmanager-render] ERROR: unresolved \${...} placeholder in rendered config:" >&2
  sed '/^[[:space:]]*#/d' "$RENDERED" | grep -n '${' >&2 || true
  rm -f "$RENDERED"
  exit 1
fi

echo "[alertmanager-render] config rendered at ${RENDERED}; starting alertmanager"
exec /bin/alertmanager --config.file="$RENDERED" --storage.path="$STORAGE_PATH" "$@"
