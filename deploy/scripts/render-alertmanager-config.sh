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
# Delivery-channel validation: when NONE of PagerDuty/OpsGenie/Slack/real
# email (SMTP_HOST other than the dead 127.0.0.1 default) is configured, a
# loud banner is stamped into the rendered config comments AND stderr — the
# deploy is not failed, but the dead-config case is unmistakable. Run with
# `--check` to render + validate without exec'ing alertmanager.
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

# ── Optional integrations: strip blocks whose credential is empty ───────────
# Alertmanager REJECTS the whole config (and crash-loops the container) when
# a receiver declares an empty PagerDuty routing key / OpsGenie API key, and
# a Slack webhook with an empty path is undeliverable. Deployments that have
# not configured these integrations must still boot: remove the receiver
# blocks / entries whose credential rendered as empty.

# strip_mapping_block <key> — delete every `<indent>key:` mapping and every
# following line indented deeper than that key (the nested block).
strip_mapping_block() {
  _key="$1"
  awk -v key="$_key" '
    {
      if (stripping) {
        if ($0 ~ /^[[:space:]]*$/) { pending++; next }
        match($0, /^[[:space:]]*/)
        if (RLENGTH > indent) { pending = 0; next }
        for (i = 0; i < pending; i++) print ""
        pending = 0; stripping = 0
      }
      if ($0 ~ "^[[:space:]]+" key ":") {
        match($0, /^[[:space:]]*/); indent = RLENGTH
        stripping = 1; next
      }
      print
    }' "$RENDERED" > "${RENDERED}.tmp" && mv "${RENDERED}.tmp" "$RENDERED"
}

# strip_empty_slack_webhooks — delete every `- url: <q>https://hooks.slack.com/services/<q>`
# list entry (and its deeper-indented fields) whose webhook path rendered
# empty. Entries with a real path keep their full URL and do not match.
strip_empty_slack_webhooks() {
  awk '
    {
      if (stripping) {
        if ($0 ~ /^[[:space:]]*$/) { pending++; next }
        match($0, /^[[:space:]]*/)
        if (RLENGTH > indent) { pending = 0; next }
        for (i = 0; i < pending; i++) print ""
        pending = 0; stripping = 0
      }
      if (index($0, "- url: \047https://hooks.slack.com/services/\047") > 0) {
        match($0, /^[[:space:]]*/); indent = RLENGTH
        stripping = 1; next
      }
      print
    }' "$RENDERED" > "${RENDERED}.tmp" && mv "${RENDERED}.tmp" "$RENDERED"
}

if [ -z "$(printenv PAGERDUTY_ROUTING_KEY 2>/dev/null || true)" ]; then
  strip_mapping_block pagerduty_configs
  echo "[alertmanager-render] PAGERDUTY_ROUTING_KEY unset — pagerduty_configs receivers stripped"
fi
if [ -z "$(printenv OPSGENIE_API_KEY 2>/dev/null || true)" ]; then
  strip_mapping_block opsgenie_configs
  echo "[alertmanager-render] OPSGENIE_API_KEY unset — opsgenie_configs receivers stripped"
fi
if [ -z "$(printenv SLACK_WEBHOOK_PATH 2>/dev/null || true)" ] || \
   [ -z "$(printenv SLACK_WEBHOOK_PATH_LOW 2>/dev/null || true)" ]; then
  strip_empty_slack_webhooks
  echo "[alertmanager-render] empty SLACK_WEBHOOK_PATH[_LOW] — matching slack webhook entries stripped"
fi

# ── Delivery-channel validation (audit: alert delivery was a black hole) ────
# The compose files default SMTP_HOST to 127.0.0.1 (nothing listens there in
# the container network) and every receiver env var to empty. When ALL of
# PagerDuty / OpsGenie / Slack / real email are unconfigured, every alert
# still fires, is grouped, and is routed to the internal
# observability:4400/alerts webhook only — i.e. alerts about the platform are
# delivered INTO the platform that is failing. That must be unmistakable, so
# this check stamps a loud banner into the rendered config comments AND
# prints to stderr. It deliberately does NOT hard-fail the deploy (the
# internal webhook still records alerts; failing the container would turn a
# delivery problem into a stack-down problem).
#
# Email counts as configured only when SMTP_HOST points somewhere real: the
# 127.0.0.1/localhost defaults are the dead-loopback case the compose files
# fall back to.
delivery_channels_configured() {
  _smtp_host="$(printenv SMTP_HOST 2>/dev/null || true)"
  case "$_smtp_host" in
    ""|127.0.0.1|localhost|::1) _email_ok=0 ;;
    *) _email_ok=1 ;;
  esac
  [ "$(printenv PAGERDUTY_ROUTING_KEY 2>/dev/null || true)" ] && return 0
  [ "$(printenv OPSGENIE_API_KEY 2>/dev/null || true)" ] && return 0
  [ "$(printenv SLACK_WEBHOOK_PATH 2>/dev/null || true)" ] && return 0
  [ "$(printenv SLACK_WEBHOOK_PATH_LOW 2>/dev/null || true)" ] && return 0
  [ "$_email_ok" -eq 1 ] && return 0
  return 1
}

validate_delivery_channels() {
  if delivery_channels_configured; then
    echo "[alertmanager-render] OK: at least one external delivery channel configured"
    return 0
  fi
  {
    echo "#"
    echo "# ############################################################################"
    echo "# #                                                                          ##"
    echo "# #  WARNING: NO EXTERNAL ALERT DELIVERY CHANNEL IS CONFIGURED               ##"
    echo "# #                                                                          ##"
    echo "# #  NONE of the following are set to working values:                        ##"
    echo "# #    PAGERDUTY_ROUTING_KEY, OPSGENIE_API_KEY,                              ##"
    echo "# #    SLACK_WEBHOOK_PATH / SLACK_WEBHOOK_PATH_LOW,                          ##"
    echo "# #    SMTP_HOST (currently the dead 127.0.0.1 default)                      ##"
    echo "# #                                                                          ##"
    echo "# #  Alerts are only routed to the INTERNAL observability webhook            ##"
    echo "# #  (http://observability:4400/alerts) — when the platform itself is        ##"
    echo "# #  down, nobody is notified. Set at least ONE receiver env var             ##"
    echo "# #  (see deploy/DEPLOYMENT.md \"Alerting / notification receivers\").         ##"
    echo "# #                                                                          ##"
    echo "# ############################################################################"
    echo "#"
  } >"${RENDERED}.banner"
  cat "$RENDERED" >>"${RENDERED}.banner" && mv "${RENDERED}.banner" "$RENDERED"
  echo "[alertmanager-render] ================================================================" >&2
  echo "[alertmanager-render] WARNING: NO EXTERNAL ALERT DELIVERY CHANNEL IS CONFIGURED!" >&2
  echo "[alertmanager-render]   PagerDuty / OpsGenie / Slack / email are ALL unconfigured" >&2
  echo "[alertmanager-render]   (SMTP_HOST is '${_smtp_host:-unset}' — nothing listens there)." >&2
  echo "[alertmanager-render]   Alerts only reach the internal observability webhook." >&2
  echo "[alertmanager-render]   Set at least one of: PAGERDUTY_ROUTING_KEY, OPSGENIE_API_KEY," >&2
  echo "[alertmanager-render]   SLACK_WEBHOOK_PATH, or a real SMTP_HOST (+SMTP creds) —" >&2
  echo "[alertmanager-render]   see deploy/DEPLOYMENT.md. Continuing (not failing)..." >&2
  echo "[alertmanager-render] ================================================================" >&2
}

# --check: render + validate only (no exec) — usable from CI/verify stages
# or a shell on the host to test the wiring without starting alertmanager.
case "${1:-}" in
  --check) validate_delivery_channels; exit 0 ;;
esac

validate_delivery_channels

echo "[alertmanager-render] config rendered at ${RENDERED}; starting alertmanager"
exec /bin/alertmanager --config.file="$RENDERED" --storage.path="$STORAGE_PATH" "$@"
