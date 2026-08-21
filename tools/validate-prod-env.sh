#!/bin/sh
# validate-prod-env.sh — fail fast before a production deploy if any
# required secret is missing, still a documented placeholder, or left at a
# development default. Reads the ${:?} guards directly out of
# docker-compose.prod.yml so the check can never drift from the compose
# contract, then verifies each value in the given env file (default
# .env.production).
#
# Usage: tools/validate-prod-env.sh [.env.production]
set -eu

ENV_FILE="${1:-.env.production}"
COMPOSE="${COMPOSE:-docker-compose.prod.yml}"
BASE_COMPOSE="${BASE_COMPOSE:-docker-compose.yml}"

[ -f "$ENV_FILE" ] || { echo "error: env file '$ENV_FILE' not found" >&2; exit 1; }
[ -f "$COMPOSE" ] || { echo "error: $COMPOSE not found (run from the repo root)" >&2; exit 1; }

fail=0

# Required vars: every ${VAR:?...} substitution in the prod overlay and the
# base file — the variables compose itself refuses to start without.
required=$(grep -oE '\$\{[A-Z0-9_]+:\?' "$COMPOSE" "$BASE_COMPOSE" 2>/dev/null \
  | grep -oE '[A-Z0-9_]+:' | tr -d ':' | sort -u)

for var in $required; do
  value=$(grep -E "^${var}=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"' || true)
  if [ -z "$value" ]; then
    echo "MISSING:   $var (guarded by :? in compose — the deployment will refuse to start)" >&2
    fail=1
  elif echo "$value" | grep -qiE 'REQUIRED-|change-me|changeme|placeholder|^dev-|<[^>]+>'; then
    echo "PLACEHOLDER: $var=$value" >&2
    fail=1
  fi
done

# _FILE indirections: the referenced secret file must exist on this host when
# the path is absolute (deploy-time paths are validated on the server; local
# paths here are checked directly).
if [ "${SKIP_FILE_CHECK:-0}" = "1" ]; then
  echo "note: SKIP_FILE_CHECK=1 — secret-file existence not verified" >&2
else
for var in $(grep -E '^PROD_[A-Z0-9_]+_FILE=' "$ENV_FILE" | cut -d= -f1 | sort -u); do
  path=$(grep -E "^${var}=" "$ENV_FILE" | tail -1 | cut -d= -f2-)
  case "$path" in
    /*) [ -f "$path" ] || { echo "MISSING FILE: $var -> $path" >&2; fail=1; } ;;
  esac
done
fi

# Operational advisories (not fatal): values that default correctly but are
# easy to forget behind the nginx edge.
if ! grep -qE '^DDOS_TRUSTED_PROXIES=.+' "$ENV_FILE"; then
  echo "note: DDOS_TRUSTED_PROXIES is empty — forwarded headers are untrusted;" \
       "set it to the proxy CIDRs when api-server is behind nginx" >&2
fi

if [ "$fail" -ne 0 ]; then
  echo "validate-prod-env: FAILED" >&2
  exit 1
fi
echo "validate-prod-env: OK — every guarded variable is set and non-placeholder"
