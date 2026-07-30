#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# verify-deployment.sh — Post-deployment cache-invalidation verification
# =============================================================================
# Verifies that critical legal pages (DPA, Privacy, Terms) return consistent
# content across multiple fetches, confirming cache coherence after deployment.
#
# Usage: ./verify-deployment.sh [base_url]
#   base_url — Target base URL (default: https://apexmail.ee)
#
# Environment variables:
#   DEPLOY_BASE_URL  — Target base URL (default: https://apexmail.ee)
#   FETCH_COUNT      — Number of verification fetches per page (default: 5)
#   MAX_RETRIES      — Max retries per fetch (default: 3)
#   RETRY_DELAY      — Retry delay in seconds (default: 5)
#   OUTPUT_DIR       — Directory for hash output files (default: /tmp/verify-deploy)
# =============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

: "${DEPLOY_BASE_URL:=${1:-https://apexmail.ee}}"
: "${FETCH_COUNT:=5}"
: "${MAX_RETRIES:=3}"
: "${RETRY_DELAY:=5}"
: "${OUTPUT_DIR:=/tmp/verify-deploy}"

readonly BASE_URL="${DEPLOY_BASE_URL%/}"

readonly CRITICAL_PAGES=(
  "/dpa/"
  "/privacy/"
  "/terms/"
)

readonly HASH_ALGO="sha256"

# ── Setup ─────────────────────────────────────────────────────

mkdir -p "$OUTPUT_DIR"

log() {
  printf '[%s] [%s] %s\n' "$(date -u +%H:%M:%S)" "$1" "$2" >&2
}

# ── Fetch with retry ──────────────────────────────────────────

fetch_page() {
  local url="$1"
  local output_file="$2"
  local attempt=1

  while [[ $attempt -le $MAX_RETRIES ]]; do
    if curl -sS -o "$output_file" -w "%{http_code}" \
      --connect-timeout 10 --max-time 30 \
      -H "Accept: text/html" \
      -H "Cache-Control: no-cache" \
      "$url" 2>/dev/null | grep -q "^2" && [[ -s "$output_file" ]]; then
      return 0
    fi
    log warn "Fetch attempt $attempt/$MAX_RETRIES failed for $url, retrying in ${RETRY_DELAY}s..."
    sleep "$RETRY_DELAY"
    ((attempt++))
  done
  return 1
}

# ── Hash a file ───────────────────────────────────────────────

hash_file() {
  local file="$1"
  if command -v shasum &>/dev/null; then
    shasum -a 256 "$file" | cut -d' ' -f1
  else
    sha256sum "$file" | cut -d' ' -f1
  fi
}

# ── Main verification ─────────────────────────────────────────

main() {
  log info "Starting deployment verification against $BASE_URL"
  log info "Fetch count: $FETCH_COUNT | Pages: ${CRITICAL_PAGES[*]}"

  local failed=0
  local page_hashes_file="${OUTPUT_DIR}/page_hashes.txt"
  > "$page_hashes_file"

  for page in "${CRITICAL_PAGES[@]}"; do
    local page_slug
    page_slug="$(echo "$page" | tr '/' '_' | sed 's/^_//;s/_$//')"
    log info "────────────────────────────────────────────"
    log info "Verifying: $page"

    local hashes=()
    local fetch_failed=0

    for i in $(seq 1 "$FETCH_COUNT"); do
      local outfile="${OUTPUT_DIR}/${page_slug}_fetch_${i}.html"
      if fetch_page "${BASE_URL}${page}" "$outfile"; then
        local h
        h="$(hash_file "$outfile")"
        hashes+=("$h")
        printf '  [fetch %d] %s\n' "$i" "$h"
      else
        log error "  [fetch $i] FAILED — could not retrieve ${BASE_URL}${page}"
        fetch_failed=1
      fi
    done

    if [[ $fetch_failed -eq 1 ]]; then
      log error "  FATAL: One or more fetches failed for $page"
      failed=1
      continue
    fi

    # Check if all hashes are identical
    local first_hash="${hashes[0]}"
    local consistent=true
    for h in "${hashes[@]:1}"; do
      if [[ "$h" != "$first_hash" ]]; then
        consistent=false
        break
      fi
    done

    if [[ "$consistent" == "true" ]]; then
      log info "  PASS: All $FETCH_COUNT fetches returned identical body hash: $first_hash"
      echo "$page_slug: $first_hash (consistent across $FETCH_COUNT fetches)" >> "$page_hashes_file"
    else
      log error "  FAIL: ${FETCH_COUNT} fetches returned DIFFERENT hashes!"
      log error "  Hash list:"
      for idx in "${!hashes[@]}"; do
        log error "    fetch $((idx+1)): ${hashes[idx]}"
      done
      failed=1
    fi
  done

  log info "────────────────────────────────────────────"
  log info "Hash summary written to $page_hashes_file"

  if [[ $failed -eq 0 ]]; then
    log info "ALL CRITICAL PAGES VERIFIED: Consistent hashes across $FETCH_COUNT fetches."
    return 0
  else
    log error "VERIFICATION FAILED: One or more critical pages returned inconsistent hashes."
    log error "Cache invalidation may be incomplete. Do NOT consider the deployment verified."
    return 1
  fi
}

main "$@"
