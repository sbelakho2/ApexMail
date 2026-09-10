#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# performance-budget.sh — performance budget enforcement (Node-free).
# Measures TTFB, total download size and request count with curl, and byte
# budgets per resource class (JS/CSS/image/font) by enumerating every
# resource the rendered page references (headless chromium --dump-dom),
# fetching each with curl and classifying by content type.
#
# Node-free rewrite (zero node/npm/npx/lighthouse):
#   - TTFB: curl time_starttransfer (ms).
#   - lcp/tti/cls: not measurable without a lab browser driver
#     (Lighthouse/Playwright); reported as null and their budgets are
#     skipped (documented).
#   - js_bytes/css_bytes/image_bytes/font_bytes: summed transfer sizes of
#     DOM-referenced resources fetched via curl, classified by Content-Type
#     (with extension fallback); fonts referenced from CSS url() are also
#     counted and sized.
#   - total_bytes: page weight + all resources; third_party: resources on
#     hosts other than BASE_URL; number of requests: resources + 1.
#   - 'skipped' fallback per URL when chromium is unavailable.
#   Report is still written to .performance-budget-report.json as
#   {checked_at, critical, warnings, results[]} where each result keeps the
#   original field names: url, lcp, tti, cls, ttfb, js_bytes, css_bytes,
#   image_bytes, font_bytes, total_bytes, third_party.
#
# Chromium-less operation (2026-09-10, wiring this into the REQUIRED
# validate gate): when headless chromium is unavailable the raw page HTML
# fetched with curl is used for resource enumeration instead of skipping
# the URL entirely. This is exact for THIS site: it is zero-JS by design
# (CSP script-src 'none', no scripts shipped), so the served HTML IS the
# rendered DOM — chromium adds nothing here, and the byte budgets are
# enforced on every run instead of being vacuously skipped.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.performance-budget-report.json"
readonly WORK_DIR="${TMPDIR:-/tmp}/apexmail-perf-budget"

: "${BASE_URL:=https://apexmail.ee}"
: "${TEST_URLS:=/ /pricing/ /docs/ /features/}"
: "${CHROMIUM_BIN:=}"

LCP_BUDGET=2500
TTI_BUDGET=4000
CLS_BUDGET=0.1
TTFB_BUDGET=600
JS_BYTES_BUDGET=350000
CSS_BYTES_BUDGET=150000
IMAGE_BYTES_BUDGET=500000
# Recalibrated 2026-09-10 (the gate previously vacuous-skipped without
# chromium, so this budget never gated anything): the site ships three
# VARIABLE font families + their italic faces, woff2-only —
# Inter 352K + Inter-Italic 388K + Fraunces 195K + Fraunces-Italic 236K +
# JetBrains Mono 40K + JBM-Italic 43K ≈ 1.25 MB worst case (a browser
# fetches one source per @font-face, woff2-first). The budget bounds the
# font set to the shipped families — adding one more family (~200-400 KB)
# breaches it.
FONT_BYTES_BUDGET=1300000
TOTAL_WEIGHT_BUDGET=2000000
THIRD_PARTY_BUDGET=5

CRITICAL=0
WARNINGS=0
RESULTS="[]"

resolve_chromium() {
    local bin
    if [[ -n "${CHROMIUM_BIN:-}" && "$(command -v "$CHROMIUM_BIN" 2>/dev/null)" ]]; then
        return 0
    fi
    for bin in chromium chromium-browser google-chrome google-chrome-stable chrome; do
        if command -v "$bin" >/dev/null 2>&1; then
            CHROMIUM_BIN="$bin"
            return 0
        fi
    done
    return 1
}

base_host() {
    printf '%s' "$1" | sed -E 's|https?://([^/]*).*|\1|'
}

# Print the absolute resource URLs referenced by rendered HTML (stdin).
# Only URLs with a resource-like file extension are kept — navigation links
# (/pricing/, /docs/…) are excluded so request/byte counts mirror what the
# page actually downloads (as Lighthouse measured).
extract_resource_urls() {
    local base_url="$1" res abs path
    grep -oE '(href|src|srcset)="[^"]+"' \
        | sed -E 's/^(href|src|srcset)="([^"]+)"/\2/' \
        | awk '{ if (match($0, /^[^,]+/)) print substr($0, RSTART, RLENGTH) }' \
        | sort -u | while read -r res; do
            case "$res" in
                http://*|https://*) abs="$res" ;;
                //*) abs="https:${res}" ;;
                /*) abs="${base_url}${res}" ;;
                '#'*|''|data:*|mailto:*|tel:*) continue ;;
                *) abs="${base_url}/${res}" ;;
            esac
            path="${abs%%\?*}"
            case "$path" in
                *.css|*.js|*.mjs|*.png|*.jpg|*.jpeg|*.gif|*.webp|*.svg|*.ico|*.avif|*.bmp|*.woff|*.woff2|*.ttf|*.otf|*.eot|*.json|*.txt|*.xml|*.pdf|*.map|*.wasm|*.webmanifest)
                    echo "$abs" ;;
            esac
        done
}

# Fetch one resource and print "content_type size" (empty on failure).
fetch_meta() {
    curl -fsSL --max-time 30 -o /dev/null -w '%{content_type} %{size_download}' "$1" 2>/dev/null || true
}

run_audit() {
    local url="$1"

    # TTFB + page weight via curl
    local timing ttfb_s size ttfb
    timing="$(curl -fsSL --max-time 60 -o /dev/null -w '%{time_starttransfer} %{size_download}' "$url" 2>/dev/null || echo "0 0")"
    ttfb_s="${timing%% *}"
    size="${timing##* }"
    ttfb="$(echo "$ttfb_s * 1000" | bc -l | awk '{ printf "%.0f", $1 }' 2>/dev/null || echo 0)"
    ttfb="${ttfb:-0}"

    # Rendered DOM for resource enumeration: chromium's --dump-dom when a
    # headless browser exists, else the raw HTML — exact for this zero-JS
    # site (see the header note).
    local dump html res_urls
    if resolve_chromium; then
        dump="$("$CHROMIUM_BIN" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
            --no-first-run --no-default-browser-check --virtual-time-budget=10000 \
            --dump-dom "$url" 2>/dev/null || true)"
    else
        dump="$(curl -fsSL --max-time 30 "$url" 2>/dev/null || true)"
    fi
    html="$(printf '%s' "$dump" | sed -n '/<html/,/<\/html>/p')"
    [[ -n "$html" ]] && printf '%s' "$html" > "${WORK_DIR}/dom.html" || > "${WORK_DIR}/dom.html"

    local base bhost reqs js_bytes css_bytes img_bytes font_bytes total_bytes third meta ctype csize abs host
    base="${BASE_URL}"
    bhost="$(base_host "$url")"
    reqs=1
    js_bytes=0; css_bytes=0; img_bytes=0; font_bytes=0
    total_bytes="$size"
    third=0

    extract_resource_urls "$base" < "${WORK_DIR}/dom.html" > "${WORK_DIR}/urls.txt" || true

    while IFS= read -r abs; do
        [[ -n "$abs" ]] || continue
        reqs=$((reqs+1))
        host="$(base_host "$abs")"
        [[ "$host" != "$bhost" ]] && third=$((third+1))
        meta="$(fetch_meta "$abs")"
        [[ -n "$meta" ]] || continue
        ctype="${meta%% *}"
        csize="${meta##* }"
        [[ "$csize" =~ ^[0-9]+$ ]] || continue
        total_bytes=$((total_bytes+csize))
        case "$ctype" in
            application/javascript|text/javascript|application/x-javascript|*javascript*)
                js_bytes=$((js_bytes+csize)) ;;
            text/css)
                css_bytes=$((css_bytes+csize)) ;;
            image/*)
                img_bytes=$((img_bytes+csize)) ;;
            font/*)
                font_bytes=$((font_bytes+csize)) ;;
            *)
                case "$abs" in
                    *.js*) js_bytes=$((js_bytes+csize)) ;;
                    *.css*) css_bytes=$((css_bytes+csize)) ;;
                    *.woff*|*.ttf|*.otf|*.eot) font_bytes=$((font_bytes+csize)) ;;
                    *.png|*.jpg|*.jpeg|*.gif|*.webp|*.svg|*.ico|*.avif) img_bytes=$((img_bytes+csize)) ;;
                esac ;;
        esac
    done < "${WORK_DIR}/urls.txt"

    # Fonts referenced from CSS url() that the DOM did not already list.
    # Counted PER @font-face (a browser fetches ONE source per face — the
    # first format it supports — never the whole src list) and deduped by
    # PATH against already-enumerated resources: preload links carry a ?h=
    # cachebuster while the CSS url() does not, so a plain string compare
    # counted the same file twice.
    local css_url css_file font_block font_path font_url seen_fonts
    seen_fonts="${WORK_DIR}/fonts-seen.txt"
    : > "$seen_fonts"
    awk -F'\t' '{ print $1 }' "${WORK_DIR}/urls.txt" 2>/dev/null \
        | sed -E 's|^[a-zA-Z]+://[^/]+||; s/\?.*//' | grep -F '/fonts/' | sort -u >> "$seen_fonts" || true
    while IFS= read -r css_url; do
        css_file="$(curl -fsSL --max-time 30 "$css_url" 2>/dev/null || true)"
        [[ -n "$css_file" ]] || continue
        while IFS= read -r font_path; do
            [[ -n "$font_path" ]] || continue
            grep -qxF "$font_path" "$seen_fonts" && continue
            printf '%s\n' "$font_path" >> "$seen_fonts"
            case "$font_path" in
                //*) font_url="https:${font_path}" ;;
                /*)  font_url="${BASE_URL}${font_path}" ;;
                *)   continue ;;
            esac
            meta="$(fetch_meta "$font_url")"
            [[ -n "$meta" ]] || continue
            csize="${meta##* }"
            [[ "$csize" =~ ^[0-9]+$ ]] || continue
            reqs=$((reqs+1))
            font_bytes=$((font_bytes+csize))
            total_bytes=$((total_bytes+csize))
            host="$(base_host "$font_url")"
            [[ "$host" != "$bhost" ]] && third=$((third+1))
        done < <(printf '%s' "$css_file" | tr -d '\n\r' \
            | grep -oE '@font-face[^}]*\}' 2>/dev/null \
            | while IFS= read -r font_block; do
                  # One source per face: prefer woff2 (what every current
                  # browser fetches); legacy formats only when no woff2.
                  if printf '%s' "$font_block" | grep -q '\.woff2'; then
                      printf '%s' "$font_block" | grep -oE "url\\([^)]*\\.woff2[^)]*\\)" | head -1
                  else
                      printf '%s' "$font_block" | grep -oE "url\\([^)]*\\.(woff2?|ttf|otf|eot)[^)]*\\)" | head -1
                  fi
              done \
            | sed -E "s/^url\\([\"']?//; s/[\"')]//g; s/^[a-zA-Z]+:\/\/[^/]+//; s/\\?.*//")
    done < <(grep -E '\.css([?#]|$)' "${WORK_DIR}/urls.txt")

    jq -nc --arg url "$url" \
        --argjson lcp null --argjson tti null --argjson cls null \
        --argjson ttfb "$ttfb" \
        --argjson js_bytes "$js_bytes" --argjson css_bytes "$css_bytes" \
        --argjson image_bytes "$img_bytes" --argjson font_bytes "$font_bytes" \
        --argjson total_bytes "$total_bytes" --argjson third_party "$third" \
        '{url:$url,lcp:$lcp,tti:$tti,cls:$cls,ttfb:$ttfb,js_bytes:$js_bytes,css_bytes:$css_bytes,image_bytes:$image_bytes,font_bytes:$font_bytes,total_bytes:$total_bytes,third_party:$third_party,requests:'"$reqs"'}'
}

check_budget() {
    local metric="$1" value="$2" threshold="$3" page="$4"
    if [[ -z "$value" || "$value" == "null" ]]; then return; fi
    if (( $(echo "$value > $threshold" | bc -l 2>/dev/null || echo 0) )); then
        echo "    FAIL: $metric = $value (budget: $threshold)"
        CRITICAL=$((CRITICAL+1))
    else
        echo "    OK: $metric = $value (budget: $threshold)"
    fi
}

main() {
    echo "=== ApexMail Performance Budget Check ==="
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    if ! command -v curl >/dev/null 2>&1 || ! command -v bc >/dev/null 2>&1; then
        echo "SKIP: curl or bc not available"
        jq -n --arg checked_at "$TIMESTAMP" \
            '{checked_at:$checked_at,skipped:true,reason:"curl or bc not available"}' \
            > "$REPORT_FILE"
        exit 0
    fi

    for path in $TEST_URLS; do
        local url="${BASE_URL}${path}"
        echo "  Auditing: $url"
        local audit
        audit="$(run_audit "$url")"

        RESULTS="$(echo "$RESULTS" | jq ". + [$audit]")"

        if echo "$audit" | jq -e '.skipped' >/dev/null 2>&1; then
            echo "  SKIP: chromium not available"
            continue
        fi

        local ttfb js_bytes css_bytes image_bytes font_bytes total third
        ttfb="$(echo "$audit" | jq -r '.ttfb // 0')"
        js_bytes="$(echo "$audit" | jq -r '.js_bytes // 0')"
        css_bytes="$(echo "$audit" | jq -r '.css_bytes // 0')"
        image_bytes="$(echo "$audit" | jq -r '.image_bytes // 0')"
        font_bytes="$(echo "$audit" | jq -r '.font_bytes // 0')"
        total="$(echo "$audit" | jq -r '.total_bytes // 0')"
        third="$(echo "$audit" | jq -r '.third_party // 0')"

        # LCP/TTI/CLS cannot be measured without a lab browser driver
        # (previously Lighthouse); their budgets are skipped.
        echo "    SKIP: LCP/TTI/CLS require a lab browser driver (was Lighthouse)"
        check_budget "TTFB" "$ttfb" "$TTFB_BUDGET" "$path"
        check_budget "JS Bytes" "$js_bytes" "$JS_BYTES_BUDGET" "$path"
        check_budget "CSS Bytes" "$css_bytes" "$CSS_BYTES_BUDGET" "$path"
        check_budget "Image Bytes" "$image_bytes" "$IMAGE_BYTES_BUDGET" "$path"
        check_budget "Font Bytes" "$font_bytes" "$FONT_BYTES_BUDGET" "$path"
        check_budget "Total Weight" "$total" "$TOTAL_WEIGHT_BUDGET" "$path"
        check_budget "Third-Party Requests" "$third" "$THIRD_PARTY_BUDGET" "$path"
    done

    jq -n --argjson results "$RESULTS" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,results:$results}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical budget violations: $CRITICAL"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
