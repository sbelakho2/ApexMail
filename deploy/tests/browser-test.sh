#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# browser-test.sh — Automated browser testing for critical console errors and
# network failures. Uses headless Chromium (no Node.js/Playwright/Puppeteer).
# Checks: JS errors, failed API requests, failed images/fonts, CORS errors,
# mixed content, unhandled rejections, hydration errors, cookie-consent errors.
#
# Node-free rewrite (zero node/npm/npx/playwright):
#   - Each page is loaded in real headless chromium with
#     --enable-logging=stderr so browser console output is captured
#     (console.error / page errors / "Failed to load resource" lines).
#     --dump-dom provides the rendered DOM for title/content length.
#   - Every resource referenced by the rendered DOM (css/js/img/font) is
#     then fetched with curl; 4xx/5xx responses are recorded as
#     failed requests (mirrors the old Playwright `response >= 400` hook).
#   - Best-effort, documented: console messages cannot be perfectly
#     classified error-vs-warning from chromium's log; messages matching
#     clear error patterns (uncaught exceptions, mixed content, net errors,
#     failed resource loads) are errors, everything else is a warning.
#   Per-page JSON keeps the original shape
#   {url,title,contentLength,errors,failedRequests,warnings,
#    hasConsoleErrors,hasFailedRequests} and is appended to the same
#   NDJSON file; the report is still written to .browser-test-report.json
#   as {checked_at, critical, warnings, test_pages}.
# =============================================================================
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPORT_FILE="${SCRIPT_DIR}/.browser-test-report.json"
readonly WORK_DIR="${TMPDIR:-/tmp}/apexmail-browser-test"
readonly NDJSON_FILE="${WORK_DIR}/results.ndjson"

: "${BASE_URL:=https://apexmail.ee}"
: "${TEST_PAGES:=/ /pricing/ /docs/ /features/ /security/ /compliance/ /private-cloud/ /signup /login /contact/ /status/}"
: "${WAIT_MS:=3000}"
: "${VIEWPORT_WIDTH:=1280}"
: "${VIEWPORT_HEIGHT:=800}"
: "${CHROMIUM_BIN:=}"

CRITICAL=0
WARNINGS=0

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

# Count non-whitespace text characters in HTML on stdin (innerText approximation).
content_length() {
    awk '
    {
        l = tolower($0)
        if (l ~ /<script[^>]*>.*<\/script>/ || l ~ /<style[^>]*>.*<\/style>/) { next }
        if (l ~ /<script/ && !s) { s=1; next }
        if (l ~ /<\/script>/ && s) { s=0; next }
        if (s) { next }
        if (l ~ /<style/ && !st) { st=1; next }
        if (l ~ /<\/style>/ && st) { st=0; next }
        if (st) { next }
        print
    }' | sed -e 's/<[^>]*>//g' | tr -d '[:space:]' | wc -c | tr -d ' '
}

# Fetch every same-origin resource referenced in the DOM and report 4xx/5xx.
resource_sweep() {
    local html="$1" url="$2" base_host res abs host code path
    base_host="$(printf '%s' "$url" | sed -E 's|https?://([^/]*).*|\1|')"
    printf '%s' "$html" \
        | grep -oE '(href|src|srcset)="[^"]+"' \
        | sed -E 's/^(href|src|srcset)="([^"]+)"/\2/' \
        | awk '{ if (match($0, /^[^,]+/)) print substr($0, RSTART, RLENGTH) }' \
        | sort -u | while read -r res; do
            case "$res" in
                http://*|https://*) abs="$res" ;;
                //*) abs="https:${res}" ;;
                /*) abs="${BASE_URL}${res}" ;;
                '#'*|''|data:*|mailto:*|tel:*) continue ;;
                *) abs="${BASE_URL}/${res}" ;;
            esac
            host="$(printf '%s' "$abs" | sed -E 's|https?://([^/]*).*|\1|')"
            [[ "$host" == "$base_host" ]] || continue
            # only actual resources, not navigation links
            path="${abs%%\?*}"
            case "$path" in
                *.css|*.js|*.mjs|*.png|*.jpg|*.jpeg|*.gif|*.webp|*.svg|*.ico|*.avif|*.bmp|*.woff|*.woff2|*.ttf|*.otf|*.eot|*.json|*.txt|*.xml|*.pdf|*.map|*.wasm|*.webmanifest) ;;
                *) continue ;;
            esac
            code="$(curl -fsS -o /dev/null --max-time 30 -w '%{http_code}' "$abs" 2>/dev/null || echo "000")"
            if [[ "$code" =~ ^[45][0-9][0-9]$ ]]; then
                echo "{\"type\":\"client-error\",\"url\":\"$abs\",\"status\":$code}"
            fi
        done
}

check_page() {
    local page="$1" out err
    local url="${BASE_URL}${page}"
    echo "  Testing: $url"
    out="$(mktemp "${WORK_DIR}/dom.XXXXXX")"
    err="$(mktemp "${WORK_DIR}/log.XXXXXX")"

    if ! resolve_chromium; then
        rm -f "$out" "$err"
        echo "    SKIP: chromium not available"
        echo '{"url":"'"$url"'","skipped":true,"reason":"chromium not available"}' >> "$NDJSON_FILE"
        return
    fi

    "$CHROMIUM_BIN" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
        --no-first-run --no-default-browser-check --enable-logging=stderr \
        --window-size="${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}" \
        --virtual-time-budget=$((WAIT_MS + 5000)) --dump-dom "$url" >"$out" 2>"$err" || true

    local html title clen
    html="$(cat "$out")"
    title="$(printf '%s' "$html" | grep -o '<title>[^<]*' | head -1 | sed 's/<title>//' || true)"
    clen="$(printf '%s' "$html" | content_length)"

    local errors failed warnings line msg src
    errors="[]"
    failed="[]"
    warnings="[]"
    while IFS= read -r line; do
        msg="$(printf '%s' "$line" | sed -E 's/^\[[^]]*\] "([^"]*)".*/\1/')"
        src="$(printf '%s' "$line" | sed -E 's/.*source: ([^ ]+) \([0-9]+\)$/\1/')"
        if printf '%s' "$msg" | grep -qi 'failed to load resource'; then
            failed="$(echo "$failed" | jq --arg type "failed-request" --arg u "$src" --arg f "$msg" \
                '. + [{type:$type,url:$u,failure:$f}]')"
        elif printf '%s' "$line" | grep -qiE 'mixed content|uncaught|TypeError|ReferenceError|SyntaxError|RangeError|is not defined|net::ERR|ERR_|CORS|Failed to fetch|fetch failed|failed to decode|ots parsing'; then
            errors="$(echo "$errors" | jq --arg type "page-error" --arg t "$msg" \
                '. + [{type:$type,text:$t}]')"
        else
            warnings="$(echo "$warnings" | jq --arg type "console-warning" --arg t "$msg" \
                '. + [{type:$type,text:$t}]')"
        fi
    done < <(grep 'INFO:CONSOLE' "$err" || true)

    local sweep r
    sweep="$(resource_sweep "$html" "$url" || true)"
    while IFS= read -r r; do
        [[ -n "$r" ]] || continue
        failed="$(echo "$failed" | jq --argjson r "$r" '. + [$r]')"
    done < <(printf '%s\n' "$sweep")

    rm -f "$out" "$err"

    local has_errors has_failed output
    has_errors="$(echo "$errors" | jq 'length > 0')"
    has_failed="$(echo "$failed" | jq 'length > 0')"

    output="$(jq -nc --arg url "$url" --arg title "$title" --argjson contentLength "$clen" \
        --argjson errors "$errors" --argjson failedRequests "$failed" --argjson warnings "$warnings" \
        --argjson hasConsoleErrors "$has_errors" --argjson hasFailedRequests "$has_failed" \
        '{url:$url,title:$title,contentLength:$contentLength,errors:$errors,failedRequests:$failedRequests,warnings:$warnings,hasConsoleErrors:$hasConsoleErrors,hasFailedRequests:$hasFailedRequests}')"

    echo "$output" >> "$NDJSON_FILE"

    if [[ "$has_errors" == "true" ]]; then
        echo "    CRITICAL: Console errors on $url"
        CRITICAL=$((CRITICAL+1))
    fi
    if [[ "$has_failed" == "true" ]]; then
        echo "    WARN: Failed requests on $url"
        WARNINGS=$((WARNINGS+1))
    fi
}

main() {
    echo "=== ApexMail Browser Console & Network Test ==="
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    : > "$NDJSON_FILE"

    for page in $TEST_PAGES; do
        check_page "$page"
    done

    # Aggregate results
    if [[ -s "$NDJSON_FILE" ]]; then
        jq -s '.' "$NDJSON_FILE" > "${WORK_DIR}/aggregated.json" 2>/dev/null || true
    fi

    jq -n --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        --arg test_pages "$TEST_PAGES" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,test_pages:$test_pages}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
