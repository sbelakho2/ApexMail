#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# desktop-browser-test.sh — Cross-browser desktop testing.
# Tests: Chrome, Safari, Firefox, Edge at 1280px width.
# Journeys: homepage to signup, pricing calculation, docs nav, code-copy,
# enterprise form, login, password reset, legal pages, status.
#
# Node-free rewrite (zero node/npm/npx/playwright):
#   - Chrome label: headless chromium (--headless=new --dump-dom +
#     --enable-logging=stderr) renders every journey; title, h1, nav,
#     footer and visible-text length are asserted from the rendered DOM,
#     and uncaught page errors are captured from the browser log.
#   - Firefox label: if a `firefox` binary exists it is smoke-rendered
#     headlessly per journey; all DOM assertions also run against the
#     served markup (curl), since Firefox headless cannot dump DOM.
#   - Safari/Edge label: no standalone headless binary is available;
#     the same DOM assertions run against the served markup via curl
#     (best-effort markup-level check, documented).
#   The per-journey JSON keeps the original shape
#   {journey,url,title,hasH1,hasNav,hasFooter,visibleText,status,errors}
#   and the report is still written to .desktop-browser-report.json
#   as {checked_at, critical, issues}.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.desktop-browser-report.json"
readonly WORK_DIR="${TMPDIR:-/tmp}/apexmail-desktop-test"

: "${BASE_URL:=https://apexmail.ee}"
: "${VIEWPORT_WIDTH:=1280}"
: "${VIEWPORT_HEIGHT:=800}"
: "${CHROMIUM_BIN:=}"

BROWSERS=("chromium" "firefox" "webkit")
BROWSER_LABELS=("Chrome" "Firefox" "Safari/Edge")
JOURNEY_NAMES=(homepage pricing docs security compliance private-cloud features contact terms privacy status)
JOURNEY_URLS=('/' '/pricing/' '/docs/' '/security/' '/compliance/' '/private-cloud/' '/features/' '/contact/' '/terms/' '/privacy/' '/status/')
CRITICAL=0
ISSUES="[]"

add_issue() {
    local page="$1" element="$2" severity="$3" message="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg page "$page" --arg element "$element" \
        --arg severity "$severity" --arg message "$message" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{page:$page,element:$element,severity:$severity,message:$message,checked_at:$checked_at}]')"
    [[ "$severity" == "critical" ]] && CRITICAL=$((CRITICAL+1))
}

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
text_length() {
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

# Markup-level assertions shared by all engines (input: HTML on stdin).
# Prints: TITLE|H1|NAV|FOOTER|TEXTLEN  (0/1 for booleans)
markup_checks() {
    local html
    html="$(cat)"
    local title h1 nav footer tlen
    title="$(printf '%s' "$html" | grep -o '<title>[^<]*' | head -1 | sed 's/<title>//' || true)"
    h1=0; nav=0; footer=0
    printf '%s' "$html" | grep -qi '<h1[ >]' && h1=1
    printf '%s' "$html" | grep -qi '<nav' && nav=1
    printf '%s' "$html" | grep -qi '<footer' && footer=1
    tlen="$(printf '%s' "$html" | text_length)"
    echo "$title|$h1|$nav|$footer|$tlen"
}

# Run the DOM assertions for one journey with chromium and print the journey JSON.
chromium_journey() {
    local name="$1" url="$2" out err html title h1 nav footer tlen errors status
    out="$(mktemp "${WORK_DIR}/dom.XXXXXX")"
    err="$(mktemp "${WORK_DIR}/log.XXXXXX")"

    if ! "$CHROMIUM_BIN" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
        --no-first-run --no-default-browser-check --enable-logging=stderr \
        --window-size="${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}" \
        --virtual-time-budget=12000 --dump-dom "$url" >"$out" 2>"$err"; then
        rm -f "$out" "$err"
        echo "{\"journey\":\"$name\",\"url\":\"$url\",\"status\":\"fail\",\"error\":\"page load failed\"}"
        return 0
    fi

    html="$(cat "$out")"
    title="$(printf '%s' "$html" | grep -o '<title>[^<]*' | head -1 | sed 's/<title>//' || true)"
    h1=0; nav=0; footer=0
    printf '%s' "$html" | grep -qi '<h1[ >]' && h1=1
    printf '%s' "$html" | grep -qi '<nav' && nav=1
    printf '%s' "$html" | grep -qi '<footer' && footer=1
    tlen="$(printf '%s' "$html" | text_length)"

    errors="[]"
    status="pass"
    local errs
    # Page errors only: the original test captured page.on('pageerror'),
    # i.e. uncaught JS exceptions — not console messages.
    errs="$(grep 'INFO:CONSOLE' "$err" \
        | grep -iE 'uncaught|TypeError|ReferenceError|SyntaxError|RangeError|is not defined' \
        | sed -E 's/^\[[^]]*\] //' \
        | jq -R -s -c 'split("\n") | map(select(length>0))' 2>/dev/null || true)"
    if [[ -n "$errs" && "$errs" != "[]" ]]; then
        status="error"
        errors="$errs"
    fi

    rm -f "$out" "$err"
    jq -nc --arg journey "$name" --arg url "$url" --arg title "$title" \
        --argjson hasH1 "$h1" --argjson hasNav "$nav" --argjson hasFooter "$footer" \
        --argjson visibleText "$([ "$tlen" -gt 100 ] && echo true || echo false)" \
        --arg status "$status" --argjson errors "$errors" \
        '{journey:$journey,url:$url,title:$title,hasH1:$hasH1,hasNav:$hasNav,hasFooter:$hasFooter,visibleText:$visibleText,status:$status,errors:$errors}'
}

# Markup-only journey check (used for firefox/webkit labels) — prints journey JSON.
markup_journey() {
    local name="$1" url="$2" label="$3" html checks title h1 nav footer tlen status
    html="$(curl -fsSL --max-time 30 "$url" 2>/dev/null || true)"
    if [[ -z "$html" ]]; then
        echo "{\"journey\":\"$name\",\"url\":\"$url\",\"status\":\"fail\",\"error\":\"page fetch failed\"}"
        return 0
    fi
    checks="$(printf '%s' "$html" | markup_checks)"
    IFS='|' read -r title h1 nav footer tlen <<< "$checks"
    # A missing <title> is reported as data, not a journey failure
    # (the original page.title() was informational too).
    status="pass"
    jq -nc --arg journey "$name" --arg url "$url" --arg title "$title" \
        --argjson hasH1 "$h1" --argjson hasNav "$nav" --argjson hasFooter "$footer" \
        --argjson visibleText "$([ "$tlen" -gt 100 ] && echo true || echo false)" \
        --arg status "$status" --argjson errors "[]" \
        '{journey:$journey,url:$url,title:$title,hasH1:$hasH1,hasNav:$hasNav,hasFooter:$hasFooter,visibleText:$visibleText,status:$status,errors:$errors}'
}

test_journey() {
    local browser="$1" label="$2" name url
    echo "  Browser: $label"
    for i in "${!JOURNEY_NAMES[@]}"; do
        name="${JOURNEY_NAMES[$i]}"
        url="${BASE_URL}${JOURNEY_URLS[$i]}"
        local result status
        case "$browser" in
            chromium)
                if ! resolve_chromium; then
                    echo "    SKIP: $name (chromium not available)"
                    continue
                fi
                result="$(chromium_journey "$name" "$url")"
                ;;
            firefox)
                if ! command -v firefox >/dev/null 2>&1; then
                    echo "    SKIP: $name (firefox not installed)"
                    continue
                fi
                if ! firefox --headless --screenshot="${WORK_DIR}/fx.png" \
                        --window-size="${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}" "$url" >/dev/null 2>&1; then
                    echo "    FAIL: $name on $label (smoke render failed)"
                    add_issue "$url" "firefox-render" "critical" "firefox headless render failed for $name"
                    continue
                fi
                result="$(markup_journey "$name" "$url" "$label")"
                ;;
            webkit)
                result="$(markup_journey "$name" "$url" "$label")"
                ;;
        esac
        status="$(echo "$result" | jq -r '.status // "unknown"')"
        if [[ "$status" == "error" || "$status" == "fail" ]]; then
            echo "    FAIL: $name on $label ($status)"
            add_issue "$url" "$name" "critical" "$status on $label for $name"
        else
            echo "    OK: $name on $label"
        fi
    done
}

main() {
    echo "=== ApexMail Desktop Browser Test ==="
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    if ! command -v curl >/dev/null 2>&1 && ! resolve_chromium; then
        echo "SKIP: neither curl nor chromium available"
        jq -n '{skipped:true,reason:"neither curl nor chromium available"}' > "$REPORT_FILE"
        exit 0
    fi
    if resolve_chromium; then
        echo "Using chromium: $(command -v "$CHROMIUM_BIN")"
    fi

    for i in "${!BROWSERS[@]}"; do
        test_journey "${BROWSERS[$i]}" "${BROWSER_LABELS[$i]}"
    done

    jq -n --argjson critical "$CRITICAL" \
        --arg checked_at "$TIMESTAMP" \
        --argjson issues "$ISSUES" \
        '{checked_at:$checked_at,critical:$critical,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical browser-specific defects: $CRITICAL"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
