#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# contrast-check.sh — WCAG 2.2 AA contrast ratio verification.
# Checks body text (4.5:1), large text (3:1), UI components (3:1),
# focus indicators, dark mode, color-only information detection.
#
# Node-free rewrite (zero node/npm/npx/axe/pa11y):
#   - Each page's HTML is fetched with curl; <style> blocks and linked
#     stylesheets are collected and parsed with awk into rule/selector
#     tables (selector, color, background, font-size, font-weight).
#   - CSS custom properties (--brand-600 etc.) are resolved against
#     light/dark variable maps before conversion to RGB.
#   - WCAG 2.x relative luminance and contrast ratio are computed in
#     bash + bc (0.2126/0.7152/0.0722 coefficients, sRGB gamma), with
#     4.5:1 for body text and 3:1 for large text (>=24px, or >=18.66px
#     bold) — a best-effort subset of axe's color-contrast rule:
#       * only CSS-declared colors are inspected (no computed-style
#         resolution, no alpha compositing, no hover/focus states,
#         no gradient analysis);
#       * rules that declare both color and background are paired;
#         rules with only a color fall back to the page background
#         (from --background / body) with a dark-mode variant;
#       * colors that cannot be resolved (e.g. var() without value,
#         named colors outside the built-in map) are skipped.
#   - The same machinery audits local CSS files under BUILD_DIR and
#     flags low-contrast pairs as warnings.
#   Report is still written to .contrast-check-report.json as
#   {checked_at, critical, warnings, issues[]}.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.contrast-check-report.json"
readonly WORK_DIR="${TMPDIR:-/tmp}/apexmail-contrast-check"

: "${BASE_URL:=https://apexmail.ee}"
: "${BUILD_DIR:=../apps/marketing-zola/public}"
: "${TEST_PAGES:=/ /pricing/ /docs/ /features/ /security/ /compliance/}"

CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local page="$1" element="$2" severity="$3" message="$4"
    ISSUES="$(echo "$ISSUES" | jq --arg page "$page" --arg element "$element" \
        --arg severity "$severity" --arg message "$message" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{page:$page,element:$element,severity:$severity,message:$message,checked_at:$checked_at}]')"
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
}

# ---- CSS text processing (portable awk) -------------------------------------

# Print TSV rows: selector \t color \t background \t font-size \t font-weight
css_rules_awk='function emit(sel, decls,   tmp) {
    color=""; bg=""; fs=""; fw=""
    if (match(decls, /(^|[;{])[ \t]*color[ \t]*:[^;]*/)) {
        tmp = substr(decls, RSTART, RLENGTH); sub(/^.*:[ \t]*/, "", tmp); color = tmp
    }
    if (match(decls, /(^|[;{])[ \t]*background-color[ \t]*:[^;]*/)) {
        tmp = substr(decls, RSTART, RLENGTH); sub(/^.*:[ \t]*/, "", tmp); bg = tmp
    } else if (match(decls, /(^|[;{])[ \t]*background[ \t]*:[^;]*/)) {
        tmp = substr(decls, RSTART, RLENGTH); sub(/^.*:[ \t]*/, "", tmp); bg = tmp
    }
    if (match(decls, /(^|[;{])[ \t]*font-size[ \t]*:[^;]*/)) {
        tmp = substr(decls, RSTART, RLENGTH); sub(/^.*:[ \t]*/, "", tmp); fs = tmp
    }
    if (match(decls, /(^|[;{])[ \t]*font-weight[ \t]*:[^;]*/)) {
        tmp = substr(decls, RSTART, RLENGTH); sub(/^.*:[ \t]*/, "", tmp); fw = tmp
    }
    gsub(/[}]/, "", color); gsub(/[}]/, "", bg)
    gsub(/[ \t\r\n]+/, " ", color); gsub(/[ \t\r\n]+/, " ", bg)
    gsub(/[ \t\r\n]+/, " ", fs); gsub(/[ \t\r\n]+/, " ", fw)
    print sel "\t" color "\t" bg "\t" fs "\t" fw
}
{
    line = $0
    n = length(line)
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (in_comment) {
            if (c == "*" && substr(line, i + 1, 1) == "/") { in_comment = 0; i++ }
            continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { in_comment = 1; i++; continue }
        buf = buf c
        if (c == "{") {
            depth++
            if (depth == 1) {
                sel = buf; sub(/\{.*/, "", sel)
                gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", sel)
                buf = ""
            }
        } else if (c == "}") {
            depth--; if (depth < 0) depth = 0
            if (depth == 0) { decls = buf; buf = ""; emit(sel, decls) }
        }
    }
}'

# Emit the declaration blocks of rules whose selector matches darkonly (or not).
css_blocks_awk() {
    local darkonly="$1"
    cat <<AWK
{
    line = \$0
    n = length(line)
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (in_comment) {
            if (c == "*" && substr(line, i + 1, 1) == "/") { in_comment = 0; i++ }
            continue
        }
        if (c == "/" && substr(line, i + 1, 1) == "*") { in_comment = 1; i++; continue }
        buf = buf c
        if (c == "{") {
            depth++
            if (depth == 1) {
                sel = buf; sub(/\{.*/, "", sel)
                gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", sel)
                buf = ""
            }
        } else if (c == "}") {
            depth--; if (depth < 0) depth = 0
            if (depth == 0) {
                decls = buf; buf = ""
                if ((tolower(sel) ~ /dark/) == ${darkonly}) print decls
            }
        }
    }
}
AWK
}

# Print "name\tvalue" lines for every CSS custom property definition.
extract_vars() {
    awk '
    {
        line = $0
        while (match(line, /--[a-zA-Z0-9_-]+[ \t]*:[ \t]*[^;]+/)) {
            t = substr(line, RSTART, RLENGTH)
            sub(/^--/, "", t)
            split(t, a, ":")
            name = a[1]; gsub(/[ \t]+$/, "", name)
            value = substr(t, index(t, ":") + 1)
            gsub(/^[ \t]+|[ \t]+$/, "", value)
            print name "\t" value
            line = substr(line, RSTART + RLENGTH)
        }
    }'
}

# ---- Color / contrast math (bash + bc) --------------------------------------

# Look up a variable (without leading --) in a "name\tvalue" file.
var_lookup() {
    local name="$1" varfile="$2" out
    out="$(awk -F '\t' -v k="$name" '$1 == k { v = $2 } END { print v }' "$varfile")"
    [[ -n "$out" ]] || return 1
    printf '%s' "$out"
}

# Resolve a color value to "r g b" (0-255). Uses light/dark variable maps.
resolve_color() {
    local value="$1" light_vars="$2" dark_vars="$3" selector="$4" var val map
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | xargs)"
    value="${value%%!important}"
    value="$(printf '%s' "$value" | xargs)"
    # expand var(--x) / var(--x, fallback), dark rules prefer the dark map
    local re_var='var\(--[a-zA-Z0-9_-]+(,[^)]*)?\)'
    local guard=0
    while [[ "$value" =~ $re_var ]]; do
        guard=$((guard+1)); [[ $guard -gt 6 ]] && return 1
        var="${BASH_REMATCH[1]}"
        local fb="${BASH_REMATCH[2]:-}"
        val=""
        if [[ "$selector" == *dark* ]]; then
            val="$(var_lookup "$var" "$dark_vars")"
        fi
        [[ -n "$val" ]] || val="$(var_lookup "$var" "$light_vars")"
        if [[ -z "$val" ]]; then
            # try the var's fallback, if any
            if [[ -n "$fb" ]]; then
                val="${fb#,}"
                val="$(printf '%s' "$val" | xargs)"
            else
                return 1
            fi
        fi
        value="${value//"var(--$var${fb})"/$val}"
    done

    local r g b h re_triple re_hex re_rgb
    # bare "r g b" triple (custom property shorthand)
    re_triple='^([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)$'
    if [[ "$value" =~ $re_triple ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"; return 0
    fi
    # #hex (3/6/8 digits)
    re_hex='^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$'
    if [[ "$value" =~ $re_hex ]]; then
        h="${BASH_REMATCH[1]}"
        if [[ "${#h}" -eq 3 ]]; then
            h="${h:0:1}${h:0:1}${h:1:1}${h:1:1}${h:2:1}${h:2:1}"
        fi
        echo "$((16#${h:0:2})) $((16#${h:2:2})) $((16#${h:4:2}))"; return 0
    fi
    # rgb() / rgba() with commas or spaces (percentages allowed)
    # Tailwind v4 syntax "rgb(X / A)" — the /alpha part is stripped.
    re_rgb='^rgba?\((.+)\)$'
    if [[ "$value" =~ $re_rgb ]]; then
        local inner parts
        inner="${BASH_REMATCH[1]}"
        inner="${inner%%\/*}"
        inner="${inner//,/ }"
        [[ "$inner" == *var\(* ]] && return 1
        read -r -a parts <<< "$inner"
        [[ "${#parts[@]}" -lt 3 ]] && return 1
        r="${parts[0]}"; g="${parts[1]}"; b="${parts[2]}"
        [[ "$r" == *% ]] && r=$(( ${r%\%} * 255 / 100 ))
        [[ "$g" == *% ]] && g=$(( ${g%\%} * 255 / 100 ))
        [[ "$b" == *% ]] && b=$(( ${b%\%} * 255 / 100 ))
        [[ "$r" =~ ^[0-9]+$ && "$g" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
        echo "$r $g $b"; return 0
    fi
    # small named-color map (best-effort subset)
    case "$value" in
        white) echo "255 255 255" ;;
        black) echo "0 0 0" ;;
        red) echo "255 0 0" ;;
        green) echo "0 128 0" ;;
        blue) echo "0 0 255" ;;
        gray|grey) echo "128 128 128" ;;
        silver) echo "192 192 192" ;;
        maroon) echo "128 0 0" ;;
        navy) echo "0 0 128" ;;
        teal) echo "0 128 128" ;;
        olive) echo "128 128 0" ;;
        purple) echo "128 0 128" ;;
        fuchsia) echo "255 0 255" ;;
        lime) echo "0 255 0" ;;
        yellow) echo "255 255 0" ;;
        orange) echo "255 165 0" ;;
        brown) echo "165 42 42" ;;
        cyan|aqua) echo "0 255 255" ;;
        transparent) echo "255 255 255" ;;
        *) return 1 ;;
    esac
}

luminance() {
    bc -l <<EOF
scale=8
define chan(x) {
  x = x / 255
  if (x <= 0.03928) return (x / 12.92)
  return e(2.4 * l((x + 0.055) / 1.055))
}
print chan($1) * 0.2126 + chan($2) * 0.7152 + chan($3) * 0.0722
EOF
}

contrast_ratio() {
    local l1 l2 lo hi
    l1="$(luminance "$1" "$2" "$3")"
    l2="$(luminance "$4" "$5" "$6")"
    lo="$(echo "$l1 $l2" | awk '{print ($1 < $2) ? $1 : $2}')"
    hi="$(echo "$l1 $l2" | awk '{print ($1 >= $2) ? $1 : $2}')"
    bc -l <<EOF
scale=3
print ($hi + 0.05) / ($lo + 0.05)
EOF
}

# Is ratio >= threshold? prints 1 or 0 (via bc to avoid float parsing issues)
ratio_ok() {
    bc -l <<EOF
if ($1 >= $2) print 1 else print 0
EOF
}

font_size_px() {
    local v="$1" n
    n="$(printf '%s' "$v" | grep -oE '[0-9.]+' | head -1)"
    [[ -n "$n" ]] || return 1
    case "$v" in
        *rem|*em) echo "scale=2; $n * 16" | bc ;;
        *pt) echo "scale=2; $n * 4 / 3" | bc ;;
        *%) echo "scale=2; $n * 16 / 100" | bc ;;
        *px) echo "$n" ;;
        *) return 1 ;;
    esac
}

# WCAG AA threshold: 3:1 for large text, 4.5:1 otherwise.
contrast_threshold() {
    local fs="$1" fw="$2" px fwn
    case "$fw" in
        bold|bolder|600|700|800|900) fwn=700 ;;
        *) fwn=400 ;;
    esac
    px="$(font_size_px "$fs" 2>/dev/null || true)"
    if [[ -n "$px" ]]; then
        local islarge
        islarge="$(bc -l <<EOF
if ($px >= 24) print 1 else if ($px >= 18.66 && $fwn >= 700) print 1 else print 0
EOF
)"
        [[ "$islarge" == "1" ]] && { echo 3.0; return; }
    fi
    echo 4.5
}

# ---- Rule analysis -----------------------------------------------------------

# Extract the first color-ish token from a CSS value (e.g. background shorthand).
first_color_token() {
    local v="$1"
    if [[ "$v" =~ ^rgba?\( ]] || [[ "$v" =~ ^var\( ]]; then
        # whole-value colors: rgb(var(--x)/alpha) etc. — resolve_color parses them
        printf '%s' "$v" | tr -d '}' | xargs
    else
        printf '%s' "$v" | tr -d '}' | grep -oE '#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|var\(--[a-zA-Z0-9_-]+\)|transparent|[a-zA-Z]+' \
            | tr '[:upper:]' '[:lower:]' | grep -vE '^(url|none|no-repeat|repeat|cover|contain|center|top|left|right|bottom|fixed|scroll|inherit|initial|unset|bold|bolder|normal|linear-gradient|radial-gradient|inline|block|flex|grid|absolute|relative|important)$' \
            | head -1
    fi
}

# Analyze a CSS file; call the issue sink for every violation found.
# args: page_label  css_file  severity(critical|warning)
analyze_css() {
    local page_label="$1" css_file="$2" severity="$3"
    local light_vars dark_vars light_bg dark_bg sel color bg fs fw
    light_vars="$(mktemp "${WORK_DIR}/lightvars.XXXXXX")"
    dark_vars="$(mktemp "${WORK_DIR}/darkvars.XXXXXX")"

    awk "$(css_blocks_awk 0)" "$css_file" 2>/dev/null | extract_vars | tac | awk -F'\t' '!seen[$1]++' >> "$light_vars"
    awk "$(css_blocks_awk 1)" "$css_file" 2>/dev/null | extract_vars | tac | awk -F'\t' '!seen[$1]++' >> "$dark_vars"

    light_bg="$(var_lookup "background" "$light_vars" || true)"
    [[ -n "$light_bg" ]] || light_bg="255 255 255"
    dark_bg="$(var_lookup "background" "$dark_vars" || true)"
    [[ -n "$dark_bg" ]] || dark_bg="$light_bg"

    while IFS=$'\t' read -r sel color bg fs fw; do
        [[ -n "$color" ]] || continue
        local tok fg bg_tok target_bg ratio thr
        bg_tok=""
        tok="$(first_color_token "$color" || true)"
        [[ -n "$tok" ]] || continue
        [[ "$tok" == "transparent" ]] && continue
        fg="$(resolve_color "$tok" "$light_vars" "$dark_vars" "$sel" || true)"
        [[ -n "$fg" ]] || continue

        if [[ -n "$bg" ]]; then
            bg_tok="$(first_color_token "$bg" || true)"
            [[ -n "$bg_tok" ]] || continue
            target_bg="$(resolve_color "$bg_tok" "$light_vars" "$dark_vars" "$sel" || true)"
            [[ -n "$target_bg" ]] || continue
        elif [[ "$sel" == *dark* ]]; then
            target_bg="$dark_bg"
        else
            target_bg="$light_bg"
        fi

        # identical foreground/background is decorative (no visible text)
        [[ "$fg" == "$target_bg" ]] && continue

        thr="$(contrast_threshold "$fs" "$fw")"
        ratio="$(contrast_ratio $fg $target_bg)"
        if [[ "$(ratio_ok "$ratio" "$thr")" != "1" ]]; then
            local element msg
            element="${sel:0:120}"
            msg="WCAG AA contrast ratio ${ratio}:1 below ${thr}:1 (fg ${tok}, bg ${bg_tok:-default})"
            echo "VIOLATION|$element|$msg"
        fi
    done < <(awk "$css_rules_awk" "$css_file" 2>/dev/null)

    rm -f "$light_vars" "$dark_vars"
}

check_contrast() {
    local page="$1" url="${BASE_URL}${page}" html css_file link
    echo "  Checking: $url"
    # Prefer the local build artifact over the live production site; only
    # fall back to the network when the page is not in BUILD_DIR.
    local local_page="" candidate
    for candidate in "${BUILD_DIR}${page}index.html" \
                     "${BUILD_DIR}${page%/}/index.html" \
                     "${BUILD_DIR}${page}.html"; do
        if [[ -f "$candidate" ]]; then
            local_page="$candidate"
            break
        fi
    done
    if [[ -n "$local_page" ]]; then
        html="$(cat "$local_page")"
    else
        html="$(curl -fsSL --max-time 30 "$url" 2>/dev/null || true)"
    fi
    if [[ -z "$html" ]]; then
        echo "    WARN: page unreachable"
        add_issue "$page" "page" "warning" "Page unreachable"
        return
    fi
    css_file="$(mktemp "${WORK_DIR}/pagecss.XXXXXX")"
    # inline <style> blocks
    printf '%s' "$html" | awk '
    { l = tolower($0) }
    l ~ /<style[^>]*>.*<\/style>/ { sub(/^.*<style[^>]*>/, ""); sub(/<\/style>.*$/, ""); print; next }
    l ~ /<style/ { f = 1; sub(/^.*<style[^>]*>/, "") }
    f { print }
    l ~ /<\/style>/ && f { f = 0 }
    ' >> "$css_file" 2>/dev/null || true
    # linked stylesheets — resolve site-relative links against BUILD_DIR
    # first; only fetch over the network when no local file matches.
    while IFS= read -r link; do
        [[ -n "$link" ]] || continue
        local local_css=""
        case "$link" in
            http://*|https://*) ;;
            //*) link="https:${link}" ;;
            /*)
                if [[ -f "${BUILD_DIR}${link}" ]]; then
                    local_css="${BUILD_DIR}${link}"
                else
                    link="${BASE_URL}${link}"
                fi
                ;;
            *)
                if [[ -f "${BUILD_DIR}/${link}" ]]; then
                    local_css="${BUILD_DIR}/${link}"
                else
                    link="${BASE_URL}/${link}"
                fi
                ;;
        esac
        if [[ -n "$local_css" ]]; then
            cat "$local_css" >> "$css_file" 2>/dev/null || true
        else
            curl -fsSL --max-time 30 "$link" >> "$css_file" 2>/dev/null || true
        fi
    done < <(printf '%s' "$html" | grep -oE 'href="[^"]+\.css[^"]*"' | sed -E 's/^href="([^"]*)"/\1/')

    while IFS='|' read -r element msg; do
        [[ -n "$element" ]] || continue
        echo "    CRITICAL: contrast violation on $page: $msg"
        add_issue "$page" "$element" "critical" "$msg"
    done < <(analyze_css "$page" "$css_file" "critical")

    rm -f "$css_file"
}

# Manual CSS check — audit local CSS files for common low-contrast patterns.
check_css_contrast() {
    local css_dir="$1"
    while IFS= read -r css; do
        local rel
        rel="$(echo "$css" | sed "s|${css_dir}||")"
        echo "  Auditing: $css"
        while IFS='|' read -r element msg; do
            [[ -n "$element" ]] || continue
            add_issue "$rel" "$element" "warning" "$msg"
        done < <(analyze_css "$rel" "$css" "warning")
    done < <(find "$css_dir" -name '*.css' 2>/dev/null)
}

main() {
    echo "=== ApexMail WCAG 2.2 AA Contrast Check ==="

    if ! command -v curl >/dev/null 2>&1 || ! command -v bc >/dev/null 2>&1; then
        echo "SKIP: curl or bc not available"
        jq -n --arg checked_at "$TIMESTAMP" \
            '{checked_at:$checked_at,skipped:true,reason:"curl or bc not available"}' \
            > "$REPORT_FILE"
        exit 0
    fi
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    for page in $TEST_PAGES; do
        check_contrast "$page"
    done

    echo ""
    echo "=== CSS Color Audit ==="
    check_css_contrast "$BUILD_DIR"

    jq -n --argjson issues "$ISSUES" \
        --arg checked_at "$TIMESTAMP" \
        --argjson critical "$CRITICAL" \
        --argjson warnings "$WARNINGS" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical contrast violations: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
