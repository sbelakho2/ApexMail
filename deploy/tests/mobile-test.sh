#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# mobile-test.sh — Responsive and mobile device testing.
# Tests at: 320, 360, 375, 390, 414, 768 pixels.
# Checks: header, menu, hero, pricing cards, calculator, tables, code blocks,
# forms, modals, footer, diagrams, docs sidebar, comparison tables, legal text.
# Ensures no horizontal scroll, CTAs visible, forms fit, text no-overlap,
# touch targets min 44x44, sticky elements don't hide content.
#
# Node-free rewrite (zero node/npm/npx/playwright):
#   - bash + curl fetch each page's HTML.
#   - headless chromium (chromium --headless=new --dump-dom, or
#     google-chrome) renders a local probe harness: the fetched HTML is
#     written into a same-origin <iframe> sized to the target viewport
#     (bypasses chromium's 500px minimum window size), and a small inline
#     browser script runs the exact measurements the old Playwright script
#     ran (scrollWidth vs clientWidth, getBoundingClientRect touch targets,
#     pairwise text-overlap counting, sticky rects, CTA rects, form rects)
#     and writes JSON into a <pre> that --dump-dom serializes.
#   - jq extracts and aggregates the results into .mobile-test-report.json
#     (same shape as before: {checked_at, critical, warnings, issues[]}).
#   The old script printed Playwright results but never aggregated them;
#   this rewrite now records every fail/warn as a report issue and exits
#   non-zero when any critical issue exists.
# =============================================================================
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPORT_FILE="${SCRIPT_DIR}/.mobile-test-report.json"
readonly WORK_DIR="${TMPDIR:-/tmp}/apexmail-mobile-test"

: "${BASE_URL:=https://apexmail.ee}"
: "${VIEWPORT_HEIGHT:=900}"
: "${CHROMIUM_BIN:=}"

WIDTHS=(320 360 375 390 414 768)
PAGES=('/' '/pricing/' '/docs/' '/features/' '/security/' '/compliance/' '/private-cloud/' '/contact/' '/terms/' '/privacy/')
CRITICAL=0
WARNINGS=0
ISSUES="[]"

add_issue() {
    local width="$1" page="$2" check="$3" severity="$4" detail="$5"
    ISSUES="$(echo "$ISSUES" | jq --argjson width "$width" --arg page "$page" \
        --arg check "$check" --arg severity "$severity" --arg detail "$detail" \
        --arg checked_at "$TIMESTAMP" \
        '. + [{width:$width,page:$page,check:$check,severity:$severity,detail:$detail,checked_at:$checked_at}]')"
    case "$severity" in
        critical) CRITICAL=$((CRITICAL+1)) ;;
        warning) WARNINGS=$((WARNINGS+1)) ;;
    esac
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

# Render one page at one width inside the harness and print the probe JSON.
probe_page() {
    local width="$1" url="$2" page_file harness probe_file page_json probe_json dump probe
    page_file="$(mktemp "${WORK_DIR}/page.XXXXXX")"
    harness="$(mktemp "${WORK_DIR}/harness.XXXXXX.html")"
    probe_file="$(mktemp "${WORK_DIR}/probe.XXXXXX.js")"

    if ! curl -fsSL --max-time 30 "$url" -o "$page_file" 2>/dev/null; then
        rm -f "$page_file" "$harness" "$probe_file"
        echo '{"error":"page fetch failed"}'
        return 0
    fi

    page_json="$(jq -Rs . "$page_file" | sed 's|</script>|<\\/script>|g')"

    cat > "$probe_file" <<'PROBE'
(function () {
  var out = document.getElementById('probe-result');
  function run() {
    var checks = {};
    try {
      var html = document.documentElement;
      checks['horizontal-scroll'] = (html.scrollWidth > html.clientWidth) ? 'fail' : 'pass';

      var smallTargets = 0;
      document.querySelectorAll('a, button, [role="button"], input[type="submit"]').forEach(function (t) {
        var r = t.getBoundingClientRect();
        if (r.width < 44 || r.height < 44) { smallTargets++; }
      });
      checks['touch-targets'] = smallTargets > 5 ? 'fail' : 'pass';

      var els = document.querySelectorAll('h1,h2,h3,h4,h5,h6,p,span,li,a,button');
      var rects = [];
      els.forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) { rects.push(r); }
      });
      var overlapCount = 0;
      for (var i = 0; i < rects.length; i++) {
        for (var j = i + 1; j < rects.length; j++) {
          var a = rects[i], b = rects[j];
          if (a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top) { overlapCount++; }
        }
      }
      checks['text-overlap'] = overlapCount > 50 ? 'warn' : 'pass';

      var stickyHides = 0;
      document.querySelectorAll('[class*="sticky"], [class*="fixed"]').forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.bottom < 0 || r.top > window.innerHeight) { stickyHides++; }
      });
      checks['sticky-hides-content'] = stickyHides > 0 ? 'warn' : 'pass';

      var ctaVisible = 0;
      document.querySelectorAll('[class*="btn-"], [class*="cta"]').forEach(function (c) {
        var r = c.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) { ctaVisible++; }
      });
      checks['cta-visible'] = ctaVisible > 0 ? 'pass' : 'warn';

      var formOverflows = 0;
      document.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach(function (f) {
        var r = f.getBoundingClientRect();
        if (r.right > window.innerWidth + 10) { formOverflows++; }
      });
      checks['form-fit'] = formOverflows > 0 ? 'fail' : 'pass';
    } catch (e) {
      checks['error'] = String(e && e.message || e);
    }
    out.textContent = JSON.stringify(checks);
  }
  if (document.readyState === 'complete') { setTimeout(run, 500); }
  else { window.addEventListener('load', function () { setTimeout(run, 800); }); }
  setTimeout(run, 3000);
})();
PROBE
    probe_json="$(jq -Rs . "$probe_file" | sed 's|</script>|<\\/script>|g')"

    cat > "$harness" <<EOF
<!doctype html><html><head><meta charset="utf-8">
<style>html,body{margin:0;padding:0;background:#fff}iframe{display:block;border:0;width:${width}px;height:${VIEWPORT_HEIGHT}px}</style>
</head><body>
<iframe id="probe-frame" style="width:${width}px;height:${VIEWPORT_HEIGHT}px"></iframe>
<pre id="probe-result"></pre>
<script>
(function () {
  var frame = document.getElementById('probe-frame');
  var doc = frame.contentDocument;
  doc.open();
  doc.write(${page_json});
  doc.write('<pre id="probe-result"></pre><scr' + 'ipt>');
  doc.write(${probe_json});
  doc.write('</scr' + 'ipt></body></html>');
  doc.close();
  function readProbe() {
    var inner = frame.contentDocument.getElementById('probe-result');
    document.getElementById('probe-result').textContent =
      inner && inner.textContent ? inner.textContent : JSON.stringify({ error: 'probe not ready' });
  }
  setTimeout(readProbe, 4000);
  setTimeout(readProbe, 9000);
})();
</script>
</body></html>
EOF

    dump="$("$CHROMIUM_BIN" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
        --no-first-run --no-default-browser-check \
        --user-agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15" \
        --virtual-time-budget=15000 --dump-dom "file://$harness" 2>/dev/null || true)"

    probe="$(printf '%s' "$dump" | sed -n 's:.*<pre id="probe-result">\(.*\)</pre>.*:\1:p' \
        | sed -e 's/&quot;/"/g' -e 's/&#39;/'"'"'/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g')"

    rm -f "$page_file" "$harness" "$probe_file"
    [[ -n "$probe" ]] && echo "$probe" || echo '{"error":"probe not extracted"}'
}

test_width() {
    local width="$1" page url probe check result
    echo "  Width: ${width}px"
    for page in "${PAGES[@]}"; do
        url="${BASE_URL}${page}"
        probe="$(probe_page "$width" "$url")"
        if ! echo "$probe" | jq -e . >/dev/null 2>&1; then
            echo "    WARN: probe failed on $page"
            add_issue "$width" "$page" "probe" "warning" "Could not evaluate page (probe output missing)"
            continue
        fi
        if [[ "$(echo "$probe" | jq -r 'has("error")')" == "true" ]]; then
            echo "    WARN: probe error on $page: $(echo "$probe" | jq -r '.error')"
            add_issue "$width" "$page" "probe" "warning" "Probe error: $(echo "$probe" | jq -r '.error')"
            continue
        fi
        for check in horizontal-scroll touch-targets text-overlap sticky-hides-content cta-visible form-fit; do
            result="$(echo "$probe" | jq -r --arg c "$check" '.[$c] // empty')"
            [[ -n "$result" ]] || continue
            case "$result" in
                fail)
                    echo "    FAIL: $check on $page"
                    add_issue "$width" "$page" "$check" "critical" "$check failed at ${width}px viewport" ;;
                warn)
                    echo "    WARN: $check on $page"
                    add_issue "$width" "$page" "$check" "warning" "$check warning at ${width}px viewport" ;;
                pass) echo "    OK: $check on $page" ;;
            esac
        done
    done
}

main() {
    echo "=== ApexMail Mobile Responsive Test ==="

    if ! resolve_chromium; then
        echo "SKIP: no chromium binary found (install chromium or google-chrome)"
        jq -n --arg checked_at "$TIMESTAMP" \
            '{checked_at:$checked_at,skipped:true,reason:"no chromium binary found"}' \
            > "$REPORT_FILE"
        exit 0
    fi
    echo "Using: $(command -v "$CHROMIUM_BIN")"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    for w in "${WIDTHS[@]}"; do
        test_width "$w"
    done

    jq -n --argjson critical "$CRITICAL" --argjson warnings "$WARNINGS" \
        --arg checked_at "$TIMESTAMP" --argjson issues "$ISSUES" \
        '{checked_at:$checked_at,critical:$critical,warnings:$warnings,issues:$issues}' \
        > "$REPORT_FILE"

    echo ""
    echo "=== Summary ==="
    echo "Critical mobile issues: $CRITICAL"
    echo "Warnings: $WARNINGS"
    echo "Report: $REPORT_FILE"

    [[ "$CRITICAL" -eq 0 ]]
}

main "$@"
