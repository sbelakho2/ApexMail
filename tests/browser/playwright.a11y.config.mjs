import { defineConfig } from '@playwright/test';

// The cross-engine lane runs eight suites in Chromium + Firefox +
// WebKit: the WCAG 2.2 AA evidence set (axe/static checks, keyboard-only
// scenarios, live-region assertions, 200% resize, 320px reflow, text
// spacing, reduced motion, forced colors, RTL + long translations), the
// cross-browser critical-path smoke suite, the portable adversarial
// subset (decoy lifecycle, BFCache round-trips, abort isolation, form
// serialization, dynamic widgets, autofill compatibility), the
// portable polymorphic-decoy suite (all six rendering strategies driven
// deterministically via the fixture's strategy hint, the offscreen and
// deferred variants included), the portable engine form-assistance
// evidence suite (Firefox-style heuristic fills, WebKit-style
// composition and delayed commits, Chromium-style silent previews, the
// offscreen variant under every fill, and the AT-snapshot exclusion of
// the decoy), the portable targeted-bot adaptation suite (a bot that
// learned the six rendering strategies and the decoy-name grammar: a
// targeted classifier that knows the response and the DOM signatures
// can identify the decoy, yet successful classification never bypasses
// the real Kiwi security boundary, because the proof and the state
// machinery still gate; the suite pins that claim and the server-side
// evidence surface stays identical), and the extension /
// interception-adversary suite (forged, malformed, delayed and
// replayed challenge responses, duplicated and redirected verify
// submissions, DOM-mutating and page-script adversaries — engine-neutral
// by construction, proven portable across all three engines). The
// portable execution-evidence suite (execution-portable.spec.mjs) runs
// the armed ExecutionChallengeV1 lifecycle end to end on every engine:
// six fresh armed solves, token minting, digest and trace shape, and
// the ephemeral-iframe teardown. The execution-CSP suite
// (execution-csp.spec.mjs) drives the same lifecycle under real
// Content-Security-Policy response headers (the documented strict
// profile and an interpreter-blocking policy). The locale-CSP suite
// (locale-csp.spec.mjs) drives the lazy widget-locales.js module under
// the same real headers: the strict files-tier profile permits the
// same-origin SRI-pinned module load, a missing or tampered module
// fails closed into the English fallback, two widgets share one
// request, and destroy or reset during the pending fetch leaves the
// settled language to the current generation only. The destroy-race
// suite (destroy-race.spec.mjs) drives the post-destroy progress-write
// regression on every engine: a SHA-256 challenge at
// the maximum ceiling (?bits=20), destroyed from a MutationObserver the
// instant the first mid-solve progress tick lands (a microtask before
// the next solver chunk, so the destroy provably lands mid-computation),
// then the cancelled generation's chunk loop is allowed to run out and
// the widget is asserted byte-identical to its destroy-time state — no
// data-progress write, no state/label/token mutation, no kiwi:* event.
// The version-6 real-platform suite (execution-v6-portable.spec.mjs)
// qualifies the real-platform execution rung on every engine: fresh
// armed v6 solves whose five platform probes (computed-style geometry,
// mutation delivery order, full event phases, Range/Selection line
// boxes, intersection thresholds) must verify against the server-side
// envelope walker through the fixture.
// The engine-specific
// torture cases stay on the chromium-only default config.
export default defineConfig({
  testDir: './specs',
  testMatch: /(a11y|brand-ui|crossbrowser|adversarial-portable|decoy-polymorphism|autofill-evidence|targeted-bot|extensions-adversary|execution-portable|execution-v6-portable|execution-csp|locale-csp|destroy-race|compat-controls|compat-observer|responsive-text|pentest|pentest-ai|pentest-stealth|pentest-supply|pentest-descriptors)\.spec\.mjs/,
  timeout: 120_000,
  retries: 1,
  use: { baseURL: 'http://127.0.0.1:8087' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: {
    command: 'php -d opcache.jit=off -S 127.0.0.1:8087 router.php',
    url: 'http://127.0.0.1:8087/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
