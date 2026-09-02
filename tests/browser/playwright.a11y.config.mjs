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
// the ephemeral-iframe teardown. The engine-specific torture cases stay
// on the chromium-only default config.
export default defineConfig({
  testDir: './specs',
  testMatch: /(a11y|crossbrowser|adversarial-portable|decoy-polymorphism|autofill-evidence|targeted-bot|extensions-adversary|execution-portable)\.spec\.mjs/,
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
