import { defineConfig } from '@playwright/test';

// The real-Firefox qualification lane: drives the machine's installed
// Firefox stable binary through the Playwright 'firefox' channel
// instead of the bundled engine, and runs the decoy evidence suites
// against it. The lane is the evidence behind the real-Firefox row of
// the autofill-qualification protocol
// (docs/autofill-qualification-protocol.md). The bundled-engine
// coverage stays on playwright.a11y.config.mjs; this lane exists only
// for the physical qualification runs.
export default defineConfig({
  testDir: './specs',
  testMatch: /(autofill-evidence|decoy-polymorphism|targeted-bot)\.spec\.mjs/,
  timeout: 120_000,
  retries: 0,
  use: { baseURL: 'http://127.0.0.1:8089' },
  projects: [
    { name: 'firefox', use: { browserName: 'firefox', channel: 'firefox' } },
  ],
  webServer: {
    command: 'php -d opcache.jit=off -S 127.0.0.1:8089 router.php',
    url: 'http://127.0.0.1:8089/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
