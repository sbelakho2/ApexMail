import { defineConfig } from '@playwright/test';

// The real-browser qualification lane: drives the machine's installed
// Google Chrome binary through the Playwright 'chrome' channel instead
// of the bundled engine, and runs the decoy evidence suites against
// it. The lane is the evidence behind the real-browser rows of the
// decoy-autofill-compatibility qualification log.
export default defineConfig({
  testDir: './specs',
  testMatch: /(autofill-evidence|decoy-polymorphism|targeted-bot)\.spec\.mjs/,
  timeout: 120_000,
  retries: 0,
  use: { baseURL: 'http://127.0.0.1:8088' },
  projects: [
    { name: 'chrome', use: { browserName: 'chromium', channel: 'chrome' } },
  ],
  webServer: {
    command: 'php -d opcache.jit=off -S 127.0.0.1:8088 router.php',
    url: 'http://127.0.0.1:8088/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
