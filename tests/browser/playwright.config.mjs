import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './specs',
  timeout: 120_000,
  retries: 0, // the security-critical lane must not mask
  // concurrency/timing flakes: a flaky challenge-lifecycle test is
  // exactly the race worth finding, not the one to paper over.
  use: { baseURL: 'http://127.0.0.1:8085' },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  webServer: {
    command: 'php -S 127.0.0.1:8085 router.php',
    url: 'http://127.0.0.1:8085/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
