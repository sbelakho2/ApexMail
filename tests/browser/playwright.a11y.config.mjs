import { defineConfig } from '@playwright/test';

// The accessibility acceptance suite runs across Chromium + Firefox + WebKit — the WCAG 2.2 AA evidence set
// (axe/static checks, keyboard-only scenarios, live-region assertions,
// 200% resize, 320px reflow, text spacing, reduced motion, forced colors,
// RTL + long translations). The functional solver/privacy specs stay on
// the chromium-only default config.
export default defineConfig({
  testDir: './specs',
  testMatch: /(a11y|crossbrowser)\.spec\.mjs/,
  timeout: 120_000,
  retries: 1,
  use: { baseURL: 'http://127.0.0.1:8087' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: {
    command: 'php -S 127.0.0.1:8087 router.php',
    url: 'http://127.0.0.1:8087/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
