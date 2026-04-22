import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './src/e2e-auth',
  testMatch: ['registration-verification.spec.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['json', { outputFile: 'reports/auth-flow/results.json' }],
    ['html', { outputFolder: 'reports/auth-flow/html', open: 'never' }],
  ],
  outputDir: 'reports/auth-flow/artifacts',
  use: {
    browserName: 'chromium',
    viewport: { width: 1280, height: 856 },
    colorScheme: 'light',
    locale: 'en-US',
    timezoneId: 'UTC',
    deviceScaleFactor: 1,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});