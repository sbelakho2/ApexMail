import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './src/visual',
  testMatch: ['rust-visual.spec.ts'],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['json', { outputFile: 'reports/rust-visual/results.json' }],
    ['html', { outputFolder: 'reports/rust-visual/html', open: 'never' }],
  ],
  outputDir: 'reports/rust-visual/artifacts',
  snapshotPathTemplate: '{testDir}/__snapshots__/{arg}{ext}',
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