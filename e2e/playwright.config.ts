import { defineConfig } from '@playwright/test';

const webBaseUrl = process.env.E2E_WEB_BASE_URL ?? 'http://127.0.0.1:3000';
const controlPlaneBaseUrl = process.env.E2E_CONTROL_PLANE_BASE_URL ?? 'http://localhost:3000';

export default defineConfig({
  testDir: 'tests/ui',
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [['list']],
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    baseURL: webBaseUrl,
  },
  projects: [
    {
      name: 'web-chromium',
      use: {
        browserName: 'chromium',
        baseURL: webBaseUrl,
      },
    },
    {
      name: 'control-plane-chromium',
      use: {
        browserName: 'chromium',
        baseURL: controlPlaneBaseUrl,
      },
      testMatch: ['**/control-plane*.spec.ts', '**/responsive-and-a11y*.spec.ts', '**/ui-route-coverage*.spec.ts'],
    },
  ],
});
