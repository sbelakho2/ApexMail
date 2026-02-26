import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

export default defineConfig({
    testDir: './src',
    testMatch: ['e2e/specs/marketing*.spec.ts', 'visual/marketing*.visual.spec.ts'],
    timeout: 30000,
    fullyParallel: true,
    retries: process.env.CI ? 1 : 0,
    workers: process.env.CI ? 2 : undefined,
    reporter: [['list']],
    use: {
        baseURL: process.env.MARKETING_URL || 'http://127.0.0.1:3003',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
        {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
        },
    ],
    // Skip global setup for this lightweight check
    globalSetup: undefined,
    globalTeardown: undefined,
    webServer: {
        command: 'pnpm --filter @apexmail/marketing exec next dev -p 3003',
        url: 'http://localhost:3003',
        reuseExistingServer: false,
        timeout: 120000,
    },
});
