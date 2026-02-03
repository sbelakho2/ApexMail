import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

export default defineConfig({
    testDir: './src',
    testMatch: ['e2e/specs/marketing.spec.ts', 'visual/marketing.visual.spec.ts'],
    timeout: 30000,
    fullyParallel: true,
    reporter: [['list']],
    use: {
        baseURL: process.env.MARKETING_URL || 'http://127.0.0.1:3001',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },
    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],
    // Skip global setup for this lightweight check
    globalSetup: undefined,
    globalTeardown: undefined,
});
