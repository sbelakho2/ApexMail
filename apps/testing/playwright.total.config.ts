import { defineConfig, devices } from '@playwright/test';
import crypto from 'node:crypto';
import os from 'node:os';

const bypassKey = process.env.E2E_BYPASS_KEY ?? crypto.randomUUID();
const sessionSecret = process.env.SESSION_SECRET ?? crypto.randomBytes(32).toString('hex');
const controlPlaneJwtSecret = process.env.CONTROL_PLANE_JWT_SECRET ?? crypto.randomBytes(32).toString('hex');
const controlPlaneApiKey = process.env.CONTROL_PLANE_API_KEY ?? crypto.randomBytes(24).toString('hex');
const ciWorkers = Math.max(2, Math.min(4, os.cpus().length));

process.env.E2E_BYPASS_KEY = bypassKey;
process.env.SESSION_SECRET = sessionSecret;
process.env.CONTROL_PLANE_JWT_SECRET = controlPlaneJwtSecret;
process.env.CONTROL_PLANE_API_KEY = controlPlaneApiKey;

export default defineConfig({
    testDir: './src/e2e-total',
    testMatch: '**/*.spec.ts',
    timeout: 90000,
    fullyParallel: true,
    retries: process.env.CI ? 1 : 0,
    workers: process.env.CI ? ciWorkers : undefined,
    reporter: [
        ['list'],
        ['html', { outputFolder: 'reports/total/html' }],
        ['json', { outputFile: 'reports/total/results.json' }],
    ],
    use: {
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'on-first-retry',
        viewport: { width: 1440, height: 900 },
        ignoreHTTPSErrors: true,
        reducedMotion: 'reduce',
    },
    projects: [
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
            },
        },
        {
            name: 'firefox',
            use: {
                ...devices['Desktop Firefox'],
            },
        },
        {
            name: 'webkit',
            use: {
                ...devices['Desktop Safari'],
            },
        },
    ],
    outputDir: 'reports/total/artifacts',
    webServer: [
        {
            command: 'pnpm --filter @apexmail/web dev',
            url: 'http://localhost:3000',
            reuseExistingServer: true,
            timeout: 120000,
            env: {
                ...process.env,
                E2E_TEST_MODE: 'true',
                E2E_BYPASS_KEY: bypassKey,
                SESSION_SECRET: sessionSecret,
                API_URL: process.env.API_URL || 'http://localhost:3001',
            },
        },
        {
            command: 'pnpm --filter @apexmail/control-plane dev',
            url: 'http://localhost:3020',
            reuseExistingServer: true,
            timeout: 120000,
            env: {
                ...process.env,
                E2E_TEST_MODE: 'true',
                E2E_BYPASS_KEY: bypassKey,
                CONTROL_PLANE_JWT_SECRET: controlPlaneJwtSecret,
                CONTROL_PLANE_API_KEY: controlPlaneApiKey,
            },
        },
    ],
});
