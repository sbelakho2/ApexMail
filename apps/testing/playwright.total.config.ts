import { defineConfig, devices } from '@playwright/test';

const bypassKey = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';

export default defineConfig({
    testDir: './src/e2e-total',
    testMatch: '**/*.spec.ts',
    timeout: 90000,
    fullyParallel: true,
    retries: process.env.CI ? 1 : 0,
    workers: process.env.CI ? 1 : undefined,
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
                SESSION_SECRET: process.env.SESSION_SECRET || 'test-web-session-secret',
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
                CONTROL_PLANE_JWT_SECRET: process.env.CONTROL_PLANE_JWT_SECRET || 'test-control-plane-jwt-secret',
                CONTROL_PLANE_API_KEY: process.env.CONTROL_PLANE_API_KEY || 'test-control-plane-api-key',
            },
        },
    ],
});
