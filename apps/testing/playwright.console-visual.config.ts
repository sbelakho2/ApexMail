import { defineConfig, devices } from '@playwright/test';

const bypassKey = process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key';

export default defineConfig({
    testDir: './src',
    testMatch: ['visual/console-control.visual.spec.ts'],
    timeout: 60000,
    fullyParallel: true,
    reporter: [['list']],
    expect: {
        toHaveScreenshot: {
            maxDiffPixels: 100,
            threshold: 0.25,
        },
    },
    use: {
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        viewport: { width: 1365, height: 900 },
        ignoreHTTPSErrors: true,
    },
    projects: [
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
            },
        },
    ],
    outputDir: 'reports/visual-console/artifacts',
    webServer: [
        {
            command: 'node ./src/visual/mock-api-server.cjs',
            url: 'http://127.0.0.1:3001/health',
            reuseExistingServer: true,
            timeout: 60000,
            env: {
                ...process.env,
                MOCK_API_PORT: '3001',
            },
        },
        {
            command: 'pnpm --filter @apexmail/web exec next dev -p 3010',
            url: process.env.WEB_URL || 'http://127.0.0.1:3010',
            reuseExistingServer: false,
            timeout: 120000,
            env: {
                ...process.env,
                WEB_URL: process.env.WEB_URL || 'http://127.0.0.1:3010',
                E2E_TEST_MODE: 'true',
                E2E_BYPASS_KEY: bypassKey,
                SESSION_SECRET: process.env.SESSION_SECRET || 'test-web-session-secret',
                API_URL: 'http://127.0.0.1:3001',
            },
        },
        {
            command: 'pnpm --filter @apexmail/control-plane dev',
            url: 'http://localhost:3020',
            reuseExistingServer: false,
            timeout: 120000,
            env: {
                ...process.env,
                CONTROL_PLANE_URL: process.env.CONTROL_PLANE_URL || 'http://localhost:3020',
                E2E_TEST_MODE: 'true',
                E2E_BYPASS_KEY: bypassKey,
                CONTROL_PLANE_JWT_SECRET: process.env.CONTROL_PLANE_JWT_SECRET || 'test-control-plane-jwt-secret',
                CONTROL_PLANE_API_KEY: process.env.CONTROL_PLANE_API_KEY || 'test-control-plane-api-key',
            },
        },
    ],
});
