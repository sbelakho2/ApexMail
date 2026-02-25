import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.test' });

/**
 * Playwright Configuration for ApexMail E2E Testing
 * 
 * Supports multiple projects for different test types:
 * - Desktop browsers (Chrome, Firefox, Safari)
 * - Mobile viewports
 * - Visual regression testing
 * - Accessibility testing
 */
export default defineConfig({
    // Test directory
    testDir: './src/e2e',
    
    // Test file patterns
    testMatch: '**/*.spec.ts',
    
    // Maximum time one test can run
    timeout: 60000,
    
    // Expect timeout
    expect: {
        timeout: 10000,
        toHaveScreenshot: {
            maxDiffPixels: 100,
            threshold: 0.3,
        },
        toMatchSnapshot: {
            threshold: 0.3,
        },
    },
    
    // Run tests in files in parallel
    fullyParallel: true,
    
    // Fail the build on CI if you accidentally left test.only in the source code
    forbidOnly: !!process.env.CI,
    
    // Retry on CI only
    retries: process.env.CI ? 2 : 0,
    
    // Limit workers to prevent dev server overload under parallel load
    workers: process.env.CI ? 1 : 2,
    
    // Reporter to use
    reporter: [
        ['html', { outputFolder: 'reports/html' }],
        ['json', { outputFile: 'reports/results.json' }],
        ['junit', { outputFile: 'reports/junit.xml' }],
        ['list'],
    ],
    
    // Shared settings for all the projects below
    use: {
        // Base URL to use in actions like `await page.goto('/')`
        baseURL: process.env.BASE_URL || 'http://127.0.0.1:3010',
        
        // Collect trace when retrying the failed test
        trace: 'on-first-retry',
        
        // Capture screenshot on failure
        screenshot: 'only-on-failure',
        
        // Record video on failure
        video: 'on-first-retry',
        
        // Set default viewport
        viewport: { width: 1280, height: 720 },
        
        // Emulate timezone
        timezoneId: 'America/New_York',
        
        // Emulate locale
        locale: 'en-US',
        
        // Ignore HTTPS errors
        ignoreHTTPSErrors: true,
        
        // Extra HTTP headers
        extraHTTPHeaders: {
            'Accept-Language': 'en-US',
        },
    },
    
    // Configure projects for major browsers
    projects: [
        // Setup project for authentication
        {
            name: 'setup',
            testMatch: /.*\.setup\.ts/,
        },
        
        // Desktop browsers
        {
            name: 'chromium',
            use: { 
                ...devices['Desktop Chrome'],
            },
            dependencies: ['setup'],
        },
        {
            name: 'firefox',
            use: { 
                ...devices['Desktop Firefox'],
            },
            dependencies: ['setup'],
        },
        {
            name: 'webkit',
            use: { 
                ...devices['Desktop Safari'],
            },
            dependencies: ['setup'],
        },
        
        // Mobile viewports
        {
            name: 'mobile-chrome',
            use: { 
                ...devices['Pixel 5'],
            },
            dependencies: ['setup'],
        },
        {
            name: 'mobile-safari',
            use: { 
                ...devices['iPhone 13'],
            },
            dependencies: ['setup'],
        },
        
        // Tablet viewport
        {
            name: 'tablet',
            use: { 
                ...devices['iPad Pro 11'],
            },
            dependencies: ['setup'],
        },
        
        // Visual regression project
        {
            name: 'visual',
            testDir: './src/visual',
            testMatch: '**/visual.spec.ts',
            use: {
                ...devices['Desktop Chrome'],
            },
            snapshotDir: './snapshots',
            // Retry once on transient connection errors from the dev server
            retries: 1,
        },
        
        // Accessibility project
        {
            name: 'a11y',
            testMatch: '**/*.a11y.ts',
            use: {
                ...devices['Desktop Chrome'],
            },
        },
        
        // Performance project
        {
            name: 'performance',
            testMatch: '**/*.perf.ts',
            use: {
                ...devices['Desktop Chrome'],
                launchOptions: {
                    args: ['--enable-precise-memory-info'],
                },
            },
        },
    ],
    
    // Output folder for test artifacts
    outputDir: 'reports/artifacts',
    
    // Run local dev server before starting the tests
    webServer: process.env.CI ? undefined : [
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
            url: process.env.BASE_URL || 'http://127.0.0.1:3010',
            reuseExistingServer: false,
            timeout: 120000,
            env: {
                ...process.env,
                BASE_URL: process.env.BASE_URL || 'http://127.0.0.1:3010',
                E2E_TEST_MODE: 'true',
                E2E_BYPASS_KEY: process.env.E2E_BYPASS_KEY || 'apexmail-e2e-bypass-key',
                SESSION_SECRET: process.env.SESSION_SECRET || 'test-web-session-secret',
                API_URL: 'http://127.0.0.1:3001',
            },
        },
    ],
    
    // Global setup/teardown
    globalSetup: './src/e2e/global-setup.ts',
    globalTeardown: './src/e2e/global-teardown.ts',
});
