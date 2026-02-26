import { defineConfig } from 'vitest/config';

/**
 * Vitest Configuration for ApexMail Unit & Integration Testing
 */
export default defineConfig({
    test: {
        // Enable global test APIs
        globals: true,
        
        // Environment
        environment: 'node',
        
        // Test patterns
        include: ['src/**/*.{test,spec}.{ts,tsx}'],
        exclude: ['src/e2e/**', 'src/a11y/**', 'src/visual/**', 'node_modules', 'dist'],
        
        // Coverage configuration
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html', 'lcov'],
            reportsDirectory: 'reports/coverage',
            exclude: [
                'node_modules',
                'dist',
                'src/e2e/**',
                '**/*.d.ts',
                '**/*.config.ts',
            ],
            thresholds: {
                statements: 80,
                branches: 75,
                functions: 80,
                lines: 80,
            },
        },
        
        // Setup files
        setupFiles: ['./src/setup.ts'],
        
        // Reporter
        reporters: ['verbose', 'html', 'json'],
        outputFile: {
            html: 'reports/vitest/index.html',
            json: 'reports/vitest/results.json',
        },
        
        // Timeouts
        testTimeout: 30000,
        hookTimeout: 30000,
        
        // Retry failed tests
        retry: process.env.CI ? 2 : 0,
        
        // Bail on first failure
        bail: 0,
        
        // Pool configuration
        pool: 'threads',
        poolOptions: {
            threads: {
                singleThread: false,
            },
        },
        
        // Watch mode options
        watch: false,
        
        // Type checking
        typecheck: {
            enabled: true,
            checker: 'tsc',
        },
    },
});
