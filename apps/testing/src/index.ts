/**
 * @apexmail/testing - Main Entry Point
 * 
 * Exports all testing utilities and runners.
 */

// E2E Test Utilities
export * from './e2e/fixtures.js';
export * from './e2e/pages/index.js';

// Chaos Testing
export * from './chaos/index.js';

// Performance Testing
export * from './performance/index.js';

// Types
export interface TestConfig {
    baseUrl: string;
    apiUrl: string;
    timeout: number;
    retries: number;
    workers: number;
}

export interface TestReport {
    type: 'e2e' | 'unit' | 'visual' | 'performance' | 'chaos' | 'a11y';
    timestamp: Date;
    duration: number;
    passed: number;
    failed: number;
    skipped: number;
    results: TestResult[];
}

export interface TestResult {
    name: string;
    status: 'passed' | 'failed' | 'skipped';
    duration: number;
    error?: string;
    retries?: number;
}

/**
 * Creates default test configuration
 */
export function createTestConfig(overrides: Partial<TestConfig> = {}): TestConfig {
    return {
        baseUrl: process.env.BASE_URL || 'http://localhost:3000',
        apiUrl: process.env.API_URL || 'http://localhost:3001',
        timeout: 30000,
        retries: 2,
        workers: 4,
        ...overrides,
    };
}

/**
 * Aggregates test results from multiple sources
 */
export function aggregateResults(reports: TestReport[]): {
    total: { passed: number; failed: number; skipped: number };
    byType: Record<string, { passed: number; failed: number; skipped: number }>;
    duration: number;
} {
    const total = { passed: 0, failed: 0, skipped: 0 };
    const byType: Record<string, { passed: number; failed: number; skipped: number }> = {};
    let duration = 0;

    for (const report of reports) {
        total.passed += report.passed;
        total.failed += report.failed;
        total.skipped += report.skipped;
        duration += report.duration;

        if (!byType[report.type]) {
            byType[report.type] = { passed: 0, failed: 0, skipped: 0 };
        }

        byType[report.type].passed += report.passed;
        byType[report.type].failed += report.failed;
        byType[report.type].skipped += report.skipped;
    }

    return { total, byType, duration };
}

/**
 * Formats test duration
 */
export function formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${Math.floor(ms / 60000)}m ${((ms % 60000) / 1000).toFixed(0)}s`;
}

/**
 * Generates a test summary
 */
export function generateSummary(reports: TestReport[]): string {
    const { total, byType, duration } = aggregateResults(reports);
    
    const lines = [
        '═══════════════════════════════════════════════════════════════',
        '                     TEST SUMMARY                               ',
        '═══════════════════════════════════════════════════════════════',
        '',
        `Total: ${total.passed + total.failed + total.skipped} tests`,
        `  ✓ Passed:  ${total.passed}`,
        `  ✗ Failed:  ${total.failed}`,
        `  ○ Skipped: ${total.skipped}`,
        '',
        `Duration: ${formatDuration(duration)}`,
        '',
        'By Type:',
    ];

    for (const [type, counts] of Object.entries(byType)) {
        const total = counts.passed + counts.failed + counts.skipped;
        const passRate = total > 0 ? ((counts.passed / total) * 100).toFixed(1) : '0.0';
        lines.push(`  ${type.padEnd(12)} ${counts.passed}/${total} (${passRate}%)`);
    }

    lines.push('');
    lines.push('═══════════════════════════════════════════════════════════════');

    return lines.join('\n');
}

// CLI runner helper
export async function runTests(options: {
    type: 'all' | 'e2e' | 'unit' | 'visual' | 'performance' | 'chaos' | 'a11y';
    config?: Partial<TestConfig>;
}): Promise<number> {
    const config = createTestConfig(options.config);
    
    console.log(`Running ${options.type} tests...`);
    console.log(`Base URL: ${config.baseUrl}`);
    console.log(`API URL: ${config.apiUrl}`);
    
    // Return exit code based on test type
    // Actual test execution would be handled by the test frameworks
    return 0;
}
