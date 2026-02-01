/**
 * @apexmail/testing - Performance Test Runner
 * 
 * Comprehensive performance testing framework using Lighthouse and custom metrics.
 */

import { chromium, Browser, Page, BrowserContext } from '@playwright/test';

export interface PerformanceConfig {
    baseUrl: string;
    pages: PageConfig[];
    thresholds: PerformanceThresholds;
    iterations: number;
    warmupIterations: number;
    networkConditions?: NetworkCondition;
    cpuThrottling?: number;
    outputDir: string;
}

export interface PageConfig {
    name: string;
    path: string;
    waitFor?: string;
    interactions?: Interaction[];
    expectedMetrics?: Partial<PerformanceMetrics>;
}

export interface Interaction {
    type: 'click' | 'type' | 'scroll' | 'navigate' | 'wait';
    selector?: string;
    value?: string;
    duration?: number;
}

export interface PerformanceThresholds {
    lcp: number; // Largest Contentful Paint in ms
    fid: number; // First Input Delay in ms
    cls: number; // Cumulative Layout Shift score
    ttfb: number; // Time to First Byte in ms
    fcp: number; // First Contentful Paint in ms
    tti: number; // Time to Interactive in ms
    tbt: number; // Total Blocking Time in ms
    speedIndex: number; // Speed Index in ms
}

export interface NetworkCondition {
    offline: boolean;
    downloadThroughput: number; // bytes per second
    uploadThroughput: number;
    latency: number; // ms
}

export interface PerformanceMetrics {
    lcp: number;
    fid: number;
    cls: number;
    ttfb: number;
    fcp: number;
    tti: number;
    tbt: number;
    speedIndex: number;
    domContentLoaded: number;
    load: number;
    resourceCount: number;
    resourceSize: number;
    jsHeapSize: number;
    domNodes: number;
}

export interface PerformanceResult {
    page: string;
    path: string;
    metrics: PerformanceMetrics;
    passed: boolean;
    failures: string[];
    timestamp: Date;
    iterations: number;
    variance: Partial<PerformanceMetrics>;
}

export interface PerformanceReport {
    runId: string;
    config: PerformanceConfig;
    results: PerformanceResult[];
    summary: PerformanceSummary;
    timestamp: Date;
}

export interface PerformanceSummary {
    totalPages: number;
    passed: number;
    failed: number;
    averageScore: number;
    criticalIssues: string[];
    recommendations: string[];
}

const networkPresets: Record<string, NetworkCondition> = {
    '4g': { offline: false, downloadThroughput: 4 * 1024 * 1024 / 8, uploadThroughput: 3 * 1024 * 1024 / 8, latency: 20 },
    '3g': { offline: false, downloadThroughput: 1.5 * 1024 * 1024 / 8, uploadThroughput: 750 * 1024 / 8, latency: 100 },
    '3gSlow': { offline: false, downloadThroughput: 500 * 1024 / 8, uploadThroughput: 500 * 1024 / 8, latency: 400 },
    '2g': { offline: false, downloadThroughput: 450 * 1024 / 8, uploadThroughput: 150 * 1024 / 8, latency: 600 },
};

export class PerformanceRunner {
    private config: PerformanceConfig;
    private browser: Browser | null = null;

    constructor(config: PerformanceConfig) {
        this.config = config;
    }

    /**
     * Runs performance tests on all configured pages
     */
    async run(): Promise<PerformanceReport> {
        const runId = `perf-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const results: PerformanceResult[] = [];

        this.browser = await chromium.launch({ headless: true });

        try {
            for (const pageConfig of this.config.pages) {
                const result = await this.testPage(pageConfig);
                results.push(result);
            }
        } finally {
            await this.browser.close();
        }

        const report = this.createReport(runId, results);
        await this.saveReport(report);

        return report;
    }

    /**
     * Tests a single page configuration
     */
    private async testPage(pageConfig: PageConfig): Promise<PerformanceResult> {
        const allMetrics: PerformanceMetrics[] = [];

        // Warmup iterations
        for (let i = 0; i < this.config.warmupIterations; i++) {
            await this.collectMetrics(pageConfig);
        }

        // Actual test iterations
        for (let i = 0; i < this.config.iterations; i++) {
            const metrics = await this.collectMetrics(pageConfig);
            allMetrics.push(metrics);
        }

        const averageMetrics = this.calculateAverageMetrics(allMetrics);
        const variance = this.calculateVariance(allMetrics, averageMetrics);
        const failures = this.checkThresholds(averageMetrics, pageConfig.expectedMetrics);

        return {
            page: pageConfig.name,
            path: pageConfig.path,
            metrics: averageMetrics,
            passed: failures.length === 0,
            failures,
            timestamp: new Date(),
            iterations: this.config.iterations,
            variance,
        };
    }

    /**
     * Collects performance metrics for a page
     */
    private async collectMetrics(pageConfig: PageConfig): Promise<PerformanceMetrics> {
        const context = await this.createContext();
        const page = await context.newPage();

        try {
            // Apply network conditions
            if (this.config.networkConditions) {
                const cdp = await context.newCDPSession(page);
                await cdp.send('Network.emulateNetworkConditions', {
                    offline: this.config.networkConditions.offline,
                    downloadThroughput: this.config.networkConditions.downloadThroughput,
                    uploadThroughput: this.config.networkConditions.uploadThroughput,
                    latency: this.config.networkConditions.latency,
                });

                if (this.config.cpuThrottling) {
                    await cdp.send('Emulation.setCPUThrottlingRate', {
                        rate: this.config.cpuThrottling,
                    });
                }
            }

            // Navigate and wait
            const url = `${this.config.baseUrl}${pageConfig.path}`;
            const startTime = Date.now();

            const response = await page.goto(url, { waitUntil: 'load' });
            
            if (pageConfig.waitFor) {
                await page.waitForSelector(pageConfig.waitFor);
            }

            // Execute interactions
            if (pageConfig.interactions) {
                for (const interaction of pageConfig.interactions) {
                    await this.executeInteraction(page, interaction);
                }
            }

            // Collect Web Vitals
            const webVitals = await this.collectWebVitals(page);

            // Collect resource metrics
            const resourceMetrics = await this.collectResourceMetrics(page);

            // Collect memory metrics
            const memoryMetrics = await this.collectMemoryMetrics(page);

            // Collect timing metrics
            const timingMetrics = await this.collectTimingMetrics(page);

            return {
                ...webVitals,
                ...resourceMetrics,
                ...memoryMetrics,
                ...timingMetrics,
            };
        } finally {
            await page.close();
            await context.close();
        }
    }

    /**
     * Creates a browser context with performance settings
     */
    private async createContext(): Promise<BrowserContext> {
        return this.browser!.newContext({
            viewport: { width: 1920, height: 1080 },
            deviceScaleFactor: 1,
            isMobile: false,
            hasTouch: false,
            javaScriptEnabled: true,
        });
    }

    /**
     * Executes a user interaction
     */
    private async executeInteraction(page: Page, interaction: Interaction): Promise<void> {
        switch (interaction.type) {
            case 'click':
                if (interaction.selector) {
                    await page.click(interaction.selector);
                }
                break;
            case 'type':
                if (interaction.selector && interaction.value) {
                    await page.fill(interaction.selector, interaction.value);
                }
                break;
            case 'scroll':
                await page.evaluate((distance) => {
                    window.scrollBy(0, distance);
                }, interaction.duration || 500);
                break;
            case 'navigate':
                if (interaction.value) {
                    await page.goto(interaction.value);
                }
                break;
            case 'wait':
                await page.waitForTimeout(interaction.duration || 1000);
                break;
        }
    }

    /**
     * Collects Core Web Vitals
     */
    private async collectWebVitals(page: Page): Promise<Partial<PerformanceMetrics>> {
        return page.evaluate(() => {
            return new Promise<Partial<PerformanceMetrics>>((resolve) => {
                const metrics: Partial<PerformanceMetrics> = {
                    lcp: 0,
                    fid: 0,
                    cls: 0,
                    fcp: 0,
                    ttfb: 0,
                };

                // Get LCP
                new PerformanceObserver((entryList) => {
                    const entries = entryList.getEntries();
                    const lastEntry = entries[entries.length - 1] as any;
                    metrics.lcp = lastEntry?.startTime || 0;
                }).observe({ type: 'largest-contentful-paint', buffered: true });

                // Get FCP
                new PerformanceObserver((entryList) => {
                    const entries = entryList.getEntries();
                    const fcpEntry = entries.find((e) => e.name === 'first-contentful-paint');
                    metrics.fcp = fcpEntry?.startTime || 0;
                }).observe({ type: 'paint', buffered: true });

                // Get CLS
                let clsValue = 0;
                new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries() as any[]) {
                        if (!entry.hadRecentInput) {
                            clsValue += entry.value;
                        }
                    }
                    metrics.cls = clsValue;
                }).observe({ type: 'layout-shift', buffered: true });

                // Get TTFB from navigation timing
                const navEntry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
                if (navEntry) {
                    metrics.ttfb = navEntry.responseStart - navEntry.requestStart;
                }

                // Wait for metrics to be collected
                setTimeout(() => resolve(metrics), 3000);
            });
        });
    }

    /**
     * Collects resource metrics
     */
    private async collectResourceMetrics(page: Page): Promise<Partial<PerformanceMetrics>> {
        return page.evaluate(() => {
            const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
            const totalSize = resources.reduce((sum, r) => sum + (r.transferSize || 0), 0);

            return {
                resourceCount: resources.length,
                resourceSize: totalSize,
            };
        });
    }

    /**
     * Collects memory metrics
     */
    private async collectMemoryMetrics(page: Page): Promise<Partial<PerformanceMetrics>> {
        return page.evaluate(() => {
            const memory = (performance as any).memory;
            const domNodes = document.querySelectorAll('*').length;

            return {
                jsHeapSize: memory?.usedJSHeapSize || 0,
                domNodes,
            };
        });
    }

    /**
     * Collects timing metrics
     */
    private async collectTimingMetrics(page: Page): Promise<Partial<PerformanceMetrics>> {
        return page.evaluate(() => {
            const navEntry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;

            return {
                domContentLoaded: navEntry?.domContentLoadedEventEnd || 0,
                load: navEntry?.loadEventEnd || 0,
                tti: 0, // TTI requires more complex calculation
                tbt: 0, // TBT requires Long Tasks observation
                speedIndex: 0, // Speed Index requires frame-by-frame analysis
            };
        });
    }

    /**
     * Calculates average metrics across iterations
     */
    private calculateAverageMetrics(allMetrics: PerformanceMetrics[]): PerformanceMetrics {
        const sum: PerformanceMetrics = {
            lcp: 0, fid: 0, cls: 0, ttfb: 0, fcp: 0, tti: 0, tbt: 0,
            speedIndex: 0, domContentLoaded: 0, load: 0, resourceCount: 0,
            resourceSize: 0, jsHeapSize: 0, domNodes: 0,
        };

        for (const metrics of allMetrics) {
            for (const key of Object.keys(sum) as (keyof PerformanceMetrics)[]) {
                sum[key] += metrics[key] || 0;
            }
        }

        const avg: PerformanceMetrics = { ...sum };
        for (const key of Object.keys(avg) as (keyof PerformanceMetrics)[]) {
            avg[key] = Math.round(avg[key] / allMetrics.length);
        }

        return avg;
    }

    /**
     * Calculates variance in metrics
     */
    private calculateVariance(
        allMetrics: PerformanceMetrics[],
        average: PerformanceMetrics
    ): Partial<PerformanceMetrics> {
        const variance: Partial<PerformanceMetrics> = {};

        for (const key of ['lcp', 'fcp', 'ttfb'] as (keyof PerformanceMetrics)[]) {
            const values = allMetrics.map((m) => m[key] as number);
            const mean = average[key] as number;
            const squaredDiffs = values.map((v) => Math.pow(v - mean, 2));
            const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
            (variance as any)[key] = Math.round(Math.sqrt(avgSquaredDiff));
        }

        return variance;
    }

    /**
     * Checks metrics against thresholds
     */
    private checkThresholds(
        metrics: PerformanceMetrics,
        expectedMetrics?: Partial<PerformanceMetrics>
    ): string[] {
        const failures: string[] = [];
        const thresholds = { ...this.config.thresholds, ...expectedMetrics };

        if (metrics.lcp > thresholds.lcp) {
            failures.push(`LCP ${metrics.lcp}ms exceeds threshold of ${thresholds.lcp}ms`);
        }

        if (metrics.fid > thresholds.fid) {
            failures.push(`FID ${metrics.fid}ms exceeds threshold of ${thresholds.fid}ms`);
        }

        if (metrics.cls > thresholds.cls) {
            failures.push(`CLS ${metrics.cls} exceeds threshold of ${thresholds.cls}`);
        }

        if (metrics.ttfb > thresholds.ttfb) {
            failures.push(`TTFB ${metrics.ttfb}ms exceeds threshold of ${thresholds.ttfb}ms`);
        }

        if (metrics.fcp > thresholds.fcp) {
            failures.push(`FCP ${metrics.fcp}ms exceeds threshold of ${thresholds.fcp}ms`);
        }

        return failures;
    }

    /**
     * Creates the final performance report
     */
    private createReport(runId: string, results: PerformanceResult[]): PerformanceReport {
        const passed = results.filter((r) => r.passed).length;
        const failed = results.filter((r) => !r.passed).length;

        const criticalIssues = results
            .filter((r) => !r.passed)
            .flatMap((r) => r.failures.map((f) => `${r.page}: ${f}`));

        const recommendations = this.generateRecommendations(results);

        const avgScore = this.calculateOverallScore(results);

        return {
            runId,
            config: this.config,
            results,
            summary: {
                totalPages: results.length,
                passed,
                failed,
                averageScore: avgScore,
                criticalIssues,
                recommendations,
            },
            timestamp: new Date(),
        };
    }

    /**
     * Calculates an overall performance score
     */
    private calculateOverallScore(results: PerformanceResult[]): number {
        let totalScore = 0;

        for (const result of results) {
            let pageScore = 100;

            // Deduct points for threshold violations
            const { metrics } = result;
            const { thresholds } = this.config;

            if (metrics.lcp > thresholds.lcp) {
                pageScore -= Math.min(25, ((metrics.lcp - thresholds.lcp) / thresholds.lcp) * 25);
            }

            if (metrics.fcp > thresholds.fcp) {
                pageScore -= Math.min(15, ((metrics.fcp - thresholds.fcp) / thresholds.fcp) * 15);
            }

            if (metrics.cls > thresholds.cls) {
                pageScore -= Math.min(20, ((metrics.cls - thresholds.cls) / thresholds.cls) * 20);
            }

            if (metrics.ttfb > thresholds.ttfb) {
                pageScore -= Math.min(10, ((metrics.ttfb - thresholds.ttfb) / thresholds.ttfb) * 10);
            }

            totalScore += Math.max(0, pageScore);
        }

        return Math.round(totalScore / results.length);
    }

    /**
     * Generates performance improvement recommendations
     */
    private generateRecommendations(results: PerformanceResult[]): string[] {
        const recommendations: string[] = [];

        for (const result of results) {
            const { metrics, page } = result;

            if (metrics.lcp > 2500) {
                recommendations.push(
                    `${page}: Consider optimizing LCP element - preload critical resources, use CDN`
                );
            }

            if (metrics.cls > 0.1) {
                recommendations.push(
                    `${page}: High CLS detected - add size attributes to images/embeds, avoid inserting content above existing content`
                );
            }

            if (metrics.resourceCount > 100) {
                recommendations.push(
                    `${page}: High resource count (${metrics.resourceCount}) - consider bundling or lazy loading`
                );
            }

            if (metrics.resourceSize > 5 * 1024 * 1024) {
                recommendations.push(
                    `${page}: Large page weight (${Math.round(metrics.resourceSize / 1024 / 1024)}MB) - compress assets, optimize images`
                );
            }

            if (metrics.domNodes > 1500) {
                recommendations.push(
                    `${page}: Large DOM size (${metrics.domNodes} nodes) - consider virtualization for lists`
                );
            }

            if (metrics.ttfb > 600) {
                recommendations.push(
                    `${page}: High TTFB - optimize server response time, use caching`
                );
            }
        }

        return [...new Set(recommendations)];
    }

    /**
     * Saves the report to disk
     */
    private async saveReport(report: PerformanceReport): Promise<void> {
        const fs = await import('fs/promises');
        const path = await import('path');

        const outputPath = path.join(this.config.outputDir, `perf-${report.runId}.json`);
        await fs.mkdir(this.config.outputDir, { recursive: true });
        await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
    }
}

/**
 * Creates default performance configuration
 */
export function createPerformanceConfig(overrides: Partial<PerformanceConfig> = {}): PerformanceConfig {
    return {
        baseUrl: process.env.BASE_URL || 'http://localhost:3000',
        pages: [
            { name: 'Login', path: '/login', waitFor: '[data-testid="login-form"]' },
            { name: 'Dashboard', path: '/dashboard', waitFor: '[data-testid="dashboard"]' },
            { name: 'Campaigns', path: '/campaigns', waitFor: '[data-testid="campaigns-table"]' },
            { name: 'Campaign Editor', path: '/campaigns/new', waitFor: '[data-testid="campaign-editor"]' },
            { name: 'Contacts', path: '/contacts', waitFor: '[data-testid="contacts-table"]' },
            { name: 'Settings', path: '/settings', waitFor: '[data-testid="settings-form"]' },
        ],
        thresholds: {
            lcp: 2500,
            fid: 100,
            cls: 0.1,
            ttfb: 600,
            fcp: 1800,
            tti: 3800,
            tbt: 200,
            speedIndex: 3400,
        },
        iterations: 3,
        warmupIterations: 1,
        networkConditions: networkPresets['4g'],
        cpuThrottling: 4, // 4x slowdown
        outputDir: './test-results/performance',
        ...overrides,
    };
}

export { networkPresets };
