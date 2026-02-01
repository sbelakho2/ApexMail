/**
 * @apexmail/testing - Chaos Testing Runner
 * 
 * Orchestrates chaos experiments to test system resilience.
 */

import { EventEmitter } from 'events';
import { ChaosExperiment, ExperimentResult, ExperimentType } from './experiments.js';

export interface ChaosConfig {
    baseUrl: string;
    apiUrl: string;
    services: ServiceConfig[];
    duration: number; // ms
    cooldownPeriod: number; // ms between experiments
    metricsEndpoint: string;
    alertWebhook?: string;
    dryRun: boolean;
}

export interface ServiceConfig {
    name: string;
    url: string;
    healthEndpoint: string;
    criticalDependencies: string[];
}

export interface ExperimentSpec {
    type: ExperimentType;
    target: string;
    parameters: Record<string, unknown>;
    assertions: Assertion[];
    rollbackOnFailure: boolean;
}

export interface Assertion {
    metric: string;
    operator: 'lt' | 'gt' | 'eq' | 'lte' | 'gte';
    value: number;
    description: string;
}

export interface ChaosReport {
    runId: string;
    startTime: Date;
    endTime: Date;
    experiments: ExperimentResult[];
    overallStatus: 'passed' | 'failed' | 'partial';
    summary: ReportSummary;
}

export interface ReportSummary {
    totalExperiments: number;
    passed: number;
    failed: number;
    skipped: number;
    criticalFailures: string[];
    recommendations: string[];
}

export class ChaosRunner extends EventEmitter {
    private config: ChaosConfig;
    private experiments: Map<string, ChaosExperiment> = new Map();
    private runId: string = '';
    private _isRunning: boolean = false;
    private abortController: AbortController | null = null;

    constructor(config: ChaosConfig) {
        super();
        this.config = config;
    }

    /**
     * Check if experiments are currently running
     */
    get isRunning(): boolean {
        return this._isRunning;
    }

    /**
     * Set running state
     */
    set isRunning(value: boolean) {
        this._isRunning = value;
    }

    /**
     * Registers an experiment for execution
     */
    registerExperiment(experiment: ChaosExperiment): void {
        this.experiments.set(experiment.id, experiment);
    }

    /**
     * Runs all registered experiments
     */
    async runAll(): Promise<ChaosReport> {
        this.runId = `chaos-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        this._isRunning = true;
        this.abortController = new AbortController();

        const startTime = new Date();
        const results: ExperimentResult[] = [];

        this.emit('run:start', { runId: this.runId, experimentCount: this.experiments.size });

        // Check baseline health before experiments
        const baselineHealth = await this.checkSystemHealth();
        if (!baselineHealth.healthy) {
            this.emit('run:abort', { reason: 'System unhealthy at baseline', health: baselineHealth });
            return this.createReport(startTime, new Date(), results, 'failed');
        }

        for (const [id, experiment] of this.experiments) {
            if (this.abortController.signal.aborted) {
                results.push(this.createSkippedResult(id, 'Run aborted'));
                continue;
            }

            this.emit('experiment:start', { id, name: experiment.name });

            try {
                const result = await this.runExperiment(experiment);
                results.push(result);

                this.emit('experiment:complete', { id, result });

                // Cooldown between experiments
                if (!this.abortController.signal.aborted) {
                    await this.cooldown();
                }

                // Check system health after each experiment
                const postHealth = await this.checkSystemHealth();
                if (!postHealth.healthy) {
                    this.emit('health:degraded', { afterExperiment: id, health: postHealth });
                    
                    // Attempt recovery
                    await this.attemptRecovery(experiment);
                }
            } catch (error) {
                const errorResult = this.createErrorResult(id, error as Error);
                results.push(errorResult);
                this.emit('experiment:error', { id, error });

                if (experiment.spec.rollbackOnFailure) {
                    await this.rollback(experiment);
                }
            }
        }

        const endTime = new Date();
        this._isRunning = false;

        const report = this.createReport(startTime, endTime, results);
        this.emit('run:complete', { report });

        if (this.config.alertWebhook && report.overallStatus === 'failed') {
            await this.sendAlert(report);
        }

        return report;
    }

    /**
     * Runs a specific experiment by ID
     */
    async runExperiment(experiment: ChaosExperiment): Promise<ExperimentResult> {
        const startTime = Date.now();

        // Dry run mode - simulate without actual injection
        if (this.config.dryRun) {
            return {
                id: experiment.id,
                name: experiment.name,
                type: experiment.spec.type,
                status: 'passed',
                duration: 0,
                assertions: experiment.spec.assertions.map(a => ({
                    ...a,
                    actual: a.value,
                    passed: true,
                })),
                metrics: {},
                timestamp: new Date(),
            };
        }

        // Inject fault
        await experiment.inject();

        // Wait for fault duration
        await this.wait(this.config.duration);

        // Collect metrics during fault
        const metrics = await this.collectMetrics(experiment.spec.target);

        // Verify assertions
        const assertionResults = this.verifyAssertions(experiment.spec.assertions, metrics);

        // Remove fault
        await experiment.recover();

        // Verify recovery
        const recoveryVerified = await this.verifyRecovery(experiment.spec.target);

        const duration = Date.now() - startTime;
        const passed = assertionResults.every(a => a.passed) && recoveryVerified;

        return {
            id: experiment.id,
            name: experiment.name,
            type: experiment.spec.type,
            status: passed ? 'passed' : 'failed',
            duration,
            assertions: assertionResults,
            metrics,
            recoveryTime: recoveryVerified ? duration : undefined,
            timestamp: new Date(),
        };
    }

    /**
     * Aborts the current run
     */
    abort(): void {
        if (this.abortController) {
            this.abortController.abort();
            this.emit('run:aborted', { runId: this.runId });
        }
    }

    /**
     * Checks overall system health
     */
    private async checkSystemHealth(): Promise<{ healthy: boolean; services: Record<string, boolean> }> {
        const serviceHealth: Record<string, boolean> = {};

        for (const service of this.config.services) {
            try {
                const response = await fetch(service.healthEndpoint, {
                    signal: AbortSignal.timeout(5000),
                });
                serviceHealth[service.name] = response.ok;
            } catch {
                serviceHealth[service.name] = false;
            }
        }

        const allHealthy = Object.values(serviceHealth).every(Boolean);
        return { healthy: allHealthy, services: serviceHealth };
    }

    /**
     * Collects metrics from target service
     */
    private async collectMetrics(target: string): Promise<Record<string, number>> {
        try {
            const response = await fetch(`${this.config.metricsEndpoint}?target=${target}`);
            return response.json();
        } catch {
            return {};
        }
    }

    /**
     * Verifies assertions against collected metrics
     */
    private verifyAssertions(
        assertions: Assertion[],
        metrics: Record<string, number>
    ): Array<Assertion & { actual: number; passed: boolean }> {
        return assertions.map(assertion => {
            const actual = metrics[assertion.metric] ?? 0;
            let passed = false;

            switch (assertion.operator) {
                case 'lt':
                    passed = actual < assertion.value;
                    break;
                case 'gt':
                    passed = actual > assertion.value;
                    break;
                case 'eq':
                    passed = actual === assertion.value;
                    break;
                case 'lte':
                    passed = actual <= assertion.value;
                    break;
                case 'gte':
                    passed = actual >= assertion.value;
                    break;
            }

            return { ...assertion, actual, passed };
        });
    }

    /**
     * Verifies service has recovered after fault removal
     */
    private async verifyRecovery(target: string): Promise<boolean> {
        const service = this.config.services.find(s => s.name === target);
        if (!service) return true;

        // Retry health check with backoff
        const maxAttempts = 5;
        const baseDelay = 1000;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                const response = await fetch(service.healthEndpoint, {
                    signal: AbortSignal.timeout(5000),
                });
                if (response.ok) return true;
            } catch {
                // Continue retrying
            }

            await this.wait(baseDelay * Math.pow(2, attempt));
        }

        return false;
    }

    /**
     * Attempts to recover a failed service
     */
    private async attemptRecovery(experiment: ChaosExperiment): Promise<void> {
        this.emit('recovery:start', { experiment: experiment.id });

        try {
            await experiment.recover();
            await this.wait(5000); // Wait for recovery

            const health = await this.checkSystemHealth();
            if (!health.healthy) {
                this.emit('recovery:failed', { experiment: experiment.id });
            } else {
                this.emit('recovery:success', { experiment: experiment.id });
            }
        } catch (error) {
            this.emit('recovery:error', { experiment: experiment.id, error });
        }
    }

    /**
     * Rolls back experiment effects
     */
    private async rollback(experiment: ChaosExperiment): Promise<void> {
        this.emit('rollback:start', { experiment: experiment.id });

        try {
            await experiment.recover();
            this.emit('rollback:complete', { experiment: experiment.id });
        } catch (error) {
            this.emit('rollback:error', { experiment: experiment.id, error });
        }
    }

    /**
     * Waits for cooldown period
     */
    private async cooldown(): Promise<void> {
        this.emit('cooldown:start', { duration: this.config.cooldownPeriod });
        await this.wait(this.config.cooldownPeriod);
        this.emit('cooldown:complete');
    }

    /**
     * Sends alert for failed chaos runs
     */
    private async sendAlert(report: ChaosReport): Promise<void> {
        if (!this.config.alertWebhook) return;

        try {
            await fetch(this.config.alertWebhook, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'chaos_test_failed',
                    runId: report.runId,
                    summary: report.summary,
                    timestamp: new Date().toISOString(),
                }),
            });
        } catch (error) {
            this.emit('alert:error', { error });
        }
    }

    /**
     * Creates the final chaos report
     */
    private createReport(
        startTime: Date,
        endTime: Date,
        results: ExperimentResult[],
        forceStatus?: 'passed' | 'failed' | 'partial'
    ): ChaosReport {
        const passed = results.filter(r => r.status === 'passed').length;
        const failed = results.filter(r => r.status === 'failed').length;
        const skipped = results.filter(r => r.status === 'skipped').length;

        const criticalFailures = results
            .filter(r => r.status === 'failed')
            .map(r => `${r.name}: ${r.assertions.filter(a => !a.passed).map(a => a.description).join(', ')}`);

        const recommendations = this.generateRecommendations(results);

        let overallStatus: 'passed' | 'failed' | 'partial';
        if (forceStatus) {
            overallStatus = forceStatus;
        } else if (failed === 0) {
            overallStatus = 'passed';
        } else if (passed === 0) {
            overallStatus = 'failed';
        } else {
            overallStatus = 'partial';
        }

        return {
            runId: this.runId,
            startTime,
            endTime,
            experiments: results,
            overallStatus,
            summary: {
                totalExperiments: results.length,
                passed,
                failed,
                skipped,
                criticalFailures,
                recommendations,
            },
        };
    }

    /**
     * Generates recommendations based on experiment results
     */
    private generateRecommendations(results: ExperimentResult[]): string[] {
        const recommendations: string[] = [];

        for (const result of results) {
            if (result.status === 'failed') {
                const failedAssertions = result.assertions.filter(a => !a.passed);

                for (const assertion of failedAssertions) {
                    if (assertion.metric === 'error_rate' && assertion.actual > assertion.value) {
                        recommendations.push(
                            `Consider implementing circuit breaker pattern for ${result.name}`
                        );
                    }

                    if (assertion.metric === 'latency_p99' && assertion.actual > assertion.value) {
                        recommendations.push(
                            `Review timeout configurations for ${result.name} - latency exceeded threshold`
                        );
                    }

                    if (assertion.metric === 'availability' && assertion.actual < assertion.value) {
                        recommendations.push(
                            `Improve redundancy for ${result.name} - availability dropped below threshold`
                        );
                    }
                }

                if (!result.recoveryTime) {
                    recommendations.push(
                        `Implement automatic recovery mechanism for ${result.name}`
                    );
                }
            }
        }

        return [...new Set(recommendations)]; // Remove duplicates
    }

    /**
     * Creates a skipped experiment result
     */
    private createSkippedResult(id: string, reason: string): ExperimentResult {
        const experiment = this.experiments.get(id)!;
        return {
            id,
            name: experiment.name,
            type: experiment.spec.type,
            status: 'skipped',
            duration: 0,
            assertions: [],
            metrics: {},
            timestamp: new Date(),
            error: reason,
        };
    }

    /**
     * Creates an error experiment result
     */
    private createErrorResult(id: string, error: Error): ExperimentResult {
        const experiment = this.experiments.get(id)!;
        return {
            id,
            name: experiment.name,
            type: experiment.spec.type,
            status: 'failed',
            duration: 0,
            assertions: [],
            metrics: {},
            timestamp: new Date(),
            error: error.message,
        };
    }

    /**
     * Utility function to wait
     */
    private wait(ms: number): Promise<void> {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(resolve, ms);

            if (this.abortController) {
                this.abortController.signal.addEventListener('abort', () => {
                    clearTimeout(timeout);
                    reject(new Error('Aborted'));
                });
            }
        });
    }
}

/**
 * Factory function to create chaos runner with default config
 */
export function createChaosRunner(overrides: Partial<ChaosConfig> = {}): ChaosRunner {
    const defaultConfig: ChaosConfig = {
        baseUrl: process.env.BASE_URL || 'http://localhost:3000',
        apiUrl: process.env.API_URL || 'http://localhost:3001',
        services: [
            {
                name: 'web',
                url: 'http://localhost:3000',
                healthEndpoint: 'http://localhost:3000/api/health',
                criticalDependencies: ['api', 'db'],
            },
            {
                name: 'api',
                url: 'http://localhost:3001',
                healthEndpoint: 'http://localhost:3001/health',
                criticalDependencies: ['db', 'redis'],
            },
            {
                name: 'worker',
                url: 'http://localhost:3002',
                healthEndpoint: 'http://localhost:3002/health',
                criticalDependencies: ['db', 'redis', 'queue'],
            },
        ],
        duration: 30000, // 30 seconds
        cooldownPeriod: 10000, // 10 seconds
        metricsEndpoint: 'http://localhost:9090/api/v1/query',
        dryRun: process.env.CHAOS_DRY_RUN === 'true',
    };

    return new ChaosRunner({ ...defaultConfig, ...overrides });
}
