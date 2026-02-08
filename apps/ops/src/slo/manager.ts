/**
 * @apexmail/ops - SLO Manager
 * 
 * Service Level Objective monitoring and error budget tracking.
 */

import {
    ServiceLevelObjective,
    ServiceLevelIndicator,
    SLOStatus,
    SLOBurnRate,
    ErrorBudgetReport,
    ErrorBudgetIncident,
    MetricQuery,
} from '../types.js';
import crypto from 'node:crypto';
import { MetricsCollector } from '../metrics/collector.js';
import { EventEmitter } from 'events';

export interface SLOManagerConfig {
    refreshIntervalMs: number;
    alertOnBurnRate: boolean;
    persistState: boolean;
}

interface SLOState {
    slo: ServiceLevelObjective;
    status: SLOStatus;
    burnRate: SLOBurnRate;
    incidents: ErrorBudgetIncident[];
}

export class SLOManager extends EventEmitter {
    private config: SLOManagerConfig;
    private metricsCollector: MetricsCollector;
    private slos: Map<string, SLOState> = new Map();
    private refreshInterval: NodeJS.Timeout | null = null;

    constructor(metricsCollector: MetricsCollector, config: Partial<SLOManagerConfig> = {}) {
        super();
        this.setMaxListeners(50); // FIX-500-332: Prevent maxListeners warning
        this.metricsCollector = metricsCollector;
        this.config = {
            refreshIntervalMs: 60000, // 1 minute
            alertOnBurnRate: true,
            persistState: true,
            ...config,
        };
    }

    /**
     * Registers an SLO for monitoring
     */
    registerSLO(slo: ServiceLevelObjective): void {
        const state: SLOState = {
            slo,
            status: this.createInitialStatus(slo),
            burnRate: this.createInitialBurnRate(slo.id),
            incidents: [],
        };

        this.slos.set(slo.id, state);
        this.emit('slo:registered', slo);
    }

    /**
     * Unregisters an SLO
     */
    unregisterSLO(sloId: string): void {
        this.slos.delete(sloId);
        this.emit('slo:unregistered', { sloId });
    }

    /**
     * Starts the SLO monitoring loop
     */
    start(): void {
        if (this.refreshInterval) return;

        this.refreshInterval = setInterval(
            () => {
                // Properly handle the async promise to prevent unhandled rejections
                this.refreshAllSLOs().catch((error) => {
                    this.emit('manager:refresh:error', { error });
                });
            },
            this.config.refreshIntervalMs
        );

        // Initial refresh (also handle the promise)
        this.refreshAllSLOs().catch((error) => {
            this.emit('manager:refresh:error', { error });
        });
        this.emit('manager:started');
    }

    /**
     * Stops the SLO monitoring loop
     */
    stop(): void {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
        this.emit('manager:stopped');
    }

    /**
     * Gets the current status of an SLO
     */
    getStatus(sloId: string): SLOStatus | null {
        return this.slos.get(sloId)?.status ?? null;
    }

    /**
     * Gets all SLO statuses
     */
    getAllStatuses(): SLOStatus[] {
        return Array.from(this.slos.values()).map((s) => s.status);
    }

    /**
     * Gets the burn rate for an SLO
     */
    getBurnRate(sloId: string): SLOBurnRate | null {
        return this.slos.get(sloId)?.burnRate ?? null;
    }

    /**
     * Gets the error budget report for an SLO
     */
    getErrorBudgetReport(sloId: string): ErrorBudgetReport | null {
        const state = this.slos.get(sloId);
        if (!state) return null;

        return this.calculateErrorBudgetReport(state);
    }

    /**
     * Records an incident against an SLO's error budget
     */
    recordIncident(sloId: string, incident: Omit<ErrorBudgetIncident, 'id'>): void {
        const state = this.slos.get(sloId);
        if (!state) return;

        const newIncident: ErrorBudgetIncident = {
            ...incident,
            id: `incident-${crypto.randomUUID()}`,
        };

        state.incidents.push(newIncident);
        this.emit('incident:recorded', { sloId, incident: newIncident });
    }

    /**
     * Closes an open incident
     */
    closeIncident(sloId: string, incidentId: string): void {
        const state = this.slos.get(sloId);
        if (!state) return;

        const incident = state.incidents.find((i) => i.id === incidentId);
        if (incident && !incident.endTime) {
            incident.endTime = new Date();
            incident.durationMinutes = Math.round(
                (incident.endTime.getTime() - incident.startTime.getTime()) / 60000
            );
            this.emit('incident:closed', { sloId, incident });
        }
    }

    /**
     * Refreshes all SLO statuses
     */
    private async refreshAllSLOs(): Promise<void> {
        for (const [sloId, state] of this.slos) {
            try {
                await this.refreshSLO(state);
            } catch (error) {
                this.emit('slo:refresh:error', { sloId, error });
            }
        }
    }

    /**
     * Refreshes a single SLO's status
     */
    private async refreshSLO(state: SLOState): Promise<void> {
        const { slo } = state;
        const previousStatus = state.status.status;

        // Calculate current SLI value
        const currentValue = await this.calculateSLI(slo.sli, slo.target.windowDays);

        // Calculate status
        const status = this.calculateStatus(slo, currentValue);
        state.status = status;

        // Calculate burn rates
        const burnRate = await this.calculateBurnRates(slo);
        state.burnRate = burnRate;

        // Check for status changes
        if (status.status !== previousStatus) {
            this.emit('slo:status:changed', {
                sloId: slo.id,
                previous: previousStatus,
                current: status.status,
            });
        }

        // Check for burn rate alerts
        if (this.config.alertOnBurnRate && burnRate.isAlerting) {
            this.emit('slo:burn:alert', {
                sloId: slo.id,
                burnRate,
            });
        }

        this.emit('slo:refreshed', { sloId: slo.id, status, burnRate });
    }

    /**
     * Calculates the current SLI value
     */
    private async calculateSLI(sli: ServiceLevelIndicator, windowDays: number): Promise<number> {
        const endTime = new Date();
        const startTime = new Date(endTime.getTime() - windowDays * 24 * 60 * 60 * 1000);

        const query: MetricQuery = {
            metric: sli.metric,
            startTime,
            endTime,
            aggregation: sli.aggregation,
        };

        const result = await this.metricsCollector.query(query);
        
        if (result.series.length === 0 || result.series[0].dataPoints.length === 0) {
            return 0;
        }

        // Aggregate based on SLI type
        const values = result.series[0].dataPoints.map((dp) => dp.value);
        
        switch (sli.type) {
            case 'availability':
                return this.calculateAvailability(values, sli.goodThreshold);
            case 'latency':
                return this.calculateLatencyPercentile(values, sli.goodThreshold);
            case 'error_rate':
                return this.calculateErrorRate(values);
            default:
                return this.aggregateValues(values, sli.aggregation);
        }
    }

    /**
     * Calculates availability percentage
     */
    private calculateAvailability(values: number[], threshold: number): number {
        if (values.length === 0) return 100;
        const goodCount = values.filter((v) => v >= threshold).length;
        return (goodCount / values.length) * 100;
    }

    /**
     * Calculates latency percentile compliance
     */
    private calculateLatencyPercentile(values: number[], threshold: number): number {
        if (values.length === 0) return 100;
        const goodCount = values.filter((v) => v <= threshold).length;
        return (goodCount / values.length) * 100;
    }

    /**
     * Calculates error rate
     */
    private calculateErrorRate(values: number[]): number {
        if (values.length === 0) return 0;
        return values.reduce((a, b) => a + b, 0) / values.length;
    }

    /**
     * Aggregates values based on aggregation type
     */
    private aggregateValues(
        values: number[],
        aggregation: string
    ): number {
        if (values.length === 0) return 0;

        const sorted = [...values].sort((a, b) => a - b);

        switch (aggregation) {
            case 'avg':
                return values.reduce((a, b) => a + b, 0) / values.length;
            case 'sum':
                return values.reduce((a, b) => a + b, 0);
            case 'count':
                return values.length;
            case 'min':
                return sorted[0];
            case 'max':
                return sorted[sorted.length - 1];
            case 'p50':
                return this.percentile(sorted, 50);
            case 'p90':
                return this.percentile(sorted, 90);
            case 'p95':
                return this.percentile(sorted, 95);
            case 'p99':
                return this.percentile(sorted, 99);
            default:
                return values.reduce((a, b) => a + b, 0) / values.length;
        }
    }

    /**
     * Calculates percentile
     */
    private percentile(sortedValues: number[], p: number): number {
        const index = Math.ceil((p / 100) * sortedValues.length) - 1;
        return sortedValues[Math.max(0, index)];
    }

    /**
     * Calculates the SLO status
     */
    private calculateStatus(slo: ServiceLevelObjective, currentValue: number): SLOStatus {
        const target = slo.target.percentage;
        const errorBudget = 100 - target;
        const errorBudgetConsumed = Math.max(0, target - currentValue);
        const errorBudgetRemaining = Math.max(0, errorBudget - errorBudgetConsumed);

        const windowStart = new Date();
        windowStart.setDate(windowStart.getDate() - slo.target.windowDays);

        let status: 'healthy' | 'warning' | 'critical' | 'exhausted';
        if (errorBudgetRemaining <= 0) {
            status = 'exhausted';
        } else if (errorBudgetRemaining < errorBudget * 0.1) {
            status = 'critical';
        } else if (errorBudgetRemaining < errorBudget * 0.3) {
            status = 'warning';
        } else {
            status = 'healthy';
        }

        const previousStatus = this.slos.get(slo.id)?.status;
        let trend: 'improving' | 'degrading' | 'stable' = 'stable';
        if (previousStatus) {
            if (currentValue > previousStatus.current) trend = 'improving';
            else if (currentValue < previousStatus.current) trend = 'degrading';
        }

        return {
            sloId: slo.id,
            current: currentValue,
            target,
            errorBudgetRemaining,
            errorBudgetConsumed,
            status,
            trend,
            lastUpdated: new Date(),
            windowStart,
            windowEnd: new Date(),
        };
    }

    /**
     * Calculates burn rates for multi-window alerts
     */
    private async calculateBurnRates(slo: ServiceLevelObjective): Promise<SLOBurnRate> {
        const shortWindowMinutes = 5;
        const longWindowMinutes = 60;

        const shortRate = await this.calculateBurnRateForWindow(slo, shortWindowMinutes);
        const longRate = await this.calculateBurnRateForWindow(slo, longWindowMinutes);

        // Determine if alerting based on configured thresholds
        let isAlerting = false;
        let severity: 'critical' | 'warning' | 'info' | 'none' = 'none';

        for (const threshold of slo.alerting.burnRateThresholds) {
            const rate = threshold.windowMinutes <= shortWindowMinutes ? shortRate : longRate;
            if (rate >= threshold.burnRate) {
                isAlerting = true;
                if (
                    severity === 'none' ||
                    this.severityPriority(threshold.severity) > this.severityPriority(severity)
                ) {
                    severity = threshold.severity;
                }
            }
        }

        return {
            sloId: slo.id,
            shortWindow: { minutes: shortWindowMinutes, rate: shortRate },
            longWindow: { minutes: longWindowMinutes, rate: longRate },
            isAlerting,
            severity,
        };
    }

    /**
     * Calculates burn rate for a specific window
     */
    private async calculateBurnRateForWindow(
        slo: ServiceLevelObjective,
        windowMinutes: number
    ): Promise<number> {
        const endTime = new Date();
        const startTime = new Date(endTime.getTime() - windowMinutes * 60 * 1000);

        const query: MetricQuery = {
            metric: slo.sli.metric,
            startTime,
            endTime,
            aggregation: slo.sli.aggregation,
        };

        const result = await this.metricsCollector.query(query);
        
        if (result.series.length === 0 || result.series[0].dataPoints.length === 0) {
            return 0;
        }

        const values = result.series[0].dataPoints.map((dp) => dp.value);
        const currentValue = this.aggregateValues(values, slo.sli.aggregation);

        // Burn rate = (error rate in window) / (allowed error rate)
        const allowedErrorRate = (100 - slo.target.percentage) / 100;
        const actualErrorRate = (100 - currentValue) / 100;

        return allowedErrorRate > 0 ? actualErrorRate / allowedErrorRate : 0;
    }

    /**
     * Returns severity priority for comparison
     */
    private severityPriority(severity: 'critical' | 'warning' | 'info' | 'none'): number {
        switch (severity) {
            case 'critical':
                return 3;
            case 'warning':
                return 2;
            case 'info':
                return 1;
            default:
                return 0;
        }
    }

    /**
     * Calculates error budget report
     */
    private calculateErrorBudgetReport(state: SLOState): ErrorBudgetReport {
        const { slo, status, incidents } = state;
        const windowMs = slo.target.windowDays * 24 * 60 * 60 * 1000;
        const errorBudgetPercentage = 100 - slo.target.percentage;

        const totalBudgetMinutes = (windowMs / 60000) * (errorBudgetPercentage / 100);
        const consumedMinutes = totalBudgetMinutes * (status.errorBudgetConsumed / errorBudgetPercentage);
        const remainingMinutes = totalBudgetMinutes - consumedMinutes;

        // Calculate consumption rate (minutes consumed per day)
        const daysElapsed = Math.max(1, slo.target.windowDays - 
            (status.windowEnd.getTime() - status.windowStart.getTime()) / (24 * 60 * 60 * 1000));
        const consumptionRate = consumedMinutes / daysElapsed;

        // Project exhaustion date
        let projectedExhaustionDate: Date | null = null;
        if (consumptionRate > 0 && remainingMinutes > 0) {
            const daysUntilExhaustion = remainingMinutes / consumptionRate;
            projectedExhaustionDate = new Date();
            projectedExhaustionDate.setDate(projectedExhaustionDate.getDate() + daysUntilExhaustion);
        }

        return {
            sloId: slo.id,
            period: { start: status.windowStart, end: status.windowEnd },
            totalBudgetMinutes,
            consumedMinutes,
            remainingMinutes,
            consumptionRate,
            projectedExhaustionDate,
            incidents,
        };
    }

    /**
     * Creates initial SLO status
     */
    private createInitialStatus(slo: ServiceLevelObjective): SLOStatus {
        const windowStart = new Date();
        windowStart.setDate(windowStart.getDate() - slo.target.windowDays);

        return {
            sloId: slo.id,
            current: slo.target.percentage,
            target: slo.target.percentage,
            errorBudgetRemaining: 100 - slo.target.percentage,
            errorBudgetConsumed: 0,
            status: 'healthy',
            trend: 'stable',
            lastUpdated: new Date(),
            windowStart,
            windowEnd: new Date(),
        };
    }

    /**
     * Creates initial burn rate
     */
    private createInitialBurnRate(sloId: string): SLOBurnRate {
        return {
            sloId,
            shortWindow: { minutes: 5, rate: 0 },
            longWindow: { minutes: 60, rate: 0 },
            isAlerting: false,
            severity: 'none',
        };
    }
}

/**
 * Creates default ApexMail SLO definitions
 */
export function createDefaultSLOs(): ServiceLevelObjective[] {
    return [
        {
            id: 'api-availability',
            name: 'API Availability',
            description: 'The API should be available 99.9% of the time',
            service: 'api',
            sli: {
                id: 'api-availability-sli',
                name: 'API Availability SLI',
                description: 'Percentage of successful health checks',
                type: 'availability',
                metric: 'api_health_check_success_rate',
                goodThreshold: 1,
                unit: 'ratio',
                aggregation: 'avg',
            },
            target: { percentage: 99.9, windowDays: 30 },
            errorBudget: 0.1,
            alerting: {
                burnRateThresholds: [
                    { windowMinutes: 5, burnRate: 14.4, severity: 'critical' },
                    { windowMinutes: 60, burnRate: 6, severity: 'warning' },
                ],
                notificationChannels: ['slack-ops', 'pagerduty'],
                silenceDurationMinutes: 30,
            },
            metadata: { team: 'platform', oncall: 'platform-oncall' },
        },
        {
            id: 'api-latency-p99',
            name: 'API Latency P99',
            description: '99th percentile API latency should be under 500ms',
            service: 'api',
            sli: {
                id: 'api-latency-sli',
                name: 'API Latency SLI',
                description: 'Percentage of requests under 500ms',
                type: 'latency',
                metric: 'api_request_duration_ms',
                goodThreshold: 500,
                unit: 'ms',
                aggregation: 'p99',
            },
            target: { percentage: 99, windowDays: 30 },
            errorBudget: 1,
            alerting: {
                burnRateThresholds: [
                    { windowMinutes: 5, burnRate: 14.4, severity: 'critical' },
                    { windowMinutes: 60, burnRate: 6, severity: 'warning' },
                ],
                notificationChannels: ['slack-ops'],
                silenceDurationMinutes: 15,
            },
            metadata: { team: 'platform' },
        },
        {
            id: 'email-delivery-rate',
            name: 'Email Delivery Rate',
            description: 'Emails should be delivered successfully 99.5% of the time',
            service: 'email-sender',
            sli: {
                id: 'email-delivery-sli',
                name: 'Email Delivery SLI',
                description: 'Percentage of emails delivered successfully',
                type: 'availability',
                metric: 'email_delivery_success_rate',
                goodThreshold: 1,
                unit: 'ratio',
                aggregation: 'avg',
            },
            target: { percentage: 99.5, windowDays: 30 },
            errorBudget: 0.5,
            alerting: {
                burnRateThresholds: [
                    { windowMinutes: 15, burnRate: 10, severity: 'critical' },
                    { windowMinutes: 60, burnRate: 5, severity: 'warning' },
                ],
                notificationChannels: ['slack-email', 'pagerduty'],
                silenceDurationMinutes: 30,
            },
            metadata: { team: 'email', oncall: 'email-oncall' },
        },
        {
            id: 'email-processing-latency',
            name: 'Email Processing Latency',
            description: 'Emails should be processed within 30 seconds',
            service: 'email-worker',
            sli: {
                id: 'email-processing-sli',
                name: 'Email Processing SLI',
                description: 'Percentage of emails processed within 30s',
                type: 'latency',
                metric: 'email_processing_duration_seconds',
                goodThreshold: 30,
                unit: 's',
                aggregation: 'p95',
            },
            target: { percentage: 99, windowDays: 30 },
            errorBudget: 1,
            alerting: {
                burnRateThresholds: [
                    { windowMinutes: 15, burnRate: 14.4, severity: 'critical' },
                    { windowMinutes: 60, burnRate: 6, severity: 'warning' },
                ],
                notificationChannels: ['slack-email'],
                silenceDurationMinutes: 15,
            },
            metadata: { team: 'email' },
        },
        {
            id: 'web-availability',
            name: 'Web Application Availability',
            description: 'The web application should be available 99.9% of the time',
            service: 'web',
            sli: {
                id: 'web-availability-sli',
                name: 'Web Availability SLI',
                description: 'Percentage of successful page loads',
                type: 'availability',
                metric: 'web_page_load_success_rate',
                goodThreshold: 1,
                unit: 'ratio',
                aggregation: 'avg',
            },
            target: { percentage: 99.9, windowDays: 30 },
            errorBudget: 0.1,
            alerting: {
                burnRateThresholds: [
                    { windowMinutes: 5, burnRate: 14.4, severity: 'critical' },
                    { windowMinutes: 60, burnRate: 6, severity: 'warning' },
                ],
                notificationChannels: ['slack-ops', 'pagerduty'],
                silenceDurationMinutes: 30,
            },
            metadata: { team: 'frontend', oncall: 'frontend-oncall' },
        },
    ];
}
