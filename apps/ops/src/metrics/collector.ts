/**
 * @apexmail/ops - Metrics Collector
 * 
 * Collects and queries metrics for SLO monitoring.
 */

import {
    MetricQuery,
    MetricResult,
    MetricTimeSeries,
    MetricDataPoint,
} from '../types.js';
import * as promClient from 'prom-client';

export interface MetricsCollectorConfig {
    prometheusUrl?: string;
    pushGatewayUrl?: string;
    defaultLabels: Record<string, string>;
    collectDefaultMetrics: boolean;
    prefix: string;
}

export class MetricsCollector {
    private config: MetricsCollectorConfig;
    private registry: promClient.Registry;
    private metrics: Map<string, promClient.Metric<string>> = new Map();
    private dataStore: Map<string, MetricDataPoint[]> = new Map(); // In-memory store for queries

    constructor(config: Partial<MetricsCollectorConfig> = {}) {
        this.config = {
            prometheusUrl: process.env.PROMETHEUS_URL,
            pushGatewayUrl: process.env.PUSHGATEWAY_URL,
            defaultLabels: {},
            collectDefaultMetrics: true,
            prefix: 'apexmail_',
            ...config,
        };

        this.registry = new promClient.Registry();
        
        if (this.config.defaultLabels) {
            this.registry.setDefaultLabels(this.config.defaultLabels);
        }

        if (this.config.collectDefaultMetrics) {
            promClient.collectDefaultMetrics({
                register: this.registry,
                prefix: this.config.prefix,
            });
        }

        this.initializeDefaultMetrics();
    }

    /**
     * Initializes default application metrics
     */
    private initializeDefaultMetrics(): void {
        // HTTP request metrics
        this.createHistogram({
            name: 'http_request_duration_seconds',
            help: 'HTTP request duration in seconds',
            labelNames: ['method', 'route', 'status_code'],
            buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
        });

        this.createCounter({
            name: 'http_requests_total',
            help: 'Total number of HTTP requests',
            labelNames: ['method', 'route', 'status_code'],
        });

        // Email metrics
        this.createCounter({
            name: 'emails_sent_total',
            help: 'Total number of emails sent',
            labelNames: ['status', 'provider'],
        });

        this.createHistogram({
            name: 'email_send_duration_seconds',
            help: 'Email send duration in seconds',
            labelNames: ['provider'],
            buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
        });

        this.createGauge({
            name: 'email_queue_size',
            help: 'Current size of the email queue',
            labelNames: ['priority'],
        });

        // Campaign metrics
        this.createCounter({
            name: 'campaigns_created_total',
            help: 'Total number of campaigns created',
            labelNames: ['type'],
        });

        this.createGauge({
            name: 'active_campaigns',
            help: 'Number of currently active campaigns',
        });

        // Contact metrics
        this.createGauge({
            name: 'total_contacts',
            help: 'Total number of contacts',
            labelNames: ['status'],
        });

        this.createCounter({
            name: 'contacts_imported_total',
            help: 'Total number of contacts imported',
        });

        // Database metrics
        this.createHistogram({
            name: 'db_query_duration_seconds',
            help: 'Database query duration in seconds',
            labelNames: ['operation', 'table'],
            buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
        });

        this.createGauge({
            name: 'db_connections_active',
            help: 'Number of active database connections',
        });

        // Cache metrics
        this.createCounter({
            name: 'cache_hits_total',
            help: 'Total number of cache hits',
            labelNames: ['cache'],
        });

        this.createCounter({
            name: 'cache_misses_total',
            help: 'Total number of cache misses',
            labelNames: ['cache'],
        });

        // Queue metrics
        this.createGauge({
            name: 'queue_jobs_waiting',
            help: 'Number of jobs waiting in queue',
            labelNames: ['queue'],
        });

        this.createGauge({
            name: 'queue_jobs_active',
            help: 'Number of jobs actively processing',
            labelNames: ['queue'],
        });

        this.createCounter({
            name: 'queue_jobs_completed_total',
            help: 'Total number of completed jobs',
            labelNames: ['queue', 'status'],
        });

        // Health check metrics
        this.createGauge({
            name: 'health_check_status',
            help: 'Health check status (1 = healthy, 0 = unhealthy)',
            labelNames: ['service', 'check'],
        });

        // SLO metrics
        this.createGauge({
            name: 'slo_current_value',
            help: 'Current SLO value',
            labelNames: ['slo_id', 'service'],
        });

        this.createGauge({
            name: 'slo_error_budget_remaining',
            help: 'Remaining error budget percentage',
            labelNames: ['slo_id', 'service'],
        });

        this.createGauge({
            name: 'slo_burn_rate',
            help: 'Current SLO burn rate',
            labelNames: ['slo_id', 'service', 'window'],
        });
    }

    /**
     * Creates a counter metric
     */
    createCounter(options: {
        name: string;
        help: string;
        labelNames?: string[];
    }): promClient.Counter<string> {
        const name = this.config.prefix + options.name;
        
        if (this.metrics.has(name)) {
            return this.metrics.get(name) as promClient.Counter<string>;
        }

        const counter = new promClient.Counter({
            name,
            help: options.help,
            labelNames: options.labelNames || [],
            registers: [this.registry],
        });

        this.metrics.set(name, counter);
        return counter;
    }

    /**
     * Creates a gauge metric
     */
    createGauge(options: {
        name: string;
        help: string;
        labelNames?: string[];
    }): promClient.Gauge<string> {
        const name = this.config.prefix + options.name;
        
        if (this.metrics.has(name)) {
            return this.metrics.get(name) as promClient.Gauge<string>;
        }

        const gauge = new promClient.Gauge({
            name,
            help: options.help,
            labelNames: options.labelNames || [],
            registers: [this.registry],
        });

        this.metrics.set(name, gauge);
        return gauge;
    }

    /**
     * Creates a histogram metric
     */
    createHistogram(options: {
        name: string;
        help: string;
        labelNames?: string[];
        buckets?: number[];
    }): promClient.Histogram<string> {
        const name = this.config.prefix + options.name;
        
        if (this.metrics.has(name)) {
            return this.metrics.get(name) as promClient.Histogram<string>;
        }

        const histogram = new promClient.Histogram({
            name,
            help: options.help,
            labelNames: options.labelNames || [],
            buckets: options.buckets || promClient.linearBuckets(0, 0.5, 10),
            registers: [this.registry],
        });

        this.metrics.set(name, histogram);
        return histogram;
    }

    /**
     * Creates a summary metric
     */
    createSummary(options: {
        name: string;
        help: string;
        labelNames?: string[];
        percentiles?: number[];
    }): promClient.Summary<string> {
        const name = this.config.prefix + options.name;
        
        if (this.metrics.has(name)) {
            return this.metrics.get(name) as promClient.Summary<string>;
        }

        const summary = new promClient.Summary({
            name,
            help: options.help,
            labelNames: options.labelNames || [],
            percentiles: options.percentiles || [0.5, 0.9, 0.95, 0.99],
            registers: [this.registry],
        });

        this.metrics.set(name, summary);
        return summary;
    }

    /**
     * Increments a counter
     */
    increment(name: string, labels?: Record<string, string>, value: number = 1): void {
        const fullName = this.config.prefix + name;
        const metric = this.metrics.get(fullName) as promClient.Counter<string>;
        
        if (metric) {
            if (labels) {
                metric.inc(labels, value);
            } else {
                metric.inc(value);
            }

            this.recordDataPoint(fullName, value, labels || {});
        }
    }

    /**
     * Sets a gauge value
     */
    setGauge(name: string, value: number, labels?: Record<string, string>): void {
        const fullName = this.config.prefix + name;
        const metric = this.metrics.get(fullName) as promClient.Gauge<string>;
        
        if (metric) {
            if (labels) {
                metric.set(labels, value);
            } else {
                metric.set(value);
            }

            this.recordDataPoint(fullName, value, labels || {});
        }
    }

    /**
     * Observes a histogram/summary value
     */
    observe(name: string, value: number, labels?: Record<string, string>): void {
        const fullName = this.config.prefix + name;
        const metric = this.metrics.get(fullName);
        
        if (metric) {
            if (metric instanceof promClient.Histogram || metric instanceof promClient.Summary) {
                if (labels) {
                    metric.observe(labels, value);
                } else {
                    metric.observe(value);
                }

                this.recordDataPoint(fullName, value, labels || {});
            }
        }
    }

    /**
     * Records a data point for querying
     */
    private recordDataPoint(
        metric: string,
        value: number,
        labels: Record<string, string>
    ): void {
        const key = this.createDataKey(metric, labels);
        
        if (!this.dataStore.has(key)) {
            this.dataStore.set(key, []);
        }

        const dataPoints = this.dataStore.get(key)!;
        dataPoints.push({
            timestamp: new Date(),
            value,
            labels,
        });

        // Keep only last 24 hours of data
        const cutoff = Date.now() - 24 * 60 * 60 * 1000;
        const filtered = dataPoints.filter((dp) => dp.timestamp.getTime() > cutoff);
        this.dataStore.set(key, filtered);
    }

    /**
     * Creates a unique key for data storage
     */
    private createDataKey(metric: string, labels: Record<string, string>): string {
        const sortedLabels = Object.entries(labels)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k}=${v}`)
            .join(',');
        
        return `${metric}{${sortedLabels}}`;
    }

    /**
     * Queries metrics
     */
    async query(query: MetricQuery): Promise<MetricResult> {
        // If Prometheus is configured, query from Prometheus
        if (this.config.prometheusUrl) {
            return this.queryPrometheus(query);
        }

        // Otherwise, query from in-memory store
        return this.queryInMemory(query);
    }

    /**
     * Queries Prometheus
     */
    private async queryPrometheus(query: MetricQuery): Promise<MetricResult> {
        const params = new URLSearchParams({
            query: this.buildPromQuery(query),
            start: Math.floor(query.startTime.getTime() / 1000).toString(),
            end: Math.floor(query.endTime.getTime() / 1000).toString(),
            step: query.step || '60s',
        });

        try {
            const response = await fetch(
                `${this.config.prometheusUrl}/api/v1/query_range?${params}`
            );

            if (!response.ok) {
                throw new Error(`Prometheus query failed: ${response.statusText}`);
            }

            const data = await response.json();
            return this.parsePrometheusResponse(query, data);
        } catch (error) {
            return {
                query,
                series: [],
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }

    /**
     * Builds a PromQL query
     */
    private buildPromQuery(query: MetricQuery): string {
        let promQuery = query.metric;

        if (query.labels && Object.keys(query.labels).length > 0) {
            const labelSelectors = Object.entries(query.labels)
                .map(([k, v]) => `${k}="${v}"`)
                .join(',');
            promQuery = `${query.metric}{${labelSelectors}}`;
        }

        if (query.aggregation) {
            switch (query.aggregation) {
                case 'avg':
                    promQuery = `avg(${promQuery})`;
                    break;
                case 'sum':
                    promQuery = `sum(${promQuery})`;
                    break;
                case 'max':
                    promQuery = `max(${promQuery})`;
                    break;
                case 'min':
                    promQuery = `min(${promQuery})`;
                    break;
                case 'p50':
                    promQuery = `histogram_quantile(0.5, ${promQuery})`;
                    break;
                case 'p90':
                    promQuery = `histogram_quantile(0.9, ${promQuery})`;
                    break;
                case 'p95':
                    promQuery = `histogram_quantile(0.95, ${promQuery})`;
                    break;
                case 'p99':
                    promQuery = `histogram_quantile(0.99, ${promQuery})`;
                    break;
            }
        }

        return promQuery;
    }

    /**
     * Parses Prometheus response
     */
    private parsePrometheusResponse(query: MetricQuery, data: any): MetricResult {
        const series: MetricTimeSeries[] = [];

        if (data.status === 'success' && data.data.result) {
            for (const result of data.data.result) {
                const dataPoints: MetricDataPoint[] = (result.values || []).map(
                    ([timestamp, value]: [number, string]) => ({
                        timestamp: new Date(timestamp * 1000),
                        value: parseFloat(value),
                        labels: result.metric || {},
                    })
                );

                series.push({
                    metric: query.metric,
                    labels: result.metric || {},
                    dataPoints,
                });
            }
        }

        return { query, series };
    }

    /**
     * Queries in-memory store
     */
    private queryInMemory(query: MetricQuery): MetricResult {
        const fullMetric = this.config.prefix + query.metric;
        const series: MetricTimeSeries[] = [];

        for (const [key, dataPoints] of this.dataStore) {
            if (!key.startsWith(fullMetric)) continue;

            // Filter by labels if specified
            if (query.labels) {
                const keyLabels = this.parseKeyLabels(key);
                const matches = Object.entries(query.labels).every(
                    ([k, v]) => keyLabels[k] === v
                );
                if (!matches) continue;
            }

            // Filter by time range
            const filtered = dataPoints.filter(
                (dp) =>
                    dp.timestamp >= query.startTime && dp.timestamp <= query.endTime
            );

            if (filtered.length > 0) {
                series.push({
                    metric: query.metric,
                    labels: filtered[0].labels,
                    dataPoints: filtered,
                });
            }
        }

        return { query, series };
    }

    /**
     * Parses labels from data key
     */
    private parseKeyLabels(key: string): Record<string, string> {
        const match = key.match(/\{(.+)\}/);
        if (!match) return {};

        const labels: Record<string, string> = {};
        match[1].split(',').forEach((pair) => {
            const [k, v] = pair.split('=');
            labels[k] = v;
        });

        return labels;
    }

    /**
     * Returns metrics in Prometheus format
     */
    async getMetrics(): Promise<string> {
        return this.registry.metrics();
    }

    /**
     * Returns registry content type
     */
    getContentType(): string {
        return this.registry.contentType;
    }

    /**
     * Pushes metrics to push gateway
     */
    async push(jobName: string): Promise<void> {
        if (!this.config.pushGatewayUrl) {
            throw new Error('Push gateway URL not configured');
        }

        const metrics = await this.getMetrics();
        
        const response = await fetch(
            `${this.config.pushGatewayUrl}/metrics/job/${jobName}`,
            {
                method: 'POST',
                headers: { 'Content-Type': this.getContentType() },
                body: metrics,
            }
        );

        if (!response.ok) {
            throw new Error(`Failed to push metrics: ${response.statusText}`);
        }
    }

    /**
     * Clears all metrics
     */
    clear(): void {
        this.registry.clear();
        this.metrics.clear();
        this.dataStore.clear();
    }
}

/**
 * Creates a singleton metrics collector
 */
let instance: MetricsCollector | null = null;

export function getMetricsCollector(
    config?: Partial<MetricsCollectorConfig>
): MetricsCollector {
    if (!instance) {
        instance = new MetricsCollector(config);
    }
    return instance;
}

export function resetMetricsCollector(): void {
    if (instance) {
        instance.clear();
    }
    instance = null;
}
