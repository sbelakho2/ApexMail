/**
 * Metrics Service
 * 
 * Prometheus-compatible metrics collection:
 * - Counter, Gauge, Histogram, Summary
 * - Custom business metrics
 * - Aggregation and export
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import * as promClient from 'prom-client';
import { Result, createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'observability:metrics' });

export enum MetricType {
  COUNTER = 'counter',
  GAUGE = 'gauge',
  HISTOGRAM = 'histogram',
  SUMMARY = 'summary',
}

export interface MetricDefinition {
  name: string;
  type: MetricType;
  help: string;
  labelNames?: string[];
  buckets?: number[];
  percentiles?: number[];
}

export interface MetricValue {
  name: string;
  type: MetricType;
  value: number;
  labels: Record<string, string>;
  timestamp: Date;
}

export interface AggregatedMetric {
  name: string;
  type: MetricType;
  help: string;
  values: Array<{
    labels: Record<string, string>;
    value: number;
    timestamp: Date;
  }>;
}

export class MetricsService {
  private db: Pool;
  private redis: Redis;
  private registry: promClient.Registry;
  private metrics: Map<string, promClient.Metric> = new Map();
  private collectInterval: NodeJS.Timeout | null = null;
  private aggregateInterval: NodeJS.Timeout | null = null;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.registry = new promClient.Registry();
  }

  /**
   * Initialize metrics service
   */
  async initialize(): Promise<void> {
    if (!config.metrics.enabled) {
      logger.info('[Metrics] Metrics collection is disabled');
      return;
    }

    // Set default labels
    this.registry.setDefaultLabels(config.metrics.defaultLabels);

    // Collect default Node.js metrics
    promClient.collectDefaultMetrics({ register: this.registry });

    // Register built-in ApexMail metrics
    this.registerBuiltInMetrics();

    // Start collection interval with error handling
    this.collectInterval = setInterval(() => {
      this.collectSystemMetrics().catch(err => {
        logger.error('[Metrics] System metrics collection failed:', { error: err instanceof Error ? err.message : String(err) });
      });
    }, config.metrics.aggregationInterval);

    // Start aggregation interval with error handling
    this.aggregateInterval = setInterval(() => {
      this.aggregateMetrics().catch(err => {
        logger.error('[Metrics] Metrics aggregation failed:', { error: err instanceof Error ? err.message : String(err) });
      });
    }, 60000);

    logger.info('[Metrics] Service initialized');
  }

  /**
   * Register a new metric
   */
  registerMetric(definition: MetricDefinition): Result<void> {
    if (this.metrics.has(definition.name)) {
      return { ok: false, error: new Error(`Metric already exists: ${definition.name}`) };
    }

    let metric: promClient.Metric;

    switch (definition.type) {
      case MetricType.COUNTER:
        metric = new promClient.Counter({
          name: definition.name,
          help: definition.help,
          labelNames: definition.labelNames || [],
          registers: [this.registry],
        });
        break;

      case MetricType.GAUGE:
        metric = new promClient.Gauge({
          name: definition.name,
          help: definition.help,
          labelNames: definition.labelNames || [],
          registers: [this.registry],
        });
        break;

      case MetricType.HISTOGRAM:
        metric = new promClient.Histogram({
          name: definition.name,
          help: definition.help,
          labelNames: definition.labelNames || [],
          buckets: definition.buckets || config.metrics.histogramBuckets,
          registers: [this.registry],
        });
        break;

      case MetricType.SUMMARY:
        metric = new promClient.Summary({
          name: definition.name,
          help: definition.help,
          labelNames: definition.labelNames || [],
          percentiles: definition.percentiles || [0.5, 0.9, 0.95, 0.99],
          registers: [this.registry],
        });
        break;
    }

    this.metrics.set(definition.name, metric);

    return { ok: true, value: undefined };
  }

  /**
   * Increment a counter
   */
  incrementCounter(name: string, value: number = 1, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Counter) {
      if (labels) {
        metric.inc(labels, value);
      } else {
        metric.inc(value);
      }
    }
  }

  /**
   * Set a gauge value
   */
  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Gauge) {
      if (labels) {
        metric.set(labels, value);
      } else {
        metric.set(value);
      }
    }
  }

  /**
   * Increment a gauge
   */
  incrementGauge(name: string, value: number = 1, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Gauge) {
      if (labels) {
        metric.inc(labels, value);
      } else {
        metric.inc(value);
      }
    }
  }

  /**
   * Decrement a gauge
   */
  decrementGauge(name: string, value: number = 1, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Gauge) {
      if (labels) {
        metric.dec(labels, value);
      } else {
        metric.dec(value);
      }
    }
  }

  /**
   * Observe a histogram value
   */
  observeHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Histogram) {
      if (labels) {
        metric.observe(labels, value);
      } else {
        metric.observe(value);
      }
    }
  }

  /**
   * Observe a summary value
   */
  observeSummary(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (metric && metric instanceof promClient.Summary) {
      if (labels) {
        metric.observe(labels, value);
      } else {
        metric.observe(value);
      }
    }
  }

  /**
   * Start a timer (returns a function to stop the timer)
   */
  startTimer(name: string, labels?: Record<string, string>): () => number {
    const metric = this.metrics.get(name);
    if (metric && (metric instanceof promClient.Histogram || metric instanceof promClient.Summary)) {
      if (labels) {
        return metric.startTimer(labels);
      }
      return metric.startTimer();
    }
    return () => 0;
  }

  /**
   * Record a metric value (stores in database for persistence)
   */
  async recordMetric(value: MetricValue): Promise<Result<void>> {
    try {
      await this.db.query(`
        INSERT INTO obs_metrics (name, type, value, labels, recorded_at)
        VALUES ($1, $2, $3, $4, $5)
      `, [value.name, value.type, value.value, JSON.stringify(value.labels), value.timestamp]);

      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * C-092: Record multiple metrics in a single batched INSERT for efficiency.
   * Avoids per-metric round-trips to the database.
   */
  private async recordMetricsBatch(values: MetricValue[]): Promise<Result<void>> {
    if (values.length === 0) return { ok: true, value: undefined };

    try {
      // Build a batched INSERT with parameterized values
      const params: unknown[] = [];
      const placeholders: string[] = [];
      for (let i = 0; i < values.length; i++) {
        const v = values[i]!;
        const offset = i * 5;
        placeholders.push(`($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5})`);
        params.push(
          v.name,
          v.type,
          v.value,
          JSON.stringify(v.labels),
          v.timestamp
        );
      }

      await this.db.query(
        `INSERT INTO obs_metrics (name, type, value, labels, recorded_at) VALUES ${placeholders.join(', ')}`,
        params
      );

      return { ok: true, value: undefined };
    } catch (error) {
      logger.error('[Metrics] Batch insert failed:', { error: error instanceof Error ? error.message : String(error), count: values.length });
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Record HTTP request metrics
   */
  recordHttpRequest(method: string, path: string, statusCode: number, duration: number): void {
    // Record to Prometheus counters/histograms
    const labels = { method, path, status_code: String(statusCode) };
    
    // Increment request counter
    this.incrementCounter('http_requests_total', 1, labels);
    
    // Record duration in histogram
    this.observeHistogram('http_request_duration_seconds', duration / 1000, labels);
  }

  /**
   * Get metrics in Prometheus format
   */
  async getPrometheusMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  /**
   * Get metrics as JSON
   */
  async getMetricsJson(): Promise<object[]> {
    return this.registry.getMetricsAsJSON();
  }

  /**
   * Aggregate metrics with grouping
   */
  async aggregate(options: {
    name: string;
    startTime: Date;
    endTime: Date;
    aggregation: 'sum' | 'avg' | 'min' | 'max' | 'count';
    groupBy?: string[];
    interval?: string;
  }): Promise<Result<{ series: { name: string; values: { time: Date; value: number }[] }[] }, Error>> {
    try {
      const agg = options.aggregation.toUpperCase();
      const query = `
        SELECT 
          ${agg}(value) as value,
          ${options.interval ? `date_trunc('${options.interval}', recorded_at)` : 'recorded_at'} as time
          ${options.groupBy?.length ? `, ${options.groupBy.map(g => `labels->>'${g}' as ${g}`).join(', ')}` : ''}
        FROM obs_metrics
        WHERE name = $1 AND recorded_at >= $2 AND recorded_at <= $3
        GROUP BY ${options.interval ? `date_trunc('${options.interval}', recorded_at)` : 'recorded_at'}
          ${options.groupBy?.length ? `, ${options.groupBy.map(g => `labels->>'${g}'`).join(', ')}` : ''}
        ORDER BY time
      `;

      const result = await this.db.query(query, [options.name, options.startTime, options.endTime]);

      // Group by series
      const seriesMap = new Map<string, { time: Date; value: number }[]>();
      for (const row of result.rows) {
        const seriesKey = options.groupBy?.map(g => row[g]).join('-') || 'default';
        if (!seriesMap.has(seriesKey)) {
          seriesMap.set(seriesKey, []);
        }
        seriesMap.get(seriesKey)!.push({
          time: new Date(row.time),
          value: parseFloat(row.value) || 0,
        });
      }

      const series = Array.from(seriesMap.entries()).map(([name, values]) => ({
        name,
        values,
      }));

      return { ok: true, value: { series } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List available metrics
   */
  async listMetrics(): Promise<Result<{ name: string; type: string; description: string }[], Error>> {
    try {
      const result = await this.db.query(`
        SELECT DISTINCT name, type
        FROM obs_metrics
        ORDER BY name
      `);

      return {
        ok: true,
        value: result.rows.map(row => ({
          name: row.name,
          type: row.type,
          description: '', // Would come from metric registration in production
        })),
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Query metrics from database
   */
  async queryMetrics(options: {
    name?: string;
    startTime: Date;
    endTime: Date;
    labels?: Record<string, string>;
    aggregation?: 'avg' | 'sum' | 'min' | 'max' | 'count';
    interval?: string;
  }): Promise<Result<MetricValue[]>> {
    try {
      let query = `
        SELECT name, type, value, labels, recorded_at
        FROM obs_metrics
        WHERE recorded_at >= $1 AND recorded_at <= $2
      `;
      const params: unknown[] = [options.startTime, options.endTime];
      let paramIndex = 3;

      if (options.name) {
        query += ` AND name = $${paramIndex}`;
        params.push(options.name);
        paramIndex++;
      }

      if (options.labels) {
        query += ` AND labels @> $${paramIndex}`;
        params.push(JSON.stringify(options.labels));
        paramIndex++;
      }

      if (options.aggregation && options.interval) {
        const agg = options.aggregation.toUpperCase();
        query = `
          SELECT 
            name,
            type,
            ${agg}(value) as value,
            labels,
            date_trunc('${options.interval}', recorded_at) as recorded_at
          FROM obs_metrics
          WHERE recorded_at >= $1 AND recorded_at <= $2
          ${options.name ? `AND name = $3` : ''}
          GROUP BY name, type, labels, date_trunc('${options.interval}', recorded_at)
          ORDER BY recorded_at
        `;
      } else {
        query += ` ORDER BY recorded_at`;
      }

      const result = await this.db.query(query, params);

      const values: MetricValue[] = result.rows.map(row => ({
        name: row.name,
        type: row.type as MetricType,
        value: parseFloat(row.value),
        labels: row.labels || {},
        timestamp: new Date(row.recorded_at),
      }));

      return { ok: true, value: values };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get metric aggregations
   */
  async getMetricAggregations(options: {
    name: string;
    startTime: Date;
    endTime: Date;
  }): Promise<Result<{
    min: number;
    max: number;
    avg: number;
    sum: number;
    count: number;
    latest: number;
  }>> {
    try {
      const result = await this.db.query(`
        SELECT 
          MIN(value) as min_value,
          MAX(value) as max_value,
          AVG(value) as avg_value,
          SUM(value) as sum_value,
          COUNT(*) as count,
          (SELECT value FROM obs_metrics 
           WHERE name = $1 AND recorded_at >= $2 AND recorded_at <= $3 
           ORDER BY recorded_at DESC LIMIT 1) as latest
        FROM obs_metrics
        WHERE name = $1 AND recorded_at >= $2 AND recorded_at <= $3
      `, [options.name, options.startTime, options.endTime]);

      const row = result.rows[0];

      return {
        ok: true,
        value: {
          min: parseFloat(row.min_value) || 0,
          max: parseFloat(row.max_value) || 0,
          avg: parseFloat(row.avg_value) || 0,
          sum: parseFloat(row.sum_value) || 0,
          count: parseInt(row.count) || 0,
          latest: parseFloat(row.latest) || 0,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete old metrics
   */
  async deleteOldMetrics(olderThanDays: number = config.metricsRetentionDays): Promise<Result<number>> {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - olderThanDays);

      const result = await this.db.query(
        'DELETE FROM obs_metrics WHERE recorded_at < $1',
        [cutoff]
      );

      logger.info(`[Metrics] Deleted ${result.rowCount} old metric records`);

      return { ok: true, value: result.rowCount || 0 };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // Private methods

  private registerBuiltInMetrics(): void {
    // Email metrics
    this.registerMetric({
      name: 'apexmail_emails_sent_total',
      type: MetricType.COUNTER,
      help: 'Total number of emails sent',
      labelNames: ['status', 'type'],
    });

    this.registerMetric({
      name: 'apexmail_emails_delivered_total',
      type: MetricType.COUNTER,
      help: 'Total number of emails delivered',
      labelNames: ['provider'],
    });

    this.registerMetric({
      name: 'apexmail_emails_bounced_total',
      type: MetricType.COUNTER,
      help: 'Total number of bounced emails',
      labelNames: ['type', 'reason'],
    });

    this.registerMetric({
      name: 'apexmail_emails_opened_total',
      type: MetricType.COUNTER,
      help: 'Total number of opened emails',
    });

    this.registerMetric({
      name: 'apexmail_emails_clicked_total',
      type: MetricType.COUNTER,
      help: 'Total number of email link clicks',
    });

    // Queue metrics
    this.registerMetric({
      name: 'apexmail_queue_size',
      type: MetricType.GAUGE,
      help: 'Current size of the email queue',
      labelNames: ['queue', 'priority'],
    });

    this.registerMetric({
      name: 'apexmail_queue_processing_duration_seconds',
      type: MetricType.HISTOGRAM,
      help: 'Time taken to process queue items',
      labelNames: ['queue'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10],
    });

    // API metrics
    this.registerMetric({
      name: 'apexmail_http_requests_total',
      type: MetricType.COUNTER,
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'path', 'status'],
    });

    this.registerMetric({
      name: 'apexmail_http_request_duration_seconds',
      type: MetricType.HISTOGRAM,
      help: 'HTTP request duration',
      labelNames: ['method', 'path'],
    });

    this.registerMetric({
      name: 'apexmail_http_requests_in_progress',
      type: MetricType.GAUGE,
      help: 'Number of HTTP requests currently being processed',
    });

    // Database metrics
    this.registerMetric({
      name: 'apexmail_db_connections_active',
      type: MetricType.GAUGE,
      help: 'Number of active database connections',
    });

    this.registerMetric({
      name: 'apexmail_db_query_duration_seconds',
      type: MetricType.HISTOGRAM,
      help: 'Database query duration',
      labelNames: ['operation'],
    });

    // Worker metrics
    this.registerMetric({
      name: 'apexmail_worker_jobs_processed_total',
      type: MetricType.COUNTER,
      help: 'Total number of jobs processed by workers',
      labelNames: ['worker', 'status'],
    });

    this.registerMetric({
      name: 'apexmail_worker_job_duration_seconds',
      type: MetricType.HISTOGRAM,
      help: 'Time taken to process jobs',
      labelNames: ['worker', 'job_type'],
    });

    // Business metrics
    this.registerMetric({
      name: 'apexmail_active_campaigns',
      type: MetricType.GAUGE,
      help: 'Number of active email campaigns',
    });

    this.registerMetric({
      name: 'apexmail_active_users',
      type: MetricType.GAUGE,
      help: 'Number of active users',
      labelNames: ['plan'],
    });

    this.registerMetric({
      name: 'apexmail_api_quota_usage',
      type: MetricType.GAUGE,
      help: 'API quota usage percentage',
      labelNames: ['organization_id'],
    });
  }

  private async collectSystemMetrics(): Promise<void> {
    try {
      // Collect database metrics
      const dbStats = await this.db.query('SELECT count(*) as active FROM pg_stat_activity WHERE state = $1', ['active']);
      this.setGauge('apexmail_db_connections_active', parseInt(dbStats.rows[0]?.active ?? '0', 10));

      // Collect queue metrics from Redis
      const queueSizes = await this.redis.llen('email:queue:high');
      this.setGauge('apexmail_queue_size', queueSizes, { queue: 'email', priority: 'high' });

      // C-092: Store metrics in database in batches for efficiency
      const metricsJson = await this.registry.getMetricsAsJSON();
      const batch: MetricValue[] = [];
      const now = new Date();

      for (const metric of metricsJson as promClient.MetricObject[]) {
        const metricWithValues = metric as promClient.MetricObjectWithValues<promClient.MetricValue<string>>;
        if (metricWithValues.values) {
          for (const value of metricWithValues.values) {
            const labels: Record<string, string> = {};
            if (value.labels) {
              for (const [k, v] of Object.entries(value.labels)) {
                if (v !== undefined) {
                  labels[k] = String(v);
                }
              }
            }
            batch.push({
              name: metric.name,
              type: this.metricTypeFromString(String(metric.type)),
              value: typeof value.value === 'number' ? value.value : 0,
              labels,
              timestamp: now,
            });
          }
        }
      }

      // Write all collected metrics in a single batched INSERT
      if (batch.length > 0) {
        await this.recordMetricsBatch(batch);
      }
    } catch (error) {
      logger.error('[Metrics] Failed to collect system metrics:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async aggregateMetrics(): Promise<void> {
    // Aggregate metrics for longer-term storage
    try {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      
      await this.db.query(`
        INSERT INTO obs_metrics_hourly (name, type, avg_value, min_value, max_value, sum_value, count, labels, hour)
        SELECT 
          name,
          type,
          AVG(value),
          MIN(value),
          MAX(value),
          SUM(value),
          COUNT(*),
          labels,
          date_trunc('hour', recorded_at)
        FROM obs_metrics
        WHERE recorded_at >= $1 - INTERVAL '1 hour' AND recorded_at < $1
        GROUP BY name, type, labels, date_trunc('hour', recorded_at)
        ON CONFLICT (name, labels, hour) DO UPDATE SET
          avg_value = EXCLUDED.avg_value,
          min_value = EXCLUDED.min_value,
          max_value = EXCLUDED.max_value,
          sum_value = EXCLUDED.sum_value,
          count = EXCLUDED.count
      `, [oneHourAgo]);
    } catch (error) {
      logger.error('[Metrics] Failed to aggregate metrics:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private metricTypeFromString(type: string): MetricType {
    const typeMap: Record<string, MetricType> = {
      counter: MetricType.COUNTER,
      gauge: MetricType.GAUGE,
      histogram: MetricType.HISTOGRAM,
      summary: MetricType.SUMMARY,
    };
    return typeMap[type.toLowerCase()] || MetricType.GAUGE;
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    if (this.collectInterval) {
      clearInterval(this.collectInterval);
    }
    if (this.aggregateInterval) {
      clearInterval(this.aggregateInterval);
    }
    logger.info('[Metrics] Service shut down');
  }
}
