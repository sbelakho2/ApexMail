/**
 * Metrics Server - Prometheus-compatible metrics endpoint
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'http';
import type { Logger } from '@apexmail/lib';

interface Metric {
  name: string;
  type: 'counter' | 'gauge' | 'histogram';
  help: string;
  labels?: string[];
  value?: number;
  values?: Map<string, number>;
  buckets?: Map<string, Map<number, number>>;
  sums?: Map<string, number>;
  counts?: Map<string, number>;
}

const HISTOGRAM_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

export class MetricsServer {
  private readonly port: number;
  private readonly logger: Logger;
  private server: Server | null = null;
  private readonly metrics = new Map<string, Metric>();

  constructor(port: number, logger: Logger) {
    this.port = port;
    this.logger = logger;
    this.initializeMetrics();
  }

  private initializeMetrics(): void {
    // Email processor metrics
    this.registerCounter('apexmail_emails_sent_total', 'Total number of emails sent', ['status', 'domain']);
    this.registerCounter('apexmail_emails_bounced_total', 'Total number of bounced emails', ['bounce_type', 'domain']);
    this.registerCounter('apexmail_emails_dropped_total', 'Total number of dropped emails', ['reason']);
    this.registerGauge('apexmail_email_queue_size', 'Current size of email queue');
    this.registerGauge('apexmail_email_processor_active_jobs', 'Number of active email processing jobs');
    this.registerHistogram('apexmail_email_send_duration_seconds', 'Email send duration in seconds', ['domain']);

    // Webhook processor metrics
    this.registerCounter('apexmail_webhooks_delivered_total', 'Total number of webhooks delivered', ['status']);
    this.registerGauge('apexmail_webhook_queue_size', 'Current size of webhook queue');
    this.registerGauge('apexmail_webhook_processor_active_jobs', 'Number of active webhook processing jobs');
    this.registerHistogram('apexmail_webhook_delivery_duration_seconds', 'Webhook delivery duration in seconds');

    // Analytics processor metrics
    this.registerCounter('apexmail_analytics_events_processed_total', 'Total analytics events processed', ['event_type']);
    this.registerGauge('apexmail_analytics_buffer_size', 'Current size of analytics buffer');
    this.registerGauge('apexmail_analytics_processor_active_jobs', 'Number of active analytics processing jobs');

    // System metrics
    this.registerCounter('apexmail_process_cpu_seconds_total', 'Total CPU time spent');
    this.registerGauge('apexmail_process_resident_memory_bytes', 'Resident memory size in bytes');
    this.registerGauge('apexmail_process_heap_bytes', 'Node.js heap size in bytes');
    this.registerGauge('apexmail_process_uptime_seconds', 'Process uptime in seconds');

    // Database metrics
    this.registerGauge('apexmail_db_pool_total', 'Total database pool connections');
    this.registerGauge('apexmail_db_pool_idle', 'Idle database pool connections');
    this.registerGauge('apexmail_db_pool_waiting', 'Waiting database pool requests');

    // Redis metrics
    this.registerGauge('apexmail_redis_connected', 'Redis connection status (1=connected, 0=disconnected)');
  }

  private registerCounter(name: string, help: string, labels?: string[]): void {
    this.metrics.set(name, {
      name,
      type: 'counter',
      help,
      labels,
      values: new Map(),
    });
  }

  private registerGauge(name: string, help: string, labels?: string[]): void {
    this.metrics.set(name, {
      name,
      type: 'gauge',
      help,
      labels,
      values: new Map(),
    });
  }

  private registerHistogram(name: string, help: string, labels?: string[]): void {
    this.metrics.set(name, {
      name,
      type: 'histogram',
      help,
      labels,
      buckets: new Map(),
      sums: new Map(),
      counts: new Map(),
    });
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));

      this.server.on('error', (error) => {
        this.logger.error('Metrics server error', { error });
        reject(error);
      });

      this.server.listen(this.port, () => {
        this.logger.info('Metrics server started', { port: this.port });
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }

      this.server.close(() => {
        this.logger.info('Metrics server stopped');
        resolve();
      });
    });
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    if (req.url === '/metrics' && req.method === 'GET') {
      this.updateSystemMetrics();
      const output = this.formatMetrics();
      
      res.writeHead(200, {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
      });
      res.end(output);
    } else if (req.url === '/health' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    } else {
      res.writeHead(404);
      res.end('Not Found');
    }
  }

  private updateSystemMetrics(): void {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    this.setCounter('apexmail_process_cpu_seconds_total', 
      (cpuUsage.user + cpuUsage.system) / 1000000);
    this.setGauge('apexmail_process_resident_memory_bytes', memUsage.rss);
    this.setGauge('apexmail_process_heap_bytes', memUsage.heapUsed);
    this.setGauge('apexmail_process_uptime_seconds', process.uptime());
  }

  private formatMetrics(): string {
    const lines: string[] = [];

    for (const metric of this.metrics.values()) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} ${metric.type}`);

      if (metric.type === 'counter' || metric.type === 'gauge') {
        if (metric.values && metric.values.size > 0) {
          for (const [labelKey, value] of metric.values) {
            if (labelKey) {
              lines.push(`${metric.name}{${labelKey}} ${value}`);
            } else {
              lines.push(`${metric.name} ${value}`);
            }
          }
        } else if (metric.value !== undefined) {
          lines.push(`${metric.name} ${metric.value}`);
        }
      } else if (metric.type === 'histogram') {
        if (metric.buckets) {
          for (const [labelKey, buckets] of metric.buckets) {
            const labelPart = labelKey ? `${labelKey},` : '';
            let cumulative = 0;

            for (const bucket of HISTOGRAM_BUCKETS) {
              cumulative += buckets.get(bucket) ?? 0;
              lines.push(`${metric.name}_bucket{${labelPart}le="${bucket}"} ${cumulative}`);
            }
            lines.push(`${metric.name}_bucket{${labelPart}le="+Inf"} ${cumulative}`);

            const sum = metric.sums?.get(labelKey) ?? 0;
            const count = metric.counts?.get(labelKey) ?? 0;
            lines.push(`${metric.name}_sum{${labelKey ? labelKey : ''}} ${sum}`);
            lines.push(`${metric.name}_count{${labelKey ? labelKey : ''}} ${count}`);
          }
        }
      }

      lines.push('');
    }

    return lines.join('\n');
  }

  // Public methods for updating metrics

  incrementCounter(name: string, labels?: Record<string, string>, value = 1): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') return;

    const labelKey = labels ? this.formatLabels(labels) : '';
    const current = metric.values?.get(labelKey) ?? 0;
    metric.values?.set(labelKey, current + value);
  }

  setCounter(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') return;

    const labelKey = labels ? this.formatLabels(labels) : '';
    if (!metric.values) {
      metric.values = new Map();
    }
    metric.values.set(labelKey, value);
  }

  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') return;

    const labelKey = labels ? this.formatLabels(labels) : '';
    
    if (!metric.values) {
      metric.values = new Map();
    }
    metric.values.set(labelKey, value);
  }

  incrementGauge(name: string, labels?: Record<string, string>, value = 1): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') return;

    const labelKey = labels ? this.formatLabels(labels) : '';
    const current = metric.values?.get(labelKey) ?? 0;
    metric.values?.set(labelKey, current + value);
  }

  decrementGauge(name: string, labels?: Record<string, string>, value = 1): void {
    this.incrementGauge(name, labels, -value);
  }

  observeHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'histogram') return;

    const labelKey = labels ? this.formatLabels(labels) : '';

    // Initialize bucket map if needed
    if (!metric.buckets!.has(labelKey)) {
      const bucketMap = new Map<number, number>();
      for (const bucket of HISTOGRAM_BUCKETS) {
        bucketMap.set(bucket, 0);
      }
      metric.buckets!.set(labelKey, bucketMap);
      metric.sums!.set(labelKey, 0);
      metric.counts!.set(labelKey, 0);
    }

    // Find the right bucket and increment
    const buckets = metric.buckets!.get(labelKey)!;
    for (const bucket of HISTOGRAM_BUCKETS) {
      if (value <= bucket) {
        buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1);
        break;
      }
    }

    // Update sum and count
    metric.sums!.set(labelKey, (metric.sums!.get(labelKey) ?? 0) + value);
    metric.counts!.set(labelKey, (metric.counts!.get(labelKey) ?? 0) + 1);
  }

  private formatLabels(labels: Record<string, string>): string {
    return Object.entries(labels)
      .map(([k, v]) => `${k}="${this.escapeLabel(v)}"`)
      .join(',');
  }

  private escapeLabel(value: string): string {
    return value
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n');
  }
}

// Singleton instance for global access
let metricsInstance: MetricsServer | null = null;

export function getMetrics(): MetricsServer | null {
  return metricsInstance;
}

export function setMetricsInstance(instance: MetricsServer): void {
  metricsInstance = instance;
}
