/**
 * Distributed Tracing Service
 * 
 * OpenTelemetry-based distributed tracing:
 * - Span creation and management
 * - Context propagation
 * - Trace collection and export
 * - Sampling strategies
 */

import {
  SpanContext,
  SpanKind,
  SpanStatusCode,
  trace,
  context,
  propagation,
  Span,
  Tracer,
  Context,
} from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { SimpleSpanProcessor, BatchSpanProcessor, ConsoleSpanExporter } from '@opentelemetry/sdk-trace-base';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { ZipkinExporter } from '@opentelemetry/exporter-zipkin';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { Result } from '@apexmail/lib';
import { config } from '../config.js';

export interface TraceContextData {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  sampled: boolean;
}

export interface TraceContext extends TraceContextData {
  /** Set an attribute on the span */
  setAttribute(key: string, value: string | number | boolean): void;
  /** Set the status of the span */
  setStatus(status: 'ok' | 'error', message?: string): void;
  /** End the span */
  end(): void;
}

export interface SpanOptions {
  name: string;
  kind?: SpanKind;
  attributes?: Record<string, string | number | boolean>;
  parentContext?: TraceContextData;
}

export interface SpanEvent {
  name: string;
  timestamp?: number;
  attributes?: Record<string, string | number | boolean>;
}

export interface TraceRecord {
  traceId: string;
  spans: SpanRecord[];
  serviceName: string;
  startTime: Date;
  endTime: Date | null;
  duration: number | null;
  status: string;
  tags: Record<string, string>;
}

export interface SpanRecord {
  spanId: string;
  parentSpanId: string | null;
  operationName: string;
  serviceName: string;
  startTime: Date;
  endTime: Date | null;
  duration: number | null;
  status: string;
  statusMessage: string | null;
  kind: string;
  attributes: Record<string, unknown>;
  events: Array<{
    name: string;
    timestamp: Date;
    attributes: Record<string, unknown>;
  }>;
}

export class TracingService {
  private db: Pool;
  private provider: NodeTracerProvider | null = null;
  private tracer: Tracer | null = null;
  private activeSpans: Map<string, Span> = new Map();
  private spanTimestamps: Map<string, number> = new Map();
  private static readonly MAX_ACTIVE_SPANS = 10000;
  private static readonly SPAN_TTL_MS = 5 * 60 * 1000; // 5 minutes
  private spanCleanupInterval: NodeJS.Timeout | null = null;
  private spanBuffer: SpanRecord[] = [];
  private flushInterval: NodeJS.Timeout | null = null;

  constructor(db: Pool, _redis: Redis) {
    this.db = db;
    void _redis; // Reserved for future caching implementation
  }

  /**
   * Initialize tracing
   */
  async initialize(): Promise<void> {
    if (!config.tracing.enabled) {
      console.log('[Tracing] Tracing is disabled');
      return;
    }

    // Create resource
    const resource = new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: config.tracing.serviceName,
      [SemanticResourceAttributes.SERVICE_VERSION]: config.tracing.serviceVersion,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: config.tracing.environment,
    });

    // Create provider
    this.provider = new NodeTracerProvider({ resource });

    // Add exporters based on configuration
    if (config.tracing.jaegerEndpoint) {
      const jaegerExporter = new JaegerExporter({
        endpoint: config.tracing.jaegerEndpoint,
      });
      this.provider.addSpanProcessor(new BatchSpanProcessor(jaegerExporter));
    }

    if (config.tracing.zipkinEndpoint) {
      const zipkinExporter = new ZipkinExporter({
        url: config.tracing.zipkinEndpoint,
      });
      this.provider.addSpanProcessor(new BatchSpanProcessor(zipkinExporter));
    }

    // Add console exporter in development
    if (config.environment === 'development') {
      this.provider.addSpanProcessor(new SimpleSpanProcessor(new ConsoleSpanExporter()));
    }

    // Custom processor to store spans
    this.provider.addSpanProcessor({
      onStart: () => {},
      onEnd: (span) => {
        this.bufferSpan(span);
      },
      shutdown: async () => {},
      forceFlush: async () => {},
    });

    // Register provider
    this.provider.register();

    // Get tracer
    this.tracer = trace.getTracer(config.tracing.serviceName, config.tracing.serviceVersion);

    // Start flush interval
    this.flushInterval = setInterval(() => {
      this.flushSpanBuffer();
    }, 5000);

    // Start periodic cleanup of stale active spans (TTL-based eviction)
    this.spanCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [spanId, startedAt] of this.spanTimestamps) {
        if (now - startedAt > TracingService.SPAN_TTL_MS) {
          const span = this.activeSpans.get(spanId);
          if (span) {
            span.setStatus({ code: SpanStatusCode.ERROR, message: 'Span expired (TTL)' });
            span.end();
          }
          this.activeSpans.delete(spanId);
          this.spanTimestamps.delete(spanId);
        }
      }
    }, 60_000);

    console.log('[Tracing] Service initialized');
  }

  /**
   * Start a new span
   */
  startSpan(options: SpanOptions): TraceContext {
    if (!this.tracer) {
      return this.createDummyContext();
    }

    let parentContext: Context = context.active();

    // If parent context is provided, extract it
    if (options.parentContext) {
      const spanContext: SpanContext = {
        traceId: options.parentContext.traceId,
        spanId: options.parentContext.spanId,
        isRemote: true,
        traceFlags: options.parentContext.sampled ? 1 : 0,
      };
      parentContext = trace.setSpanContext(context.active(), spanContext);
    }

    const span = this.tracer.startSpan(
      options.name,
      {
        kind: options.kind ?? SpanKind.INTERNAL,
        attributes: options.attributes,
      },
      parentContext
    );

    const spanContext = span.spanContext();
    const traceContext: TraceContext = {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      parentSpanId: options.parentContext?.spanId,
      sampled: (spanContext.traceFlags & 1) === 1,
      setAttribute: (key: string, value: string | number | boolean) => {
        span.setAttribute(key, value);
      },
      setStatus: (status: 'ok' | 'error', message?: string) => {
        if (status === 'error') {
          span.setStatus({ code: SpanStatusCode.ERROR, message });
        } else {
          span.setStatus({ code: SpanStatusCode.OK });
        }
      },
      end: () => {
        span.end();
        this.activeSpans.delete(spanContext.spanId);
        this.spanTimestamps.delete(spanContext.spanId);
      },
    };

    // Evict oldest spans if at capacity
    if (this.activeSpans.size >= TracingService.MAX_ACTIVE_SPANS) {
      const oldest = this.activeSpans.keys().next().value;
      if (oldest) {
        this.activeSpans.delete(oldest);
        this.spanTimestamps.delete(oldest);
      }
    }

    this.activeSpans.set(spanContext.spanId, span);
    this.spanTimestamps.set(spanContext.spanId, Date.now());

    return traceContext;
  }

  /**
   * End a span
   */
  endSpan(spanId: string, status?: 'ok' | 'error', errorMessage?: string): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      return;
    }

    if (status === 'error') {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: errorMessage,
      });
    } else {
      span.setStatus({ code: SpanStatusCode.OK });
    }

    span.end();
    this.activeSpans.delete(spanId);
    this.spanTimestamps.delete(spanId);
  }

  /**
   * Add attributes to a span
   */
  setSpanAttributes(spanId: string, attributes: Record<string, string | number | boolean>): void {
    const span = this.activeSpans.get(spanId);
    if (span) {
      span.setAttributes(attributes);
    }
  }

  /**
   * Add an event to a span
   */
  addSpanEvent(spanId: string, event: SpanEvent): void {
    const span = this.activeSpans.get(spanId);
    if (span) {
      span.addEvent(event.name, event.attributes, event.timestamp);
    }
  }

  /**
   * Record an exception on a span
   */
  recordException(spanId: string, error: Error): void {
    const span = this.activeSpans.get(spanId);
    if (span) {
      span.recordException(error);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message,
      });
    }
  }

  /**
   * Extract trace context from HTTP headers
   * Supports W3C Trace Context (traceparent/tracestate) headers
   */
  extractContext(headers: Record<string, string>): TraceContextData | null {
    try {
      // W3C Trace Context: Check for traceparent header first
      // Format: version-traceId-parentId-flags (e.g., "00-{traceId}-{spanId}-01")
      const traceparent = headers['traceparent'] || headers['Traceparent'];
      
      if (traceparent) {
        const parts = traceparent.split('-');
        if (parts.length === 4) {
          const version = parts[0];
          const traceId = parts[1];
          const spanId = parts[2];
          const flags = parts[3];
          if (version === '00' && traceId && traceId.length === 32 && spanId && spanId.length === 16 && flags) {
            return {
              traceId,
              spanId,
              sampled: (parseInt(flags, 16) & 1) === 1,
            };
          }
        }
      }
      
      // Fall back to OpenTelemetry propagation API
      const ctx = propagation.extract(context.active(), headers);
      const spanContext = trace.getSpanContext(ctx);
      
      if (spanContext) {
        return {
          traceId: spanContext.traceId,
          spanId: spanContext.spanId,
          sampled: (spanContext.traceFlags & 1) === 1,
        };
      }
    } catch {
      // Extraction failed
    }
    return null;
  }

  /**
   * Inject trace context into HTTP headers
   * Includes W3C Trace Context (traceparent) header for interoperability
   */
  injectContext(traceContext: TraceContext): Record<string, string> {
    const headers: Record<string, string> = {};
    
    const spanContext: SpanContext = {
      traceId: traceContext.traceId,
      spanId: traceContext.spanId,
      isRemote: false,
      traceFlags: traceContext.sampled ? 1 : 0,
    };
    
    const ctx = trace.setSpanContext(context.active(), spanContext);
    propagation.inject(ctx, headers);
    
    // ENHANCEMENT: Explicitly add W3C Trace Context traceparent header
    // Format: version-traceId-parentId-flags
    const flags = traceContext.sampled ? '01' : '00';
    headers['traceparent'] = `00-${traceContext.traceId}-${traceContext.spanId}-${flags}`;
    
    return headers;
  }

  /**
   * Get a trace by ID
   */
  async getTrace(traceId: string): Promise<Result<TraceRecord | null>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM obs_spans WHERE trace_id = $1 ORDER BY start_time ASC
      `, [traceId]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const spans: SpanRecord[] = result.rows.map(row => ({
        spanId: row.span_id,
        parentSpanId: row.parent_span_id,
        operationName: row.operation_name,
        serviceName: row.service_name,
        startTime: new Date(row.start_time),
        endTime: row.end_time ? new Date(row.end_time) : null,
        duration: row.duration_ms,
        status: row.status,
        statusMessage: row.status_message,
        kind: row.span_kind,
        attributes: row.attributes || {},
        events: row.events || [],
      }));

      if (spans.length === 0) {
        return { ok: false, error: new Error('No spans found for trace') };
      }

      const firstSpan = spans[0]!;
      const lastSpan = spans[spans.length - 1]!;

      const trace: TraceRecord = {
        traceId,
        spans,
        serviceName: firstSpan.serviceName,
        startTime: firstSpan.startTime,
        endTime: lastSpan.endTime,
        duration: lastSpan.endTime 
          ? lastSpan.endTime.getTime() - firstSpan.startTime.getTime()
          : null,
        status: spans.some(s => s.status === 'error') ? 'error' : 'ok',
        tags: {},
      };

      return { ok: true, value: trace };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Search traces
   */
  async searchTraces(options: {
    service?: string;
    operation?: string;
    minDuration?: number;
    maxDuration?: number;
    startTime?: Date;
    endTime?: Date;
    status?: 'ok' | 'error';
    tags?: Record<string, string>;
    limit?: number;
    offset?: number;
  }): Promise<Result<{ traces: TraceRecord[]; total: number }>> {
    try {
      let query = `
        SELECT DISTINCT trace_id, 
               MIN(start_time) as start_time,
               MAX(end_time) as end_time,
               service_name,
               MAX(CASE WHEN status = 'error' THEN 'error' ELSE 'ok' END) as status
        FROM obs_spans
        WHERE 1=1
      `;
      const params: unknown[] = [];
      let paramIndex = 1;

      if (options.service) {
        query += ` AND service_name = $${paramIndex}`;
        params.push(options.service);
        paramIndex++;
      }

      if (options.operation) {
        query += ` AND operation_name ILIKE $${paramIndex}`;
        params.push(`%${options.operation}%`);
        paramIndex++;
      }

      if (options.startTime) {
        query += ` AND start_time >= $${paramIndex}`;
        params.push(options.startTime);
        paramIndex++;
      }

      if (options.endTime) {
        query += ` AND start_time <= $${paramIndex}`;
        params.push(options.endTime);
        paramIndex++;
      }

      if (options.status === 'error') {
        query += ` AND status = 'error'`;
      }

      query += ` GROUP BY trace_id, service_name`;

      if (options.minDuration) {
        query += ` HAVING (MAX(end_time) - MIN(start_time)) >= $${paramIndex} * INTERVAL '1 millisecond'`;
        params.push(options.minDuration);
        paramIndex++;
      }

      // Count total
      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM (${query}) subq`,
        params
      );

      query += ` ORDER BY start_time DESC`;

      if (options.limit) {
        query += ` LIMIT $${paramIndex}`;
        params.push(options.limit);
        paramIndex++;
      }

      if (options.offset) {
        query += ` OFFSET $${paramIndex}`;
        params.push(options.offset);
      }

      const result = await this.db.query(query, params);

      const traces: TraceRecord[] = result.rows.map(row => ({
        traceId: row.trace_id,
        spans: [],
        serviceName: row.service_name,
        startTime: new Date(row.start_time),
        endTime: row.end_time ? new Date(row.end_time) : null,
        duration: row.end_time 
          ? new Date(row.end_time).getTime() - new Date(row.start_time).getTime()
          : null,
        status: row.status,
        tags: {},
      }));

      return {
        ok: true,
        value: {
          traces,
          total: parseInt(countResult.rows[0]?.total ?? '0', 10),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get trace statistics
   */
  async getTraceStats(options: {
    service?: string;
    startTime: Date;
    endTime: Date;
  }): Promise<Result<{
    totalTraces: number;
    errorRate: number;
    avgDuration: number;
    p50Duration: number;
    p95Duration: number;
    p99Duration: number;
    operationStats: Array<{
      operation: string;
      count: number;
      avgDuration: number;
      errorRate: number;
    }>;
  }>> {
    try {
      const params: unknown[] = [options.startTime, options.endTime];
      let serviceCondition = '';
      
      if (options.service) {
        serviceCondition = ' AND service_name = $3';
        params.push(options.service);
      }

      // Overall stats
      const statsResult = await this.db.query(`
        SELECT 
          COUNT(DISTINCT trace_id) as total_traces,
          AVG(CASE WHEN status = 'error' THEN 1.0 ELSE 0.0 END) as error_rate,
          AVG(duration_ms) as avg_duration,
          PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms) as p50,
          PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95,
          PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms) as p99
        FROM obs_spans
        WHERE start_time >= $1 AND start_time <= $2 ${serviceCondition}
          AND parent_span_id IS NULL
      `, params);

      // Per-operation stats
      const opResult = await this.db.query(`
        SELECT 
          operation_name,
          COUNT(*) as count,
          AVG(duration_ms) as avg_duration,
          AVG(CASE WHEN status = 'error' THEN 1.0 ELSE 0.0 END) as error_rate
        FROM obs_spans
        WHERE start_time >= $1 AND start_time <= $2 ${serviceCondition}
        GROUP BY operation_name
        ORDER BY count DESC
        LIMIT 50
      `, params);

      const stats = statsResult.rows[0];

      return {
        ok: true,
        value: {
          totalTraces: parseInt(stats.total_traces) || 0,
          errorRate: parseFloat(stats.error_rate) || 0,
          avgDuration: parseFloat(stats.avg_duration) || 0,
          p50Duration: parseFloat(stats.p50) || 0,
          p95Duration: parseFloat(stats.p95) || 0,
          p99Duration: parseFloat(stats.p99) || 0,
          operationStats: opResult.rows.map(row => ({
            operation: row.operation_name,
            count: parseInt(row.count),
            avgDuration: parseFloat(row.avg_duration) || 0,
            errorRate: parseFloat(row.error_rate) || 0,
          })),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete old traces
   */
  async deleteOldTraces(olderThanDays: number = config.traceRetentionDays): Promise<Result<number>> {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - olderThanDays);

      const result = await this.db.query(
        'DELETE FROM obs_spans WHERE start_time < $1',
        [cutoff]
      );

      console.log(`[Tracing] Deleted ${result.rowCount} old spans`);

      return { ok: true, value: result.rowCount || 0 };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // Private methods

  private bufferSpan(span: unknown): void {
    const spanData = span as {
      name: string;
      spanContext: () => SpanContext;
      parentSpanId?: string;
      startTime: [number, number];
      endTime: [number, number];
      status: { code: number; message?: string };
      kind: number;
      attributes: Record<string, unknown>;
      events: Array<{ name: string; time: [number, number]; attributes?: Record<string, unknown> }>;
    };

    const spanContext = spanData.spanContext();
    
    const record: SpanRecord = {
      spanId: spanContext.spanId,
      parentSpanId: spanData.parentSpanId || null,
      operationName: spanData.name,
      serviceName: config.tracing.serviceName,
      startTime: this.hrtimeToDate(spanData.startTime),
      endTime: this.hrtimeToDate(spanData.endTime),
      duration: this.calculateDuration(spanData.startTime, spanData.endTime),
      status: spanData.status.code === SpanStatusCode.ERROR ? 'error' : 'ok',
      statusMessage: spanData.status.message || null,
      kind: this.kindToString(spanData.kind),
      attributes: spanData.attributes || {},
      events: spanData.events?.map(e => ({
        name: e.name,
        timestamp: this.hrtimeToDate(e.time),
        attributes: e.attributes || {},
      })) || [],
    };

    this.spanBuffer.push(record);
  }

  private async flushSpanBuffer(): Promise<void> {
    if (this.spanBuffer.length === 0) {
      return;
    }

    const spansToFlush = [...this.spanBuffer];
    this.spanBuffer = [];

    try {
      for (const span of spansToFlush) {
        await this.db.query(`
          INSERT INTO obs_spans (
            span_id, trace_id, parent_span_id, operation_name, service_name,
            start_time, end_time, duration_ms, status, status_message,
            span_kind, attributes, events
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
          )
        `, [
          span.spanId,
          span.spanId.substring(0, 32), // Extract trace ID
          span.parentSpanId,
          span.operationName,
          span.serviceName,
          span.startTime,
          span.endTime,
          span.duration,
          span.status,
          span.statusMessage,
          span.kind,
          JSON.stringify(span.attributes),
          JSON.stringify(span.events),
        ]);
      }
    } catch (error) {
      console.error('[Tracing] Failed to flush span buffer:', error);
      // Re-add failed spans to buffer
      this.spanBuffer.push(...spansToFlush);
    }
  }

  private createDummyContext(): TraceContext {
    return {
      traceId: uuidv4().replace(/-/g, ''),
      spanId: uuidv4().replace(/-/g, '').substring(0, 16),
      sampled: false,
      setAttribute: () => { /* no-op when tracing disabled */ },
      setStatus: () => { /* no-op when tracing disabled */ },
      end: () => { /* no-op when tracing disabled */ },
    };
  }

  private hrtimeToDate(hrtime: [number, number]): Date {
    const ms = hrtime[0] * 1000 + hrtime[1] / 1000000;
    return new Date(ms);
  }

  private calculateDuration(start: [number, number], end: [number, number]): number {
    const startMs = start[0] * 1000 + start[1] / 1000000;
    const endMs = end[0] * 1000 + end[1] / 1000000;
    return endMs - startMs;
  }

  private kindToString(kind: number): string {
    const kinds: Record<number, string> = {
      0: 'INTERNAL',
      1: 'SERVER',
      2: 'CLIENT',
      3: 'PRODUCER',
      4: 'CONSUMER',
    };
    return kinds[kind] || 'INTERNAL';
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }

    await this.flushSpanBuffer();

    if (this.provider) {
      await this.provider.shutdown();
    }

    console.log('[Tracing] Service shut down');
  }
}
