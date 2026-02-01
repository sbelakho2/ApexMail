/**
 * @apexmail/ops - OpenTelemetry Tracing
 * 
 * Distributed tracing with OpenTelemetry integration.
 */

import {
    Span,
    SpanKind,
    SpanStatusCode,
    trace,
    context,
    propagation,
    Context,
    Tracer,
    SpanContext,
    SpanOptions,
    Attributes,
} from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import {
    BatchSpanProcessor,
    SpanExporter,
    ReadableSpan,
    SimpleSpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import {
    ATTR_SERVICE_NAME,
    ATTR_SERVICE_VERSION,
    ATTR_DEPLOYMENT_ENVIRONMENT,
} from '@opentelemetry/semantic-conventions';
import { W3CTraceContextPropagator } from '@opentelemetry/core';
import pino from 'pino';

const logger = pino({ name: 'tracer' });

export interface TracerConfig {
    serviceName: string;
    serviceVersion: string;
    environment: string;
    endpoint?: string;
    sampleRate: number;
    enabled: boolean;
}

interface SpanData {
    traceId: string;
    spanId: string;
    parentSpanId?: string;
    name: string;
    kind: SpanKind;
    startTime: number;
    endTime?: number;
    status: { code: SpanStatusCode; message?: string };
    attributes: Record<string, string | number | boolean>;
    events: { name: string; timestamp: number; attributes?: Record<string, unknown> }[];
}

export class TracingService {
    private config: TracerConfig;
    private provider: NodeTracerProvider | null = null;
    private tracer: Tracer | null = null;
    private spans: Map<string, SpanData> = new Map();
    private exportedSpans: SpanData[] = [];

    constructor(config: TracerConfig) {
        this.config = config;
        if (config.enabled) {
            this.initialize();
        }
    }

    /**
     * Initializes the tracer provider
     */
    private initialize(): void {
        const resource = new Resource({
            [ATTR_SERVICE_NAME]: this.config.serviceName,
            [ATTR_SERVICE_VERSION]: this.config.serviceVersion,
            [ATTR_DEPLOYMENT_ENVIRONMENT]: this.config.environment,
        });

        this.provider = new NodeTracerProvider({
            resource,
            sampler: {
                shouldSample: () => ({
                    decision: Math.random() < this.config.sampleRate ? 1 : 0,
                }),
            },
        });

        // Configure exporter
        if (this.config.endpoint) {
            const exporter = new OTLPTraceExporter({
                url: this.config.endpoint,
            });
            this.provider.addSpanProcessor(new BatchSpanProcessor(exporter));
        }

        // Add local collector for debugging
        this.provider.addSpanProcessor(
            new SimpleSpanProcessor(this.createLocalExporter())
        );

        // Set up propagation
        propagation.setGlobalPropagator(new W3CTraceContextPropagator());

        this.provider.register();
        this.tracer = trace.getTracer(this.config.serviceName, this.config.serviceVersion);

        logger.info(
            { serviceName: this.config.serviceName },
            'Tracing initialized'
        );
    }

    /**
     * Creates a local span exporter for debugging
     */
    private createLocalExporter(): SpanExporter {
        const self = this;
        return {
            export(spans: ReadableSpan[], resultCallback: (result: { code: number }) => void): void {
                for (const span of spans) {
                    const data: SpanData = {
                        traceId: span.spanContext().traceId,
                        spanId: span.spanContext().spanId,
                        parentSpanId: span.parentSpanId,
                        name: span.name,
                        kind: span.kind,
                        startTime: span.startTime[0] * 1000 + span.startTime[1] / 1e6,
                        endTime: span.endTime[0] * 1000 + span.endTime[1] / 1e6,
                        status: span.status,
                        attributes: span.attributes as Record<string, string | number | boolean>,
                        events: span.events.map((e) => ({
                            name: e.name,
                            timestamp: e.time[0] * 1000 + e.time[1] / 1e6,
                            attributes: e.attributes as Record<string, unknown>,
                        })),
                    };
                    self.exportedSpans.push(data);
                    
                    // Keep only last 1000 spans
                    if (self.exportedSpans.length > 1000) {
                        self.exportedSpans.shift();
                    }
                }
                resultCallback({ code: 0 });
            },
            shutdown(): Promise<void> {
                return Promise.resolve();
            },
        };
    }

    /**
     * Gets the tracer instance
     */
    getTracer(): Tracer {
        if (!this.tracer) {
            return trace.getTracer(this.config.serviceName);
        }
        return this.tracer;
    }

    /**
     * Starts a new span
     */
    startSpan(
        name: string,
        options: {
            kind?: SpanKind;
            attributes?: Attributes;
            parent?: Context;
        } = {}
    ): Span {
        const tracer = this.getTracer();
        const spanOptions: SpanOptions = {
            kind: options.kind || SpanKind.INTERNAL,
            attributes: options.attributes,
        };

        const ctx = options.parent || context.active();
        return tracer.startSpan(name, spanOptions, ctx);
    }

    /**
     * Executes a function within a span
     */
    async withSpan<T>(
        name: string,
        fn: (span: Span) => Promise<T>,
        options: {
            kind?: SpanKind;
            attributes?: Attributes;
        } = {}
    ): Promise<T> {
        const span = this.startSpan(name, options);

        try {
            const result = await context.with(
                trace.setSpan(context.active(), span),
                () => fn(span)
            );
            span.setStatus({ code: SpanStatusCode.OK });
            return result;
        } catch (error) {
            span.setStatus({
                code: SpanStatusCode.ERROR,
                message: error instanceof Error ? error.message : 'Unknown error',
            });
            span.recordException(error as Error);
            throw error;
        } finally {
            span.end();
        }
    }

    /**
     * Executes a sync function within a span
     */
    withSpanSync<T>(
        name: string,
        fn: (span: Span) => T,
        options: {
            kind?: SpanKind;
            attributes?: Attributes;
        } = {}
    ): T {
        const span = this.startSpan(name, options);

        try {
            const result = context.with(
                trace.setSpan(context.active(), span),
                () => fn(span)
            );
            span.setStatus({ code: SpanStatusCode.OK });
            return result;
        } catch (error) {
            span.setStatus({
                code: SpanStatusCode.ERROR,
                message: error instanceof Error ? error.message : 'Unknown error',
            });
            span.recordException(error as Error);
            throw error;
        } finally {
            span.end();
        }
    }

    /**
     * Gets the current span
     */
    getCurrentSpan(): Span | undefined {
        return trace.getActiveSpan();
    }

    /**
     * Gets the current span context
     */
    getCurrentSpanContext(): SpanContext | undefined {
        return trace.getActiveSpan()?.spanContext();
    }

    /**
     * Extracts trace context from headers
     */
    extractContext(headers: Record<string, string>): Context {
        return propagation.extract(context.active(), headers);
    }

    /**
     * Injects trace context into headers
     */
    injectContext(headers: Record<string, string>): void {
        propagation.inject(context.active(), headers);
    }

    /**
     * Creates a child span
     */
    createChildSpan(
        parentSpan: Span,
        name: string,
        options: {
            kind?: SpanKind;
            attributes?: Attributes;
        } = {}
    ): Span {
        const tracer = this.getTracer();
        const ctx = trace.setSpan(context.active(), parentSpan);
        return tracer.startSpan(name, {
            kind: options.kind || SpanKind.INTERNAL,
            attributes: options.attributes,
        }, ctx);
    }

    /**
     * Adds attributes to the current span
     */
    setAttributes(attributes: Attributes): void {
        const span = this.getCurrentSpan();
        if (span) {
            span.setAttributes(attributes);
        }
    }

    /**
     * Adds an event to the current span
     */
    addEvent(
        name: string,
        attributes?: Attributes,
        timestamp?: number
    ): void {
        const span = this.getCurrentSpan();
        if (span) {
            span.addEvent(name, attributes, timestamp);
        }
    }

    /**
     * Records an exception on the current span
     */
    recordException(error: Error): void {
        const span = this.getCurrentSpan();
        if (span) {
            span.recordException(error);
            span.setStatus({
                code: SpanStatusCode.ERROR,
                message: error.message,
            });
        }
    }

    /**
     * Creates a span for HTTP requests
     */
    startHTTPSpan(
        method: string,
        url: string,
        headers: Record<string, string>
    ): { span: Span; context: Context } {
        const parentContext = this.extractContext(headers);
        const span = this.startSpan(`HTTP ${method}`, {
            kind: SpanKind.SERVER,
            parent: parentContext,
            attributes: {
                'http.method': method,
                'http.url': url,
                'http.target': new URL(url).pathname,
            },
        });

        return {
            span,
            context: trace.setSpan(context.active(), span),
        };
    }

    /**
     * Creates a span for database queries
     */
    startDatabaseSpan(
        operation: string,
        statement: string,
        system: string = 'postgresql'
    ): Span {
        return this.startSpan(`DB ${operation}`, {
            kind: SpanKind.CLIENT,
            attributes: {
                'db.system': system,
                'db.operation': operation,
                'db.statement': statement,
            },
        });
    }

    /**
     * Creates a span for external HTTP calls
     */
    async traceHTTPCall<T>(
        method: string,
        url: string,
        fn: (headers: Record<string, string>) => Promise<T>
    ): Promise<T> {
        return this.withSpan(
            `HTTP ${method} ${new URL(url).hostname}`,
            async (span) => {
                span.setAttributes({
                    'http.method': method,
                    'http.url': url,
                });

                // Inject trace context
                const headers: Record<string, string> = {};
                propagation.inject(
                    trace.setSpan(context.active(), span),
                    headers
                );

                const result = await fn(headers);
                return result;
            },
            { kind: SpanKind.CLIENT }
        );
    }

    /**
     * Creates a span for queue operations
     */
    startQueueSpan(
        operation: 'publish' | 'consume' | 'process',
        queueName: string
    ): Span {
        const kind = operation === 'publish' ? SpanKind.PRODUCER : SpanKind.CONSUMER;
        return this.startSpan(`Queue ${operation}`, {
            kind,
            attributes: {
                'messaging.system': 'redis',
                'messaging.destination': queueName,
                'messaging.operation': operation,
            },
        });
    }

    /**
     * Gets exported spans (for debugging)
     */
    getExportedSpans(options: {
        limit?: number;
        traceId?: string;
    } = {}): SpanData[] {
        let spans = [...this.exportedSpans];

        if (options.traceId) {
            spans = spans.filter((s) => s.traceId === options.traceId);
        }

        if (options.limit) {
            spans = spans.slice(-options.limit);
        }

        return spans;
    }

    /**
     * Gets a trace by ID
     */
    getTrace(traceId: string): SpanData[] {
        return this.exportedSpans
            .filter((s) => s.traceId === traceId)
            .sort((a, b) => a.startTime - b.startTime);
    }

    /**
     * Gets recent traces
     */
    getRecentTraces(limit: number = 20): { traceId: string; rootSpan: SpanData; spanCount: number }[] {
        const traces = new Map<string, SpanData[]>();

        for (const span of this.exportedSpans) {
            const existing = traces.get(span.traceId) || [];
            existing.push(span);
            traces.set(span.traceId, existing);
        }

        return Array.from(traces.entries())
            .map(([traceId, spans]) => {
                const rootSpan = spans.find((s) => !s.parentSpanId) || spans[0];
                return { traceId, rootSpan, spanCount: spans.length };
            })
            .sort((a, b) => b.rootSpan.startTime - a.rootSpan.startTime)
            .slice(0, limit);
    }

    /**
     * Gets span statistics
     */
    getStatistics(): {
        totalSpans: number;
        byKind: Record<string, number>;
        byStatus: Record<string, number>;
        averageLatency: number;
        p95Latency: number;
        p99Latency: number;
    } {
        const spans = this.exportedSpans;
        const byKind: Record<string, number> = {};
        const byStatus: Record<string, number> = {};
        const latencies: number[] = [];

        const kindNames = ['INTERNAL', 'SERVER', 'CLIENT', 'PRODUCER', 'CONSUMER'];

        for (const span of spans) {
            const kindName = kindNames[span.kind] || 'UNKNOWN';
            byKind[kindName] = (byKind[kindName] || 0) + 1;

            const statusName = span.status.code === SpanStatusCode.OK ? 'OK' : 'ERROR';
            byStatus[statusName] = (byStatus[statusName] || 0) + 1;

            if (span.endTime) {
                latencies.push(span.endTime - span.startTime);
            }
        }

        latencies.sort((a, b) => a - b);

        const percentile = (arr: number[], p: number): number => {
            if (arr.length === 0) return 0;
            const idx = Math.ceil(arr.length * p) - 1;
            return arr[Math.max(0, idx)];
        };

        return {
            totalSpans: spans.length,
            byKind,
            byStatus,
            averageLatency:
                latencies.length > 0
                    ? latencies.reduce((a, b) => a + b, 0) / latencies.length
                    : 0,
            p95Latency: percentile(latencies, 0.95),
            p99Latency: percentile(latencies, 0.99),
        };
    }

    /**
     * Clears exported spans
     */
    clearExportedSpans(): void {
        this.exportedSpans = [];
    }

    /**
     * Shuts down the tracer
     */
    async shutdown(): Promise<void> {
        if (this.provider) {
            await this.provider.shutdown();
            logger.info('Tracer shutdown complete');
        }
    }
}

/**
 * Creates a decorator for tracing methods
 */
export function TraceMethod(
    name?: string,
    options?: { kind?: SpanKind; attributes?: Attributes }
) {
    return function (
        _target: unknown,
        propertyKey: string,
        descriptor: PropertyDescriptor
    ) {
        const originalMethod = descriptor.value;
        const spanName = name || propertyKey;

        descriptor.value = async function (...args: unknown[]) {
            const tracer = trace.getTracer('apexmail');
            const span = tracer.startSpan(spanName, {
                kind: options?.kind || SpanKind.INTERNAL,
                attributes: options?.attributes,
            });

            try {
                const result = await context.with(
                    trace.setSpan(context.active(), span),
                    () => originalMethod.apply(this, args)
                );
                span.setStatus({ code: SpanStatusCode.OK });
                return result;
            } catch (error) {
                span.setStatus({
                    code: SpanStatusCode.ERROR,
                    message: error instanceof Error ? error.message : 'Unknown error',
                });
                span.recordException(error as Error);
                throw error;
            } finally {
                span.end();
            }
        };

        return descriptor;
    };
}
