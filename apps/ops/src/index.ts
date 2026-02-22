/**
 * @apexmail/ops - Operations & SLO Module
 * 
 * Comprehensive operations infrastructure including:
 * - SLO/SLI management with error budgets
 * - Prometheus-compatible metrics collection
 * - Alert management with escalation
 * - Incident management with workflows
 * - Status page service
 * - Trust center
 * - Health checks
 * - Distributed tracing
 */

import { serve } from '@hono/node-server';
import { Pool } from 'pg';
import { createLogger } from '@apexmail/lib';

// Export all modules
export * from './types.js';
export * from './slo/index.js';
export * from './metrics/index.js';
export * from './alerts/index.js';
export * from './incidents/index.js';
export { StatusPageService } from './status/index.js';
export * from './trust/index.js';
export * from './health/index.js';
export * from './tracing/index.js';
export { createOpsRoutes, type OpsServices } from './routes.js';

// Import for initialization
import { SLOManager } from './slo/manager.js';
import { MetricsCollector } from './metrics/collector.js';
import { AlertManager } from './alerts/manager.js';
import { IncidentManager } from './incidents/manager.js';
import { StatusPageService } from './status/page.js';
import { TrustCenterService } from './trust/center.js';
import { HealthChecker } from './health/checker.js';
import { TracingService } from './tracing/tracer.js';
import { createOpsRoutes, OpsServices } from './routes.js';

const logger = createLogger({ name: 'apexmail-ops' });

export interface OpsConfig {
    serviceName: string;
    serviceVersion: string;
    environment: string;
    port: number;
    metricsEnabled: boolean;
    tracingEnabled: boolean;
    tracingEndpoint?: string;
    tracingSampleRate: number;
    statusPageUrl: string;
    companyName: string;
    supportEmail: string;
    dpoEmail: string;
}

/**
 * Creates and configures all ops services
 * FIX-500-155/156: Accepts optional DB pool for persistent storage.
 */
export function createOpsServices(config: OpsConfig, db?: Pool): OpsServices {
    // Metrics Collector (needs to be created first for SLOManager)
    const metrics = new MetricsCollector({
        prefix: 'apexmail',
        defaultLabels: {
            service: config.serviceName,
            version: config.serviceVersion,
            environment: config.environment,
        },
        collectDefaultMetrics: true,
    });

    // SLO Manager
    const slo = new SLOManager(metrics, {
        refreshIntervalMs: 60000, // 1 minute
    });

    // Alert Manager
    const alerts = new AlertManager({
        defaultChannels: ['slack', 'email'],
        escalationTimeoutMs: 15 * 60 * 1000, // 15 minutes
        deduplicationWindowMs: 5 * 60 * 1000, // 5 minutes
        maxActiveAlerts: 100,
    });

    // Incident Manager
    const incidents = new IncidentManager({
        autoCreateFromAlerts: true,
        criticalAlertThreshold: 2,
        slackChannelPrefix: 'inc',
        postMortemDueDays: 5,
    });

    // Status Page Service
    const statusPage = new StatusPageService({
        publicUrl: config.statusPageUrl,
        companyName: config.companyName,
        supportUrl: `mailto:${config.supportEmail}`,
        timezone: 'UTC',
        allowSubscriptions: true,
    }, db);

    // Trust Center Service
    const trustCenter = new TrustCenterService({
        publicUrl: `${config.statusPageUrl}/trust`,
        companyName: config.companyName,
        legalEntity: `${config.companyName}, Inc.`,
        supportEmail: config.supportEmail,
        dpoEmail: config.dpoEmail,
    }, db);

    // Health Checker
    const health = new HealthChecker({
        interval: 30000,
        timeout: 5000,
        unhealthyThreshold: 3,
        healthyThreshold: 2,
    });

    // Tracing Service
    const tracing = new TracingService({
        serviceName: config.serviceName,
        serviceVersion: config.serviceVersion,
        environment: config.environment,
        endpoint: config.tracingEndpoint,
        sampleRate: config.tracingSampleRate,
        enabled: config.tracingEnabled,
    });

    // Wire up event handlers
    wireEventHandlers({
        slo,
        metrics,
        alerts,
        incidents,
        statusPage,
        trustCenter,
        health,
        tracing,
    });

    return {
        slo,
        metrics,
        alerts,
        incidents,
        statusPage,
        trustCenter,
        health,
        tracing,
    };
}

/**
 * Wires up event handlers between services
 */
function wireEventHandlers(services: OpsServices): void {
    const { slo, metrics, alerts, incidents, statusPage, health } = services;

    // SLO events -> Metrics
    slo.on('slo:evaluated', (data) => {
        metrics.setSLOValue(data.sloId, data.currentValue);
        metrics.setSLOErrorBudget(data.sloId, data.errorBudgetRemaining);
    });

    // SLO events -> Alerts
    slo.on('slo:breached', (data) => {
        alerts.evaluateMetric('slo.breached', 1, { slo_id: data.sloId });
    });

    // Alert events -> Metrics
    alerts.on('alert:triggered', (alert) => {
        metrics.incrementAlertCounter(alert.severity, 'triggered');
    });

    alerts.on('alert:resolved', (alert) => {
        metrics.incrementAlertCounter(alert.severity, 'resolved');
    });

    // Alert events -> Incidents (auto-create for critical)
    alerts.on('alert:triggered', (alert) => {
        if (alert.severity === 'critical') {
            incidents.createFromAlert(alert);
        }
    });

    // Incident events -> Status page
    incidents.on('incident:created', (incident) => {
        statusPage.createIncident({
            title: incident.title,
            impact: incident.severity === 'critical' ? 'critical' : 
                   incident.severity === 'high' ? 'major' : 'minor',
            affectedComponents: incident.affectedServices,
            message: incident.description,
        });
    });

    // Health events -> Status page
    health.on('status:changed', (data) => {
        const componentMap: Record<string, string> = {
            'api-internal': 'api',
            'email-service': 'email-sending',
            'worker-service': 'webhooks',
            'database-primary': 'api',
            'redis-cache': 'api',
        };

        const componentId = componentMap[data.checkId];
        if (componentId) {
            const status = data.newStatus === 'healthy' ? 'operational' :
                          data.newStatus === 'degraded' ? 'degraded' : 'partial_outage';
            statusPage.updateComponentStatus(componentId, status);
        }
    });

    // Health events -> Metrics
    health.on('check:completed', (data) => {
        metrics.recordHealthCheck(data.checkId, data.result.healthy, data.result.latency || 0);
    });

    logger.info('Event handlers wired up');
}

/**
 * Starts the ops server
 */
export function startOpsServer(
    services: OpsServices,
    port: number
): void {
    const app = createOpsRoutes(services);

    // Start health checker
    services.health.start();

    // Start SLO evaluation
    services.slo.start();

    serve({
        fetch: app.fetch,
        port,
    });

    logger.info('Ops server started', { port });
}

/**
 * Main entry point
 */
export async function main(): Promise<void> {
    const config: OpsConfig = {
        serviceName: process.env.SERVICE_NAME || 'apexmail',
        serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        port: parseInt(process.env.OPS_PORT || '9095'), // Changed from 9090 to avoid conflict with worker metrics
        metricsEnabled: process.env.METRICS_ENABLED !== 'false',
        tracingEnabled: process.env.TRACING_ENABLED !== 'false',
        tracingEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
        tracingSampleRate: parseFloat(process.env.TRACING_SAMPLE_RATE || '0.1'),
        statusPageUrl: process.env.STATUS_PAGE_URL || 'https://status.apexmail.ee',
        companyName: process.env.COMPANY_NAME || 'ApexMail',
        supportEmail: process.env.SUPPORT_EMAIL || 'support@apexmail.ee',
        dpoEmail: process.env.DPO_EMAIL || 'dpo@apexmail.ee',
    };

    logger.info('Starting ops services', { config: { ...config, tracingEndpoint: '***' } });

    // FIX-500-155/156: Create DB pool for persistent storage
    const db = new Pool({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME || 'apexmail',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        max: 5,
    });

    const services = createOpsServices(config, db);

    // FIX-500-155/156: Load persistent state from DB
    await services.statusPage.loadFromDb();
    await services.trustCenter.loadFromDb();

    startOpsServer(services, config.port);

    // Graceful shutdown
    // FIX-500-236/238/239: Extract shared shutdown logic and include alertManager.stop()
    const shutdown = async (signal: string) => {
        logger.info(`Received ${signal}, shutting down`);
        services.alerts.stop();
        services.health.stop();
        services.slo.stop();
        await services.tracing.shutdown();
        await db.end();
        process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch((error) => {
        logger.error('Failed to start ops services', { error });
        process.exit(1);
    });
}
