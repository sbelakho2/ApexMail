/**
 * @apexmail/ops - HTTP API Routes
 * 
 * Hono-based HTTP routes for operations endpoints.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger as honoLogger } from 'hono/logger';
import { timing } from 'hono/timing';
import { SLOManager } from './slo/manager.js';
import { MetricsCollector } from './metrics/collector.js';
import { AlertManager } from './alerts/manager.js';
import { IncidentManager } from './incidents/manager.js';
import { StatusPageService } from './status/page.js';
import { TrustCenterService } from './trust/center.js';
import { HealthChecker } from './health/checker.js';
import { TracingService } from './tracing/tracer.js';
import { WarmupManager } from './warmup/manager.js';

export interface OpsServices {
    slo: SLOManager;
    metrics: MetricsCollector;
    alerts: AlertManager;
    incidents: IncidentManager;
    statusPage: StatusPageService;
    trustCenter: TrustCenterService;
    health: HealthChecker;
    tracing: TracingService;
    warmup?: WarmupManager;
}

export function createOpsRoutes(services: OpsServices): Hono {
    const app = new Hono();

    // Middleware
    app.use('*', cors({
        exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    }));
    app.use('*', honoLogger());
    app.use('*', timing());

    // FIX-500-026: Auth middleware for all non-health ops routes
    app.use('/api/*', async (c, next) => {
        const apiKey = c.req.header('x-api-key') || c.req.header('authorization')?.replace('Bearer ', '');
        const expectedKey = process.env.OPS_API_KEY || process.env.INTERNAL_API_KEY;
        if (!expectedKey) {
            return c.json({ error: 'OPS_API_KEY not configured' }, 500);
        }
        if (!apiKey || apiKey !== expectedKey) {
            return c.json({ error: 'Unauthorized' }, 401);
        }
        await next();
    });

    // Health endpoints
    app.get('/health', async (c) => {
        const overall = services.health.getOverallHealth();
        return c.json({
            status: overall.status,
            timestamp: new Date().toISOString(),
        });
    });

    app.get('/health/detailed', async (c) => {
        const report = await services.health.deepHealthCheck();
        return c.json(report);
    });

    app.get('/health/ready', async (c) => {
        const overall = services.health.getOverallHealth();
        if (overall.status === 'unhealthy') {
            return c.json({ ready: false }, 503);
        }
        return c.json({ ready: true });
    });

    app.get('/health/live', (c) => {
        return c.json({ alive: true });
    });

    // Metrics endpoints
    app.get('/metrics', async (c) => {
        const metrics = await services.metrics.getPrometheusMetrics();
        return c.text(metrics, 200, {
            'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        });
    });

    app.get('/metrics/json', (c) => {
        const metrics = services.metrics.getMetricsJSON();
        return c.json(metrics);
    });

    // SLO endpoints
    app.get('/slo', (c) => {
        const slos = services.slo.getAllStatuses();
        return c.json({ slos });
    });

    app.get('/slo/:id', (c) => {
        const status = services.slo.getStatus(c.req.param('id'));
        if (!status) {
            return c.json({ error: 'SLO not found' }, 404);
        }
        return c.json(status);
    });

    app.get('/slo/:id/history', (c) => {
        const status = services.slo.getStatus(c.req.param('id'));
        if (!status) {
            return c.json({ error: 'SLO not found' }, 404);
        }
        const report = services.slo.getErrorBudgetReport(c.req.param('id'));
        return c.json({ sloId: c.req.param('id'), history: report });
    });

    app.get('/slo/report/summary', (c) => {
        const statuses = services.slo.getAllStatuses();
        return c.json({ statuses });
    });

    // Alert endpoints
    app.get('/alerts', (c) => {
        const active = services.alerts.getActiveAlerts();
        return c.json({ alerts: active, count: active.length });
    });

    app.get('/alerts/history', (c) => {
        const limit = parseInt(c.req.query('limit') || '50', 10) || 50;
        const offset = parseInt(c.req.query('offset') || '0', 10) || 0;
        const history = services.alerts.getAlertHistory({ limit, offset });
        return c.json({ alerts: history });
    });

    app.get('/alerts/rules', (c) => {
        const rules = services.alerts.getRules();
        return c.json({ rules });
    });

    app.get('/alerts/stats', (c) => {
        const stats = services.alerts.getStatistics();
        return c.json(stats);
    });

    app.post('/alerts/:id/acknowledge', async (c) => {
        const body = await c.req.json<{ acknowledgedBy: string }>();
        services.alerts.acknowledgeAlert(c.req.param('id'), body.acknowledgedBy);
        return c.json({ success: true });
    });

    app.post('/alerts/:id/resolve', async (c) => {
        const body = await c.req.json<{ resolvedBy?: string }>();
        services.alerts.resolveAlert(c.req.param('id'), body.resolvedBy);
        return c.json({ success: true });
    });

    app.post('/alerts/:id/silence', async (c) => {
        const body = await c.req.json<{ duration: number; silencedBy: string; reason: string }>();
        services.alerts.silenceAlert(
            c.req.param('id'),
            body.duration,
            body.silencedBy,
            body.reason
        );
        return c.json({ success: true });
    });

    // Incident endpoints
    app.get('/incidents', (c) => {
        const active = services.incidents.getActiveIncidents();
        return c.json({ incidents: active, count: active.length });
    });

    app.get('/incidents/history', (c) => {
        const limit = parseInt(c.req.query('limit') || '50', 10) || 50;
        const offset = parseInt(c.req.query('offset') || '0', 10) || 0;
        const history = services.incidents.getHistory({ limit, offset });
        return c.json({ incidents: history });
    });

    app.get('/incidents/:id', (c) => {
        const data = services.incidents.exportIncident(c.req.param('id'));
        if (!data.incident) {
            return c.json({ error: 'Incident not found' }, 404);
        }
        return c.json(data);
    });

    app.get('/incidents/:id/timeline', (c) => {
        const timeline = services.incidents.getTimeline(c.req.param('id'));
        if (!timeline) {
            return c.json({ error: 'Incident not found' }, 404);
        }
        return c.json(timeline);
    });

    app.post('/incidents', async (c) => {
        const body = await c.req.json<{
            title: string;
            description: string;
            severity: 'critical' | 'high' | 'medium' | 'low' | 'sev1' | 'sev2' | 'sev3' | 'sev4';
            affectedServices: string[];
            reportedBy: string;
        }>();
        const incident = services.incidents.createIncident(body);
        return c.json(incident, 201);
    });

    app.post('/incidents/:id/status', async (c) => {
        const body = await c.req.json<{
            status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
            message: string;
            updatedBy: string;
        }>();
        services.incidents.updateStatus(
            c.req.param('id'),
            body.status,
            body.message,
            body.updatedBy
        );
        return c.json({ success: true });
    });

    app.post('/incidents/:id/note', async (c) => {
        const body = await c.req.json<{ content: string; author: string }>();
        services.incidents.addNote(c.req.param('id'), body.content, body.author);
        return c.json({ success: true });
    });

    app.get('/incidents/stats', (c) => {
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        const stats = services.incidents.getStatistics({
            start: thirtyDaysAgo,
            end: now,
        });
        return c.json(stats);
    });

    // Status page endpoints
    app.get('/status', (c) => {
        const data = services.statusPage.getStatusPageData();
        return c.json(data);
    });

    app.get('/status/components', (c) => {
        const data = services.statusPage.getStatusPageData();
        return c.json({ components: data.components, groups: data.groups });
    });

    app.get('/status/incidents', (c) => {
        const limit = parseInt(c.req.query('limit') || '10', 10) || 10;
        const offset = parseInt(c.req.query('offset') || '0', 10) || 0;
        const includeResolved = c.req.query('includeResolved') !== 'false';
        const incidents = services.statusPage.getIncidentHistory({
            limit,
            offset,
            includeResolved,
        });
        return c.json({ incidents });
    });

    app.get('/status/maintenance', (c) => {
        const maintenance = services.statusPage.getMaintenanceHistory({
            status: ['scheduled', 'in_progress'],
        });
        return c.json({ maintenance });
    });

    app.post('/status/subscribe', async (c) => {
        const body = await c.req.json<{ email: string; components?: string[] }>();
        const id = services.statusPage.addSubscriber(body.email, body.components);
        return c.json({ subscriberId: id });
    });

    app.post('/status/subscribe/:id/confirm', (c) => {
        const success = services.statusPage.confirmSubscriber(c.req.param('id'));
        return c.json({ success });
    });

    app.delete('/status/subscribe/:id', (c) => {
        services.statusPage.removeSubscriber(c.req.param('id'));
        return c.json({ success: true });
    });

    // Trust center endpoints
    app.get('/trust', (c) => {
        const data = services.trustCenter.getTrustCenterData();
        return c.json(data);
    });

    app.get('/trust/certifications', (c) => {
        const certs = services.trustCenter.getValidCertifications();
        return c.json({ certifications: certs });
    });

    app.get('/trust/documents', (c) => {
        const type = c.req.query('type') as 'policy' | 'agreement' | 'whitepaper' | 'guide' | 'disclosure' | undefined;
        const docs = services.trustCenter.getDocuments(type);
        return c.json({ documents: docs });
    });

    app.get('/trust/security', (c) => {
        const category = c.req.query('category');
        const controls = services.trustCenter.getSecurityControls(category);
        const categories = services.trustCenter.getSecurityControlCategories();
        return c.json({ controls, categories });
    });

    app.get('/trust/subprocessors', (c) => {
        const processors = services.trustCenter.getSubProcessors();
        return c.json({ subProcessors: processors });
    });

    app.get('/trust/faq', (c) => {
        const category = c.req.query('category');
        const faq = services.trustCenter.getFAQ(category);
        const categories = services.trustCenter.getFAQCategories();
        return c.json({ faq, categories });
    });

    app.get('/trust/summary', (c) => {
        const summary = services.trustCenter.generateComplianceSummary();
        return c.json(summary);
    });

    // Tracing endpoints
    app.get('/traces', (c) => {
        const limit = parseInt(c.req.query('limit') || '20', 10) || 20;
        const traces = services.tracing.getRecentTraces(limit);
        return c.json({ traces });
    });

    app.get('/traces/:traceId', (c) => {
        const spans = services.tracing.getTrace(c.req.param('traceId'));
        if (spans.length === 0) {
            return c.json({ error: 'Trace not found' }, 404);
        }
        return c.json({ traceId: c.req.param('traceId'), spans });
    });

    app.get('/traces/stats', (c) => {
        const stats = services.tracing.getStatistics();
        return c.json(stats);
    });

    // Admin endpoints
    app.post('/admin/alerts/rules/:id/enable', (c) => {
        services.alerts.enableRule(c.req.param('id'));
        return c.json({ success: true });
    });

    app.post('/admin/alerts/rules/:id/disable', (c) => {
        services.alerts.disableRule(c.req.param('id'));
        return c.json({ success: true });
    });

    app.post('/admin/status/component/:id', async (c) => {
        const body = await c.req.json<{ status: 'operational' | 'degraded' | 'partial_outage' | 'major_outage' | 'maintenance'; reason?: string }>();
        services.statusPage.updateComponentStatus(
            c.req.param('id'),
            body.status,
            body.reason
        );
        return c.json({ success: true });
    });

    app.post('/admin/status/incident', async (c) => {
        const body = await c.req.json<{
            title: string;
            impact: 'none' | 'minor' | 'major' | 'critical';
            affectedComponents: string[];
            message: string;
        }>();
        const incident = services.statusPage.createIncident(body);
        return c.json(incident, 201);
    });

    app.post('/admin/status/incident/:id/update', async (c) => {
        const body = await c.req.json<{
            status?: 'investigating' | 'identified' | 'monitoring' | 'resolved';
            message: string;
            author?: string;
        }>();
        const incident = services.statusPage.updateIncident(c.req.param('id'), body);
        if (!incident) {
            return c.json({ error: 'Incident not found' }, 404);
        }
        return c.json(incident);
    });

    app.post('/admin/status/maintenance', async (c) => {
        const body = await c.req.json<{
            title: string;
            description: string;
            scheduledStart: string;
            scheduledEnd: string;
            affectedComponents: string[];
        }>();
        const maintenance = services.statusPage.scheduleMaintenance({
            ...body,
            scheduledStart: new Date(body.scheduledStart),
            scheduledEnd: new Date(body.scheduledEnd),
        });
        return c.json(maintenance, 201);
    });

    app.post('/admin/health/check/:id/enable', (c) => {
        services.health.enableCheck(c.req.param('id'));
        return c.json({ success: true });
    });

    app.post('/admin/health/check/:id/disable', (c) => {
        services.health.disableCheck(c.req.param('id'));
        return c.json({ success: true });
    });

    app.post('/admin/health/check/:id/force', async (c) => {
        const state = await services.health.forceCheck(c.req.param('id'));
        if (!state) {
            return c.json({ error: 'Check not found' }, 404);
        }
        return c.json(state);
    });

    // ========================================
    // IP WARMUP MANAGEMENT ENDPOINTS
    // ========================================

    // Get warmup schedule info
    app.get('/warmup/schedules', (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        return c.json(services.warmup.getWarmupScheduleInfo());
    });

    // Get all IP pools status
    app.get('/warmup/pools', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        const pools = await services.warmup.getAllPoolsStatus();
        return c.json({ pools });
    });

    // Get warmup status for a specific pool
    app.get('/warmup/pools/:poolId', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        const ips = await services.warmup.getPoolWarmupStatus(c.req.param('poolId'));
        return c.json({ ips });
    });

    // Trigger daily warmup advancement (for cron job or manual run)
    app.post('/warmup/advance', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        const result = await services.warmup.runDailyAdvancement();
        return c.json(result);
    });

    // Start warmup for an IP
    app.post('/warmup/ip/:ipAddress/start', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        await services.warmup.startIPWarmup(c.req.param('ipAddress'));
        return c.json({ success: true, message: 'Warmup started' });
    });

    // Pause warmup for an IP
    app.post('/warmup/ip/:ipAddress/pause', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        await services.warmup.pauseIPWarmup(c.req.param('ipAddress'));
        return c.json({ success: true, message: 'Warmup paused' });
    });

    // Reset warmup for an IP
    app.post('/warmup/ip/:ipAddress/reset', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        await services.warmup.resetIPWarmup(c.req.param('ipAddress'));
        return c.json({ success: true, message: 'Warmup reset' });
    });

    // Set warmup day manually
    app.post('/warmup/ip/:ipAddress/day', async (c) => {
        if (!services.warmup) {
            return c.json({ error: 'Warmup service not configured' }, 503);
        }
        const body = await c.req.json<{ day: number }>();
        if (typeof body.day !== 'number' || body.day < 0) {
            return c.json({ error: 'Invalid day value' }, 400);
        }
        await services.warmup.setWarmupDay(c.req.param('ipAddress'), body.day);
        return c.json({ success: true, message: `Warmup day set to ${body.day}` });
    });

    // Dashboard data endpoint
    app.get('/dashboard', async (c) => {
        const [healthReport, sloStatuses, activeAlerts, activeIncidents, statusData] = await Promise.all([
            services.health.deepHealthCheck(),
            Promise.resolve(services.slo.getAllStatuses()),
            Promise.resolve(services.alerts.getActiveAlerts()),
            Promise.resolve(services.incidents.getActiveIncidents()),
            Promise.resolve(services.statusPage.getStatusPageData()),
        ]);

        return c.json({
            health: healthReport,
            slos: {
                statuses: sloStatuses,
                atRisk: sloStatuses.filter((s: { status: string }) => s.status === 'at_risk').length,
                breached: sloStatuses.filter((s: { status: string }) => s.status === 'breached').length,
            },
            alerts: {
                active: activeAlerts.length,
                bySeverity: services.alerts.getStatistics().bySeverity,
            },
            incidents: {
                active: activeIncidents.length,
                bySeverity: activeIncidents.reduce((acc, i) => {
                    acc[i.severity] = (acc[i.severity] || 0) + 1;
                    return acc;
                }, {} as Record<string, number>),
            },
            status: {
                overall: statusData.overallStatus,
                uptime: statusData.uptime,
            },
            timestamp: new Date().toISOString(),
        });
    });

    return app;
}
