/**
 * Observability Routes
 * 
 * HTTP endpoints for observability features
 */

import { Hono } from 'hono';
import { TracingService } from '../services/tracing.js';
import { MetricsService, MetricType } from '../services/metrics.js';
import { LoggingService, LogLevel, type LogEntry } from '../services/logging.js';
import { AlertingService, AlertSeverity, AlertStatus } from '../services/alerting.js';
import { DashboardService } from '../services/dashboards.js';

export function createObservabilityRoutes(
  tracing: TracingService,
  metrics: MetricsService,
  logging: LoggingService,
  alerting: AlertingService,
  dashboards: DashboardService
): Hono {
  const app = new Hono();

  // ==================== Tracing Routes ====================

  /**
   * Search traces
   */
  app.get('/traces', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();
    const service = c.req.query('service');
    const operation = c.req.query('operation');
    const minDuration = c.req.query('minDuration') 
      ? parseInt(c.req.query('minDuration')!) 
      : undefined;
    const tags = c.req.query('tags') 
      ? JSON.parse(c.req.query('tags')!) 
      : undefined;
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 100;

    const result = await tracing.searchTraces({
      startTime,
      endTime,
      service,
      operation,
      minDuration,
      tags,
      limit,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get trace by ID
   */
  app.get('/traces/:traceId', async (c) => {
    const traceId = c.req.param('traceId');
    const result = await tracing.getTrace(traceId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Get trace statistics
   */
  app.get('/traces/stats', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();

    const result = await tracing.getTraceStats({ startTime, endTime });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  // ==================== Metrics Routes ====================

  /**
   * Prometheus metrics endpoint
   */
  app.get('/metrics', async (c) => {
    const metricsOutput = await metrics.getPrometheusMetrics();
    c.header('Content-Type', 'text/plain; version=0.0.4');
    return c.text(metricsOutput);
  });

  /**
   * Query metrics
   */
  app.get('/metrics/query', async (c) => {
    const name = c.req.query('name');
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();
    const labels = c.req.query('labels') 
      ? JSON.parse(c.req.query('labels')!) 
      : undefined;

    const result = await metrics.queryMetrics({
      name,
      startTime,
      endTime,
      labels,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get metric aggregation
   */
  app.get('/metrics/aggregate', async (c) => {
    const name = c.req.query('name');
    if (!name) {
      return c.json({ error: 'Metric name is required' }, 400);
    }

    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();
    const aggregation = (c.req.query('aggregation') || 'avg') as 'sum' | 'avg' | 'min' | 'max' | 'count';
    const groupBy = c.req.query('groupBy')?.split(',');
    const interval = c.req.query('interval');

    const result = await metrics.aggregate({
      name,
      startTime,
      endTime,
      aggregation,
      groupBy,
      interval,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * List available metrics
   */
  app.get('/metrics/list', async (c) => {
    const result = await metrics.listMetrics();

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Record custom metric
   */
  app.post('/metrics', async (c) => {
    const body = await c.req.json();

    if (!body.name || body.value === undefined) {
      return c.json({ error: 'Name and value are required' }, 400);
    }

    const result = await metrics.recordMetric({
      name: body.name,
      type: body.type || MetricType.GAUGE,
      value: body.value,
      labels: body.labels || {},
      timestamp: body.timestamp ? new Date(body.timestamp) : new Date(),
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json({ success: true });
  });

  // ==================== Logging Routes ====================

  /**
   * Query logs
   */
  app.get('/logs', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();
    const level = c.req.query('level') as LogLevel | undefined;
    const service = c.req.query('service');
    const search = c.req.query('search');
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 100;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    const result = await logging.queryLogs({
      startTime,
      endTime,
      level,
      service,
      search,
      limit,
      offset,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get log statistics
   */
  app.get('/logs/stats', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 3600000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();

    const result = await logging.getLogStats({ startTime, endTime });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get log context
   */
  app.get('/logs/:logId/context', async (c) => {
    const logId = c.req.param('logId');
    const lines = c.req.query('lines') ? parseInt(c.req.query('lines')!) : 10;

    const result = await logging.getLogContext(logId, lines);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Stream logs (SSE)
   */
  app.get('/logs/stream', async (c) => {
    const level = c.req.query('level') as LogLevel | undefined;
    const service = c.req.query('service');
    void c.req.query('filter'); // Reserved for future text filtering

    // Set up SSE
    c.header('Content-Type', 'text/event-stream');
    c.header('Cache-Control', 'no-cache');
    c.header('Connection', 'keep-alive');

    // Create readable stream
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const subscription = await logging.streamLogs(
          (log: LogEntry) => {
            const data = `data: ${JSON.stringify(log)}\n\n`;
            controller.enqueue(encoder.encode(data));
          },
          { service, minLevel: level }
        );

        // Clean up on close
        c.req.raw.signal.addEventListener('abort', () => {
          subscription.unsubscribe();
          controller.close();
        });
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    });
  });

  // ==================== Alerting Routes ====================

  /**
   * List alert rules
   */
  app.get('/alerts/rules', async (c) => {
    // Get rules from database
    return c.json({ rules: [] }); // Would query from alerting service
  });

  /**
   * Create alert rule
   */
  app.post('/alerts/rules', async (c) => {
    const body = await c.req.json();

    const result = await alerting.createRule({
      name: body.name,
      description: body.description,
      enabled: body.enabled ?? true,
      expression: body.expression,
      duration: body.duration || 300,
      severity: body.severity || AlertSeverity.WARNING,
      labels: body.labels || {},
      annotations: body.annotations || {},
      notificationChannels: body.notificationChannels || [],
      runbook: body.runbook,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Update alert rule
   */
  app.put('/alerts/rules/:ruleId', async (c) => {
    const ruleId = c.req.param('ruleId');
    const body = await c.req.json();

    const result = await alerting.updateRule(ruleId, body);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Delete alert rule
   */
  app.delete('/alerts/rules/:ruleId', async (c) => {
    const ruleId = c.req.param('ruleId');

    const result = await alerting.deleteRule(ruleId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json({ success: true });
  });

  /**
   * Get active alerts
   */
  app.get('/alerts', async (c) => {
    const severity = c.req.query('severity') as AlertSeverity | undefined;
    const status = c.req.query('status') as AlertStatus | undefined;
    const ruleId = c.req.query('ruleId');

    const result = await alerting.getActiveAlerts({ severity, status, ruleId });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get alert history
   */
  app.get('/alerts/history', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 86400000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 100;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    const result = await alerting.getAlertHistory({ startTime, endTime, limit, offset });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get alert statistics
   */
  app.get('/alerts/stats', async (c) => {
    const startTime = c.req.query('startTime') 
      ? new Date(c.req.query('startTime')!) 
      : new Date(Date.now() - 86400000);
    const endTime = c.req.query('endTime') 
      ? new Date(c.req.query('endTime')!) 
      : new Date();

    const result = await alerting.getAlertStats({ startTime, endTime });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Fire manual alert
   */
  app.post('/alerts', async (c) => {
    const body = await c.req.json();

    const result = await alerting.fireAlert({
      ruleName: body.ruleName || 'Manual Alert',
      severity: body.severity || AlertSeverity.WARNING,
      summary: body.summary,
      description: body.description,
      labels: body.labels,
      value: body.value,
      threshold: body.threshold,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Acknowledge alert
   */
  app.post('/alerts/:alertId/acknowledge', async (c) => {
    const alertId = c.req.param('alertId');
    const body = await c.req.json();

    const result = await alerting.acknowledgeAlert(alertId, body.userId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Resolve alert
   */
  app.post('/alerts/:alertId/resolve', async (c) => {
    const alertId = c.req.param('alertId');

    const result = await alerting.resolveAlert(alertId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Create silence
   */
  app.post('/alerts/silences', async (c) => {
    const body = await c.req.json();

    const result = await alerting.createSilence({
      matchers: body.matchers,
      startsAt: new Date(body.startsAt),
      endsAt: new Date(body.endsAt),
      createdBy: body.createdBy,
      comment: body.comment,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Create notification channel
   */
  app.post('/alerts/channels', async (c) => {
    const body = await c.req.json();

    const result = await alerting.createChannel({
      name: body.name,
      type: body.type,
      config: body.config,
      enabled: body.enabled ?? true,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // ==================== Dashboard Routes ====================

  /**
   * List dashboards
   */
  app.get('/dashboards', async (c) => {
    const ownerId = c.req.query('ownerId');
    const tags = c.req.query('tags')?.split(',');
    const search = c.req.query('search');
    const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50;
    const offset = c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0;

    const result = await dashboards.listDashboards({ ownerId, tags, search, limit, offset });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Get dashboard templates
   */
  app.get('/dashboards/templates', async (c) => {
    const templates = dashboards.getTemplateDashboards();
    return c.json({ templates });
  });

  /**
   * Create dashboard
   */
  app.post('/dashboards', async (c) => {
    const body = await c.req.json();

    const result = await dashboards.createDashboard({
      name: body.name,
      description: body.description,
      ownerId: body.ownerId,
      isPublic: body.isPublic ?? false,
      tags: body.tags || [],
      layout: body.layout || { rows: [] },
      variables: body.variables || [],
      timeRange: body.timeRange || {
        from: 'now-6h',
        to: 'now',
        raw: { from: 'now-6h', to: 'now' },
      },
      refreshInterval: body.refreshInterval || 30,
    });

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Create dashboard from template
   */
  app.post('/dashboards/from-template', async (c) => {
    const body = await c.req.json();

    const result = await dashboards.createFromTemplate(
      body.templateId,
      body.ownerId,
      body.name
    );

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 400);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get dashboard
   */
  app.get('/dashboards/:dashboardId', async (c) => {
    const dashboardId = c.req.param('dashboardId');

    const result = await dashboards.getDashboard(dashboardId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Update dashboard
   */
  app.put('/dashboards/:dashboardId', async (c) => {
    const dashboardId = c.req.param('dashboardId');
    const body = await c.req.json();

    const result = await dashboards.updateDashboard(dashboardId, body);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  /**
   * Delete dashboard
   */
  app.delete('/dashboards/:dashboardId', async (c) => {
    const dashboardId = c.req.param('dashboardId');

    const result = await dashboards.deleteDashboard(dashboardId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json({ success: true });
  });

  /**
   * Add panel to dashboard
   */
  app.post('/dashboards/:dashboardId/panels', async (c) => {
    const dashboardId = c.req.param('dashboardId');
    const body = await c.req.json();

    const result = await dashboards.addPanel(dashboardId, body.rowIndex || 0, body.panel);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Remove panel from dashboard
   */
  app.delete('/dashboards/:dashboardId/panels/:panelId', async (c) => {
    const dashboardId = c.req.param('dashboardId');
    const panelId = c.req.param('panelId');

    const result = await dashboards.removePanel(dashboardId, panelId);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Execute panel query
   */
  app.post('/dashboards/:dashboardId/panels/:panelId/query', async (c) => {
    const dashboardId = c.req.param('dashboardId');
    const panelId = c.req.param('panelId');
    const body = await c.req.json();

    // Get dashboard and panel
    const dashResult = await dashboards.getDashboard(dashboardId);
    if (!dashResult.ok) {
      return c.json({ error: dashResult.error.message }, 404);
    }

    // Find panel
    let panel = null;
    for (const row of dashResult.value.layout.rows) {
      panel = row.panels.find(p => p.id === panelId);
      if (panel) break;
    }

    if (!panel) {
      return c.json({ error: 'Panel not found' }, 404);
    }

    const result = await dashboards.executePanelQuery(
      panel,
      body.timeRange || dashResult.value.timeRange,
      body.variables || {}
    );

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value);
  });

  /**
   * Create snapshot
   */
  app.post('/dashboards/:dashboardId/snapshots', async (c) => {
    const dashboardId = c.req.param('dashboardId');
    const body = await c.req.json();

    const result = await dashboards.createSnapshot(dashboardId, body.expiresInDays);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  /**
   * Get snapshot by key
   */
  app.get('/snapshots/:key', async (c) => {
    const key = c.req.param('key');

    const result = await dashboards.getSnapshotByKey(key);

    if (!result.ok) {
      return c.json({ error: (result as { ok: false; error: Error }).error.message }, 404);
    }

    return c.json(result.value);
  });

  return app;
}
