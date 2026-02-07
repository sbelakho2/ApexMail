/**
 * Dashboard Service
 * 
 * Dashboard and visualization management:
 * - Dashboard definitions
 * - Widget configurations
 * - Real-time data streaming
 * - Dashboard sharing
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { Result, createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'observability:dashboards' });

export interface Dashboard {
  id: string;
  name: string;
  description: string;
  ownerId: string;
  isPublic: boolean;
  tags: string[];
  layout: DashboardLayout;
  variables: DashboardVariable[];
  timeRange: TimeRange;
  refreshInterval: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface DashboardLayout {
  rows: LayoutRow[];
}

export interface LayoutRow {
  height: number;
  panels: Panel[];
}

export interface Panel {
  id: string;
  title: string;
  description?: string;
  type: PanelType;
  gridPos: GridPosition;
  datasource: string;
  targets: PanelTarget[];
  options: Record<string, unknown>;
  fieldConfig?: FieldConfig;
  thresholds?: Threshold[];
  links?: PanelLink[];
}

export enum PanelType {
  GRAPH = 'graph',
  STAT = 'stat',
  GAUGE = 'gauge',
  BAR_GAUGE = 'bar-gauge',
  TABLE = 'table',
  TEXT = 'text',
  HEATMAP = 'heatmap',
  HISTOGRAM = 'histogram',
  LOGS = 'logs',
  ALERT_LIST = 'alert-list',
  PIE_CHART = 'pie-chart',
  TIME_SERIES = 'time-series',
  STATE_TIMELINE = 'state-timeline',
  NODE_GRAPH = 'node-graph',
}

export interface GridPosition {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface PanelTarget {
  refId: string;
  expr: string;
  legendFormat?: string;
  interval?: string;
}

export interface FieldConfig {
  defaults: {
    unit?: string;
    decimals?: number;
    min?: number;
    max?: number;
    color?: {
      mode: 'fixed' | 'thresholds' | 'palette';
      fixedColor?: string;
    };
  };
  overrides?: Array<{
    matcher: { id: string; options: string };
    properties: Array<{ id: string; value: unknown }>;
  }>;
}

export interface Threshold {
  value: number;
  color: string;
  state: string;
}

export interface PanelLink {
  title: string;
  url: string;
  targetBlank: boolean;
}

export interface DashboardVariable {
  name: string;
  type: 'query' | 'custom' | 'constant' | 'textbox' | 'interval';
  label?: string;
  current: {
    value: string | string[];
    text: string;
  };
  options?: Array<{ value: string; text: string }>;
  query?: string;
  multi?: boolean;
  includeAll?: boolean;
  refresh?: 'never' | 'on_dashboard_load' | 'on_time_range_change';
}

export interface TimeRange {
  from: string;
  to: string;
  raw: {
    from: string;
    to: string;
  };
}

export interface DashboardSnapshot {
  id: string;
  dashboardId: string;
  name: string;
  key: string;
  expiresAt: Date | null;
  data: Dashboard;
  createdAt: Date;
}

export interface DashboardPermission {
  dashboardId: string;
  userId?: string;
  teamId?: string;
  permission: 'view' | 'edit' | 'admin';
}

export class DashboardService {
  private db: Pool;
  private redis: Redis;
  private dashboards: Map<string, Dashboard> = new Map();
  private templateDashboards: Map<string, Dashboard> = new Map();

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
    this.initializeTemplateDashboards();
  }

  /**
   * Initialize template dashboards
   */
  private initializeTemplateDashboards(): void {
    // Email Overview Dashboard
    this.templateDashboards.set('email-overview', this.createEmailOverviewDashboard());
    
    // Delivery Performance Dashboard
    this.templateDashboards.set('delivery-performance', this.createDeliveryPerformanceDashboard());
    
    // Infrastructure Dashboard
    this.templateDashboards.set('infrastructure', this.createInfrastructureDashboard());
    
    // Security Dashboard
    this.templateDashboards.set('security', this.createSecurityDashboard());
    
    // Business Metrics Dashboard
    this.templateDashboards.set('business-metrics', this.createBusinessMetricsDashboard());
  }

  /**
   * Create a dashboard
   */
  async createDashboard(dashboard: Omit<Dashboard, 'id' | 'createdAt' | 'updatedAt'>): Promise<Result<Dashboard>> {
    const id = `dash_${Date.now()}`;
    const now = new Date();

    const fullDashboard: Dashboard = {
      ...dashboard,
      id,
      createdAt: now,
      updatedAt: now,
    };

    try {
      await this.db.query(`
        INSERT INTO obs_dashboards (
          id, name, description, owner_id, is_public, tags,
          layout, variables, time_range, refresh_interval,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        id,
        dashboard.name,
        dashboard.description,
        dashboard.ownerId,
        dashboard.isPublic,
        JSON.stringify(dashboard.tags),
        JSON.stringify(dashboard.layout),
        JSON.stringify(dashboard.variables),
        JSON.stringify(dashboard.timeRange),
        dashboard.refreshInterval,
        now,
        now,
      ]);

      this.dashboards.set(id, fullDashboard);

      logger.info(`[Dashboards] Created dashboard: ${dashboard.name}`);

      return { ok: true, value: fullDashboard };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get a dashboard
   */
  async getDashboard(id: string): Promise<Result<Dashboard>> {
    // Check cache first
    if (this.dashboards.has(id)) {
      return { ok: true, value: this.dashboards.get(id)! };
    }

    // Check templates
    if (this.templateDashboards.has(id)) {
      return { ok: true, value: this.templateDashboards.get(id)! };
    }

    try {
      const result = await this.db.query('SELECT * FROM obs_dashboards WHERE id = $1', [id]);
      
      if (result.rows.length === 0) {
        return { ok: false, error: new Error(`Dashboard not found: ${id}`) };
      }

      const dashboard = this.rowToDashboard(result.rows[0]);
      this.dashboards.set(id, dashboard);

      return { ok: true, value: dashboard };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update a dashboard
   */
  async updateDashboard(id: string, updates: Partial<Dashboard>): Promise<Result<Dashboard>> {
    const existing = await this.getDashboard(id);
    if (!existing.ok) {
      return existing;
    }

    const updatedDashboard: Dashboard = {
      ...existing.value,
      ...updates,
      id,
      createdAt: existing.value.createdAt,
      updatedAt: new Date(),
    };

    try {
      await this.db.query(`
        UPDATE obs_dashboards SET
          name = $2, description = $3, is_public = $4, tags = $5,
          layout = $6, variables = $7, time_range = $8, refresh_interval = $9,
          updated_at = $10
        WHERE id = $1
      `, [
        id,
        updatedDashboard.name,
        updatedDashboard.description,
        updatedDashboard.isPublic,
        JSON.stringify(updatedDashboard.tags),
        JSON.stringify(updatedDashboard.layout),
        JSON.stringify(updatedDashboard.variables),
        JSON.stringify(updatedDashboard.timeRange),
        updatedDashboard.refreshInterval,
        updatedDashboard.updatedAt,
      ]);

      this.dashboards.set(id, updatedDashboard);

      return { ok: true, value: updatedDashboard };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete a dashboard
   */
  async deleteDashboard(id: string): Promise<Result<void>> {
    try {
      await this.db.query('DELETE FROM obs_dashboards WHERE id = $1', [id]);
      this.dashboards.delete(id);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * List dashboards
   */
  async listDashboards(options?: {
    ownerId?: string;
    tags?: string[];
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<Result<{ dashboards: Dashboard[]; total: number }>> {
    try {
      let whereClause = '1=1';
      const params: (string | number)[] = [];
      let paramIndex = 1;

      if (options?.ownerId) {
        whereClause += ` AND owner_id = $${paramIndex++}`;
        params.push(options.ownerId);
      }

      if (options?.search) {
        whereClause += ` AND (name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`;
        params.push(`%${options.search}%`);
        paramIndex++;
      }

      if (options?.tags && options.tags.length > 0) {
        whereClause += ` AND tags ?| $${paramIndex++}`;
        params.push(JSON.stringify(options.tags));
      }

      const countResult = await this.db.query(
        `SELECT COUNT(*) as total FROM obs_dashboards WHERE ${whereClause}`,
        params
      );

      const result = await this.db.query(`
        SELECT * FROM obs_dashboards
        WHERE ${whereClause}
        ORDER BY updated_at DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `, [...params, options?.limit || 50, options?.offset || 0]);

      const dashboards = result.rows.map(row => this.rowToDashboard(row));

      return {
        ok: true,
        value: {
          dashboards,
          total: parseInt(countResult.rows[0]?.total ?? '0', 10),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create dashboard from template
   */
  async createFromTemplate(templateId: string, ownerId: string, name?: string): Promise<Result<Dashboard>> {
    const template = this.templateDashboards.get(templateId);
    if (!template) {
      return { ok: false, error: new Error(`Template not found: ${templateId}`) };
    }

    const dashboard: Omit<Dashboard, 'id' | 'createdAt' | 'updatedAt'> = {
      ...template,
      name: name || `${template.name} (Copy)`,
      ownerId,
      isPublic: false,
    };

    return this.createDashboard(dashboard);
  }

  /**
   * Create a snapshot
   */
  async createSnapshot(dashboardId: string, expiresInDays?: number): Promise<Result<DashboardSnapshot, Error>> {
    const dashboardResult = await this.getDashboard(dashboardId);
    if (!dashboardResult.ok) {
      return { ok: false, error: (dashboardResult as { ok: false; error: Error }).error };
    }

    const id = `snap_${Date.now()}`;
    const key = this.generateSnapshotKey();

    const snapshot: DashboardSnapshot = {
      id,
      dashboardId,
      name: dashboardResult.value.name,
      key,
      expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null,
      data: dashboardResult.value,
      createdAt: new Date(),
    };

    try {
      await this.db.query(`
        INSERT INTO obs_dashboard_snapshots (id, dashboard_id, name, key, expires_at, data, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [id, dashboardId, snapshot.name, key, snapshot.expiresAt, JSON.stringify(snapshot.data), snapshot.createdAt]);

      return { ok: true, value: snapshot };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get snapshot by key
   */
  async getSnapshotByKey(key: string): Promise<Result<DashboardSnapshot>> {
    try {
      const result = await this.db.query(`
        SELECT * FROM obs_dashboard_snapshots
        WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())
      `, [key]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Snapshot not found or expired') };
      }

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          dashboardId: row.dashboard_id,
          name: row.name,
          key: row.key,
          expiresAt: row.expires_at ? new Date(row.expires_at) : null,
          data: row.data,
          createdAt: new Date(row.created_at),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Add panel to dashboard
   */
  async addPanel(dashboardId: string, rowIndex: number, panel: Panel): Promise<Result<Dashboard>> {
    const dashboardResult = await this.getDashboard(dashboardId);
    if (!dashboardResult.ok) {
      return dashboardResult;
    }

    const dashboard = dashboardResult.value;
    
    // Ensure row exists
    while (dashboard.layout.rows.length <= rowIndex) {
      dashboard.layout.rows.push({ height: 8, panels: [] });
    }

    const row = dashboard.layout.rows[rowIndex];
    if (row) {
      row.panels.push(panel);
    }

    return this.updateDashboard(dashboardId, { layout: dashboard.layout });
  }

  /**
   * Remove panel from dashboard
   */
  async removePanel(dashboardId: string, panelId: string): Promise<Result<Dashboard>> {
    const dashboardResult = await this.getDashboard(dashboardId);
    if (!dashboardResult.ok) {
      return dashboardResult;
    }

    const dashboard = dashboardResult.value;

    for (const row of dashboard.layout.rows) {
      const index = row.panels.findIndex(p => p.id === panelId);
      if (index !== -1) {
        row.panels.splice(index, 1);
        break;
      }
    }

    return this.updateDashboard(dashboardId, { layout: dashboard.layout });
  }

  /**
   * Execute panel query
   */
  async executePanelQuery(panel: Panel, timeRange: TimeRange, variables: Record<string, string>): Promise<Result<{
    series: Array<{
      name: string;
      values: Array<{ time: Date; value: number }>;
    }>;
  }>> {
    try {
      const series = [];

      for (const target of panel.targets) {
        // Interpolate variables
        let expr = target.expr;
        for (const [key, value] of Object.entries(variables)) {
          expr = expr.replace(new RegExp(`\\$${key}`, 'g'), value);
        }

        // Parse time range
        const { from, to } = this.parseTimeRange(timeRange);

        // Execute query based on datasource
        const result = await this.executeMetricQuery(expr, from, to);

        series.push({
          name: target.legendFormat || target.refId,
          values: result,
        });
      }

      return { ok: true, value: { series } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Stream dashboard updates
   */
  async streamDashboardUpdates(dashboardId: string, callback: (data: unknown) => void): Promise<() => void> {
    const channel = `dashboard:${dashboardId}:updates`;
    
    const subscriber = this.redis.duplicate();
    await subscriber.subscribe(channel);

    subscriber.on('message', (_, message) => {
      try {
        callback(JSON.parse(message));
      } catch {
        callback(message);
      }
    });

    // Return unsubscribe function
    return async () => {
      await subscriber.unsubscribe(channel);
      await subscriber.quit();
    };
  }

  // Template dashboard definitions

  private createEmailOverviewDashboard(): Dashboard {
    return {
      id: 'email-overview',
      name: 'Email Overview',
      description: 'Overview of email sending metrics',
      ownerId: 'system',
      isPublic: true,
      tags: ['email', 'overview'],
      layout: {
        rows: [
          {
            height: 4,
            panels: [
              this.createStatPanel('sent-today', 'Emails Sent Today', 'apexmail_emails_sent_total', 0, 0, 6, 4),
              this.createStatPanel('delivered-today', 'Delivered Today', 'apexmail_emails_delivered_total', 6, 0, 6, 4),
              this.createStatPanel('bounce-rate', 'Bounce Rate', 'apexmail_bounce_rate', 12, 0, 6, 4, '%'),
              this.createStatPanel('delivery-rate', 'Delivery Rate', 'apexmail_delivery_rate', 18, 0, 6, 4, '%'),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('email-volume', 'Email Volume Over Time', [
                { refId: 'A', expr: 'rate(apexmail_emails_sent_total[5m])', legendFormat: 'Sent' },
                { refId: 'B', expr: 'rate(apexmail_emails_delivered_total[5m])', legendFormat: 'Delivered' },
              ], 0, 4, 12, 8),
              this.createPieChartPanel('status-breakdown', 'Status Breakdown', 'apexmail_email_status', 12, 4, 12, 8),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTablePanel('top-domains', 'Top Sending Domains', 'topk(10, sum by (domain) (apexmail_emails_sent_total))', 0, 12, 12, 8),
              this.createBarGaugePanel('delivery-by-provider', 'Delivery by Provider', 'sum by (provider) (apexmail_deliveries_total)', 12, 12, 12, 8),
            ],
          },
        ],
      },
      variables: [
        {
          name: 'workspace',
          type: 'query',
          label: 'Workspace',
          current: { value: '$__all', text: 'All' },
          query: 'label_values(apexmail_emails_sent_total, workspace_id)',
          includeAll: true,
        },
      ],
      timeRange: {
        from: 'now-6h',
        to: 'now',
        raw: { from: 'now-6h', to: 'now' },
      },
      refreshInterval: 30,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private createDeliveryPerformanceDashboard(): Dashboard {
    return {
      id: 'delivery-performance',
      name: 'Delivery Performance',
      description: 'Email delivery performance and latency metrics',
      ownerId: 'system',
      isPublic: true,
      tags: ['delivery', 'performance'],
      layout: {
        rows: [
          {
            height: 4,
            panels: [
              this.createStatPanel('avg-latency', 'Avg Delivery Latency', 'apexmail_delivery_latency_seconds', 0, 0, 6, 4, 's'),
              this.createStatPanel('p99-latency', 'P99 Latency', 'histogram_quantile(0.99, apexmail_delivery_latency_bucket)', 6, 0, 6, 4, 's'),
              this.createStatPanel('queue-depth', 'Queue Depth', 'apexmail_queue_depth', 12, 0, 6, 4),
              this.createStatPanel('throughput', 'Throughput/min', 'rate(apexmail_emails_sent_total[1m])*60', 18, 0, 6, 4),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('latency-over-time', 'Delivery Latency Over Time', [
                { refId: 'A', expr: 'histogram_quantile(0.5, rate(apexmail_delivery_latency_bucket[5m]))', legendFormat: 'P50' },
                { refId: 'B', expr: 'histogram_quantile(0.95, rate(apexmail_delivery_latency_bucket[5m]))', legendFormat: 'P95' },
                { refId: 'C', expr: 'histogram_quantile(0.99, rate(apexmail_delivery_latency_bucket[5m]))', legendFormat: 'P99' },
              ], 0, 4, 24, 8),
            ],
          },
          {
            height: 8,
            panels: [
              this.createHeatmapPanel('latency-heatmap', 'Latency Distribution', 'rate(apexmail_delivery_latency_bucket[5m])', 0, 12, 12, 8),
              this.createTimeSeriesPanel('queue-metrics', 'Queue Metrics', [
                { refId: 'A', expr: 'apexmail_queue_depth', legendFormat: 'Depth' },
                { refId: 'B', expr: 'rate(apexmail_queue_processed_total[5m])', legendFormat: 'Processed/s' },
              ], 12, 12, 12, 8),
            ],
          },
        ],
      },
      variables: [],
      timeRange: {
        from: 'now-3h',
        to: 'now',
        raw: { from: 'now-3h', to: 'now' },
      },
      refreshInterval: 15,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private createInfrastructureDashboard(): Dashboard {
    return {
      id: 'infrastructure',
      name: 'Infrastructure',
      description: 'System infrastructure metrics',
      ownerId: 'system',
      isPublic: true,
      tags: ['infrastructure', 'system'],
      layout: {
        rows: [
          {
            height: 4,
            panels: [
              this.createGaugePanel('cpu-usage', 'CPU Usage', 'apexmail_cpu_usage_percent', 0, 0, 6, 4, '%'),
              this.createGaugePanel('memory-usage', 'Memory Usage', 'apexmail_memory_usage_percent', 6, 0, 6, 4, '%'),
              this.createStatPanel('active-connections', 'Active Connections', 'apexmail_active_connections', 12, 0, 6, 4),
              this.createStatPanel('uptime', 'Uptime', 'apexmail_uptime_seconds', 18, 0, 6, 4, 's'),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('resource-usage', 'Resource Usage', [
                { refId: 'A', expr: 'apexmail_cpu_usage_percent', legendFormat: 'CPU %' },
                { refId: 'B', expr: 'apexmail_memory_usage_percent', legendFormat: 'Memory %' },
              ], 0, 4, 12, 8),
              this.createTimeSeriesPanel('network-io', 'Network I/O', [
                { refId: 'A', expr: 'rate(apexmail_network_bytes_received[5m])', legendFormat: 'Received' },
                { refId: 'B', expr: 'rate(apexmail_network_bytes_sent[5m])', legendFormat: 'Sent' },
              ], 12, 4, 12, 8),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('db-metrics', 'Database Metrics', [
                { refId: 'A', expr: 'apexmail_db_pool_active', legendFormat: 'Active Connections' },
                { refId: 'B', expr: 'rate(apexmail_db_queries_total[5m])', legendFormat: 'Queries/s' },
              ], 0, 12, 12, 8),
              this.createTimeSeriesPanel('redis-metrics', 'Redis Metrics', [
                { refId: 'A', expr: 'apexmail_redis_connections', legendFormat: 'Connections' },
                { refId: 'B', expr: 'rate(apexmail_redis_commands_total[5m])', legendFormat: 'Commands/s' },
              ], 12, 12, 12, 8),
            ],
          },
        ],
      },
      variables: [
        {
          name: 'instance',
          type: 'query',
          label: 'Instance',
          current: { value: '$__all', text: 'All' },
          query: 'label_values(apexmail_uptime_seconds, instance)',
          includeAll: true,
        },
      ],
      timeRange: {
        from: 'now-1h',
        to: 'now',
        raw: { from: 'now-1h', to: 'now' },
      },
      refreshInterval: 10,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private createSecurityDashboard(): Dashboard {
    return {
      id: 'security',
      name: 'Security',
      description: 'Security and authentication metrics',
      ownerId: 'system',
      isPublic: true,
      tags: ['security', 'authentication'],
      layout: {
        rows: [
          {
            height: 4,
            panels: [
              this.createStatPanel('auth-failures', 'Auth Failures (24h)', 'increase(apexmail_auth_failures_total[24h])', 0, 0, 6, 4),
              this.createStatPanel('rate-limited', 'Rate Limited (1h)', 'increase(apexmail_rate_limited_total[1h])', 6, 0, 6, 4),
              this.createStatPanel('api-key-usage', 'API Keys in Use', 'apexmail_api_keys_active', 12, 0, 6, 4),
              this.createStatPanel('blocked-ips', 'Blocked IPs', 'apexmail_blocked_ips_total', 18, 0, 6, 4),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('auth-events', 'Authentication Events', [
                { refId: 'A', expr: 'rate(apexmail_auth_success_total[5m])', legendFormat: 'Success' },
                { refId: 'B', expr: 'rate(apexmail_auth_failures_total[5m])', legendFormat: 'Failures' },
              ], 0, 4, 12, 8),
              this.createTablePanel('top-failed-ips', 'Top Failed Auth IPs', 'topk(10, sum by (ip) (apexmail_auth_failures_total))', 12, 4, 12, 8),
            ],
          },
          {
            height: 6,
            panels: [
              this.createAlertListPanel('security-alerts', 'Security Alerts', 0, 12, 24, 6),
            ],
          },
        ],
      },
      variables: [],
      timeRange: {
        from: 'now-24h',
        to: 'now',
        raw: { from: 'now-24h', to: 'now' },
      },
      refreshInterval: 60,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private createBusinessMetricsDashboard(): Dashboard {
    return {
      id: 'business-metrics',
      name: 'Business Metrics',
      description: 'Business and usage metrics',
      ownerId: 'system',
      isPublic: true,
      tags: ['business', 'usage'],
      layout: {
        rows: [
          {
            height: 4,
            panels: [
              this.createStatPanel('active-workspaces', 'Active Workspaces', 'apexmail_active_workspaces', 0, 0, 6, 4),
              this.createStatPanel('total-users', 'Total Users', 'apexmail_users_total', 6, 0, 6, 4),
              this.createStatPanel('emails-today', 'Emails Today', 'increase(apexmail_emails_sent_total[24h])', 12, 0, 6, 4),
              this.createStatPanel('revenue-today', 'Revenue Today', 'increase(apexmail_revenue_total[24h])', 18, 0, 6, 4, 'currencyUSD'),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTimeSeriesPanel('usage-trend', 'Usage Trend', [
                { refId: 'A', expr: 'rate(apexmail_emails_sent_total[1h])', legendFormat: 'Emails/hour' },
                { refId: 'B', expr: 'apexmail_active_users', legendFormat: 'Active Users' },
              ], 0, 4, 12, 8),
              this.createPieChartPanel('usage-by-plan', 'Usage by Plan', 'sum by (plan) (apexmail_emails_sent_total)', 12, 4, 12, 8),
            ],
          },
          {
            height: 8,
            panels: [
              this.createTablePanel('top-workspaces', 'Top Workspaces by Volume', 'topk(10, sum by (workspace) (apexmail_emails_sent_total))', 0, 12, 24, 8),
            ],
          },
        ],
      },
      variables: [],
      timeRange: {
        from: 'now-7d',
        to: 'now',
        raw: { from: 'now-7d', to: 'now' },
      },
      refreshInterval: 300,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  // Panel factory methods

  private createStatPanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number, unit?: string): Panel {
    return {
      id,
      title,
      type: PanelType.STAT,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: {
        reduceOptions: { calcs: ['lastNotNull'], fields: '' },
        colorMode: 'value',
        graphMode: 'none',
      },
      fieldConfig: {
        defaults: { unit: unit || 'short' },
      },
    };
  }

  private createGaugePanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number, unit?: string): Panel {
    return {
      id,
      title,
      type: PanelType.GAUGE,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: { showThresholdLabels: false, showThresholdMarkers: true },
      fieldConfig: {
        defaults: { unit: unit || 'percent', min: 0, max: 100 },
      },
      thresholds: [
        { value: 0, color: 'green', state: 'ok' },
        { value: 70, color: 'yellow', state: 'warning' },
        { value: 90, color: 'red', state: 'critical' },
      ],
    };
  }

  private createTimeSeriesPanel(id: string, title: string, targets: PanelTarget[], x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.TIME_SERIES,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets,
      options: {
        legend: { displayMode: 'list', placement: 'bottom' },
        tooltip: { mode: 'multi', sort: 'desc' },
      },
    };
  }

  private createTablePanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.TABLE,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: { showHeader: true, sortBy: [{ displayName: 'Value', desc: true }] },
    };
  }

  private createPieChartPanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.PIE_CHART,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: {
        pieType: 'pie',
        displayLabels: ['name', 'percent'],
        legend: { displayMode: 'list', placement: 'right' },
      },
    };
  }

  private createBarGaugePanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.BAR_GAUGE,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: { displayMode: 'lcd', orientation: 'horizontal' },
    };
  }

  private createHeatmapPanel(id: string, title: string, expr: string, x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.HEATMAP,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [{ refId: 'A', expr }],
      options: {
        calculate: false,
        yAxis: { unit: 's' },
        color: { mode: 'spectrum', scheme: 'Oranges' },
      },
    };
  }

  private createAlertListPanel(id: string, title: string, x: number, y: number, w: number, h: number): Panel {
    return {
      id,
      title,
      type: PanelType.ALERT_LIST,
      gridPos: { x, y, w, h },
      datasource: 'prometheus',
      targets: [],
      options: {
        showOptions: 'current',
        sortOrder: 3,
        stateFilter: { alerting: true, pending: true },
      },
    };
  }

  // Helper methods

  private rowToDashboard(row: Record<string, unknown>): Dashboard {
    return {
      id: row.id as string,
      name: row.name as string,
      description: row.description as string,
      ownerId: row.owner_id as string,
      isPublic: row.is_public as boolean,
      tags: (row.tags as string[]) || [],
      layout: (row.layout as DashboardLayout) || { rows: [] },
      variables: (row.variables as DashboardVariable[]) || [],
      timeRange: (row.time_range as TimeRange) || {
        from: 'now-6h',
        to: 'now',
        raw: { from: 'now-6h', to: 'now' },
      },
      refreshInterval: row.refresh_interval as number || 30,
      createdAt: new Date(row.created_at as string),
      updatedAt: new Date(row.updated_at as string),
    };
  }

  private generateSnapshotKey(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
  }

  private parseTimeRange(timeRange: TimeRange): { from: Date; to: Date } {
    const now = new Date();
    
    const parseRelative = (str: string): Date => {
      const match = str.match(/now(-(\d+)([hdwMy]))?/);
      if (!match) return now;
      if (!match[1]) return now;

      const value = parseInt(match[2] ?? '0');
      const unit = match[3] ?? 'd';
      const date = new Date(now);

      switch (unit) {
        case 'h': date.setHours(date.getHours() - value); break;
        case 'd': date.setDate(date.getDate() - value); break;
        case 'w': date.setDate(date.getDate() - value * 7); break;
        case 'M': date.setMonth(date.getMonth() - value); break;
        case 'y': date.setFullYear(date.getFullYear() - value); break;
      }

      return date;
    };

    return {
      from: parseRelative(timeRange.from),
      to: parseRelative(timeRange.to),
    };
  }

  private async executeMetricQuery(expr: string, from: Date, to: Date): Promise<Array<{ time: Date; value: number }>> {
    // Extract metric name from expression
    const metricMatch = expr.match(/\w+/);
    if (!metricMatch) return [];

    const metricName = metricMatch[0];

    try {
      const result = await this.db.query(`
        SELECT recorded_at, value
        FROM obs_metrics
        WHERE name = $1 AND recorded_at BETWEEN $2 AND $3
        ORDER BY recorded_at
        LIMIT 1000
      `, [metricName, from, to]);

      return result.rows.map(row => ({
        time: new Date(row.recorded_at),
        value: parseFloat(row.value),
      }));
    } catch {
      return [];
    }
  }

  /**
   * Get list of available template dashboards
   */
  getTemplateDashboards(): Array<{ id: string; name: string; description: string }> {
    return Array.from(this.templateDashboards.entries()).map(([id, dash]) => ({
      id,
      name: dash.name,
      description: dash.description,
    }));
  }
}
