/**
 * Alerting Service
 * 
 * Alert management and notification:
 * - Alert rules
 * - Notification channels
 * - Alert grouping and deduplication
 * - Escalation policies
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { Result, createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'observability:alerting' });

export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  CRITICAL = 'critical',
  EMERGENCY = 'emergency',
}

export enum AlertStatus {
  PENDING = 'pending',
  FIRING = 'firing',
  RESOLVED = 'resolved',
  ACKNOWLEDGED = 'acknowledged',
  SILENCED = 'silenced',
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  expression: string;
  duration: number;
  severity: AlertSeverity;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  notificationChannels: string[];
  runbook?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  status: AlertStatus;
  severity: AlertSeverity;
  summary: string;
  description: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  value: number;
  threshold: number;
  firedAt: Date;
  resolvedAt: Date | null;
  acknowledgedAt: Date | null;
  acknowledgedBy: string | null;
  silencedUntil: Date | null;
  notificationsSent: number;
  lastNotificationAt: Date | null;
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: 'slack' | 'email' | 'pagerduty' | 'opsgenie' | 'webhook' | 'sms';
  config: Record<string, unknown>;
  enabled: boolean;
  createdAt: Date;
}

export interface Silence {
  id: string;
  matchers: Array<{
    name: string;
    value: string;
    isRegex: boolean;
  }>;
  startsAt: Date;
  endsAt: Date;
  createdBy: string;
  comment: string;
}

export interface EscalationPolicy {
  id: string;
  name: string;
  steps: Array<{
    delayMinutes: number;
    channels: string[];
    repeatInterval?: number;
  }>;
}

export class AlertingService {
  private db: Pool;
  private redis: Redis;
  private rules: Map<string, AlertRule> = new Map();
  private channels: Map<string, NotificationChannel> = new Map();
  private silences: Map<string, Silence> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private evaluationInterval: NodeJS.Timeout | null = null;

  /** Max entries in each local-cache Map to prevent unbounded growth */
  private static readonly MAX_LOCAL_RULES = 10_000;
  private static readonly MAX_LOCAL_CHANNELS = 1_000;
  private static readonly MAX_LOCAL_SILENCES = 10_000;
  private static readonly MAX_LOCAL_ALERTS = 50_000;
  /** Redis key prefix for notification cooldowns */
  private static readonly COOLDOWN_PREFIX = 'alert:cooldown:';

  /**
   * FIX-500-186: Track consecutive evaluation failures per rule.
   * After MAX_CONSECUTIVE_FAILURES, the rule is temporarily disabled until a
   * successful evaluation resets the counter.
   */
  private readonly ruleFailureCounts = new Map<string, number>();
  private static readonly MAX_CONSECUTIVE_FAILURES = 5;

  constructor(db: Pool, redis: Redis) {
    this.db = db;
    this.redis = redis;
  }

  /**
   * Enforce a size cap on a Map by evicting the oldest entry (first key).
   * Uses insertion-order semantics of ES2015 Maps as a simple FIFO eviction.
   */
  private enforceMapCap<K, V>(map: Map<K, V>, max: number): void {
    while (map.size > max) {
      const firstKey = map.keys().next().value;
      if (firstKey !== undefined) map.delete(firstKey);
      else break;
    }
  }

  /**
   * Initialize alerting service
   */
  async initialize(): Promise<void> {
    if (!config.alerting.enabled) {
      logger.info('[Alerting] Alerting is disabled');
      return;
    }

    // Load rules, channels, and silences
    await this.loadRules();
    await this.loadChannels();
    await this.loadSilences();
    await this.loadActiveAlerts();

    // Start evaluation loop with proper error handling
    this.evaluationInterval = setInterval(() => {
      this.evaluateRules().catch(err => {
        logger.error('[Alerting] Rule evaluation failed:', { error: err instanceof Error ? err.message : String(err) });
      });
    }, 60000);

    logger.info('[Alerting] Service initialized');
  }

  /**
   * Create an alert rule
   *
   * G-219: Validates alert thresholds and durations before persisting.
   */
  async createRule(rule: Omit<AlertRule, 'id' | 'createdAt' | 'updatedAt'>): Promise<Result<AlertRule>> {
    // G-219: Validate alert rule parameters
    const validationError = this.validateRuleParams(rule);
    if (validationError) {
      return { ok: false, error: new Error(validationError) };
    }

    const id = `rule_${Date.now()}`;
    const now = new Date();

    const fullRule: AlertRule = {
      ...rule,
      id,
      createdAt: now,
      updatedAt: now,
    };

    try {
      await this.db.query(`
        INSERT INTO obs_alert_rules (
          id, name, description, enabled, expression, duration,
          severity, labels, annotations, notification_channels, runbook,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      `, [
        id,
        rule.name,
        rule.description,
        rule.enabled,
        rule.expression,
        rule.duration,
        rule.severity,
        JSON.stringify(rule.labels),
        JSON.stringify(rule.annotations),
        JSON.stringify(rule.notificationChannels),
        rule.runbook,
        now,
        now,
      ]);

      this.rules.set(id, fullRule);
      this.enforceMapCap(this.rules, AlertingService.MAX_LOCAL_RULES);

      logger.info(`[Alerting] Created rule: ${rule.name}`);

      return { ok: true, value: fullRule };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Update an alert rule
   *
   * G-219: Validates updated thresholds and durations before persisting.
   */
  async updateRule(id: string, updates: Partial<AlertRule>): Promise<Result<AlertRule>> {
    const rule = this.rules.get(id);
    if (!rule) {
      return { ok: false, error: new Error(`Rule not found: ${id}`) };
    }

    const updatedRule: AlertRule = {
      ...rule,
      ...updates,
      id,
      createdAt: rule.createdAt,
      updatedAt: new Date(),
    };

    // G-219: Re-validate merged rule before persisting
    const validationError = this.validateRuleParams(updatedRule);
    if (validationError) {
      return { ok: false, error: new Error(validationError) };
    }

    try {
      await this.db.query(`
        UPDATE obs_alert_rules SET
          name = $2, description = $3, enabled = $4, expression = $5,
          duration = $6, severity = $7, labels = $8, annotations = $9,
          notification_channels = $10, runbook = $11, updated_at = $12
        WHERE id = $1
      `, [
        id,
        updatedRule.name,
        updatedRule.description,
        updatedRule.enabled,
        updatedRule.expression,
        updatedRule.duration,
        updatedRule.severity,
        JSON.stringify(updatedRule.labels),
        JSON.stringify(updatedRule.annotations),
        JSON.stringify(updatedRule.notificationChannels),
        updatedRule.runbook,
        updatedRule.updatedAt,
      ]);

      this.rules.set(id, updatedRule);
      this.enforceMapCap(this.rules, AlertingService.MAX_LOCAL_RULES);

      return { ok: true, value: updatedRule };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Delete an alert rule
   */
  async deleteRule(id: string): Promise<Result<void>> {
    try {
      await this.db.query('DELETE FROM obs_alert_rules WHERE id = $1', [id]);
      this.rules.delete(id);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create a notification channel
   */
  async createChannel(channel: Omit<NotificationChannel, 'id' | 'createdAt'>): Promise<Result<NotificationChannel>> {
    const id = `channel_${Date.now()}`;

    const fullChannel: NotificationChannel = {
      ...channel,
      id,
      createdAt: new Date(),
    };

    try {
      await this.db.query(`
        INSERT INTO obs_notification_channels (id, name, type, config, enabled, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [id, channel.name, channel.type, JSON.stringify(channel.config), channel.enabled, fullChannel.createdAt]);

      this.channels.set(id, fullChannel);
      this.enforceMapCap(this.channels, AlertingService.MAX_LOCAL_CHANNELS);

      logger.info(`[Alerting] Created channel: ${channel.name}`);

      return { ok: true, value: fullChannel };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Fire an alert manually
   *
   * G-219: Validates threshold/value when provided.
   */
  async fireAlert(options: {
    ruleId?: string;
    ruleName: string;
    severity: AlertSeverity;
    summary: string;
    description: string;
    labels?: Record<string, string>;
    value?: number;
    threshold?: number;
  }): Promise<Result<Alert>> {
    // G-219: Validate threshold and value if provided
    if (options.threshold !== undefined) {
      if (typeof options.threshold !== 'number' || !isFinite(options.threshold) || options.threshold < 0) {
        return { ok: false, error: new Error('G-219: Alert threshold must be a finite non-negative number') };
      }
      if (options.threshold > 1_000_000_000) {
        return { ok: false, error: new Error('G-219: Alert threshold exceeds maximum allowed value (1,000,000,000)') };
      }
    }
    if (options.value !== undefined) {
      if (typeof options.value !== 'number' || !isFinite(options.value)) {
        return { ok: false, error: new Error('G-219: Alert value must be a finite number') };
      }
    }

    const id = `alert_${Date.now()}`;

    const alert: Alert = {
      id,
      ruleId: options.ruleId || 'manual',
      ruleName: options.ruleName,
      status: AlertStatus.FIRING,
      severity: options.severity,
      summary: options.summary,
      description: options.description,
      labels: options.labels || {},
      annotations: {},
      value: options.value || 0,
      threshold: options.threshold || 0,
      firedAt: new Date(),
      resolvedAt: null,
      acknowledgedAt: null,
      acknowledgedBy: null,
      silencedUntil: null,
      notificationsSent: 0,
      lastNotificationAt: null,
    };

    // Check if silenced
    if (this.isAlertSilenced(alert)) {
      alert.status = AlertStatus.SILENCED;
    }

    try {
      await this.saveAlert(alert);
      this.activeAlerts.set(id, alert);
      this.enforceMapCap(this.activeAlerts, AlertingService.MAX_LOCAL_ALERTS);

      // Send notifications
      if (alert.status === AlertStatus.FIRING) {
        await this.sendNotifications(alert);
      }

      // Publish event
      await this.redis.publish('alerts:fired', JSON.stringify(alert));

      logger.info(`[Alerting] Alert fired: ${alert.summary}`);

      return { ok: true, value: alert };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Resolve an alert
   */
  async resolveAlert(alertId: string): Promise<Result<Alert>> {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      return { ok: false, error: new Error(`Alert not found: ${alertId}`) };
    }

    alert.status = AlertStatus.RESOLVED;
    alert.resolvedAt = new Date();

    try {
      await this.saveAlert(alert);
      
      // Send resolution notification
      await this.sendNotifications(alert, 'resolved');

      // Publish event
      await this.redis.publish('alerts:resolved', JSON.stringify(alert));

      logger.info(`[Alerting] Alert resolved: ${alert.summary}`);

      return { ok: true, value: alert };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(alertId: string, userId: string): Promise<Result<Alert>> {
    const alert = this.activeAlerts.get(alertId);
    if (!alert) {
      return { ok: false, error: new Error(`Alert not found: ${alertId}`) };
    }

    alert.status = AlertStatus.ACKNOWLEDGED;
    alert.acknowledgedAt = new Date();
    alert.acknowledgedBy = userId;

    try {
      await this.saveAlert(alert);

      // Publish event
      await this.redis.publish('alerts:acknowledged', JSON.stringify(alert));

      logger.info(`[Alerting] Alert acknowledged by ${userId}: ${alert.summary}`);

      return { ok: true, value: alert };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create a silence
   */
  async createSilence(silence: Omit<Silence, 'id'>): Promise<Result<Silence>> {
    const id = `silence_${Date.now()}`;

    const fullSilence: Silence = {
      ...silence,
      id,
    };

    try {
      await this.db.query(`
        INSERT INTO obs_silences (id, matchers, starts_at, ends_at, created_by, comment)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        id,
        JSON.stringify(silence.matchers),
        silence.startsAt,
        silence.endsAt,
        silence.createdBy,
        silence.comment,
      ]);

      this.silences.set(id, fullSilence);
      this.enforceMapCap(this.silences, AlertingService.MAX_LOCAL_SILENCES);

      // Check and silence matching active alerts
      for (const alert of this.activeAlerts.values()) {
        if (this.matchesSilence(alert, fullSilence)) {
          alert.status = AlertStatus.SILENCED;
          alert.silencedUntil = silence.endsAt;
          await this.saveAlert(alert);
        }
      }

      logger.info(`[Alerting] Created silence: ${silence.comment}`);

      return { ok: true, value: fullSilence };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get active alerts
   */
  async getActiveAlerts(options?: {
    severity?: AlertSeverity;
    status?: AlertStatus;
    ruleId?: string;
  }): Promise<Result<Alert[]>> {
    let alerts = Array.from(this.activeAlerts.values());

    if (options?.severity) {
      alerts = alerts.filter(a => a.severity === options.severity);
    }
    if (options?.status) {
      alerts = alerts.filter(a => a.status === options.status);
    }
    if (options?.ruleId) {
      alerts = alerts.filter(a => a.ruleId === options.ruleId);
    }

    return { ok: true, value: alerts };
  }

  /**
   * Get alert history
   */
  async getAlertHistory(options: {
    startTime: Date;
    endTime: Date;
    limit?: number;
    offset?: number;
  }): Promise<Result<{ alerts: Alert[]; total: number }>> {
    try {
      const countResult = await this.db.query(`
        SELECT COUNT(*) as total FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
      `, [options.startTime, options.endTime]);

      const result = await this.db.query(`
        SELECT * FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
        ORDER BY fired_at DESC
        LIMIT $3 OFFSET $4
      `, [options.startTime, options.endTime, options.limit || 100, options.offset || 0]);

      const alerts: Alert[] = result.rows.map(row => ({
        id: row.id,
        ruleId: row.rule_id,
        ruleName: row.rule_name,
        status: row.status,
        severity: row.severity,
        summary: row.summary,
        description: row.description,
        labels: row.labels || {},
        annotations: row.annotations || {},
        value: row.value,
        threshold: row.threshold,
        firedAt: new Date(row.fired_at),
        resolvedAt: row.resolved_at ? new Date(row.resolved_at) : null,
        acknowledgedAt: row.acknowledged_at ? new Date(row.acknowledged_at) : null,
        acknowledgedBy: row.acknowledged_by,
        silencedUntil: row.silenced_until ? new Date(row.silenced_until) : null,
        notificationsSent: row.notifications_sent,
        lastNotificationAt: row.last_notification_at ? new Date(row.last_notification_at) : null,
      }));

      return {
        ok: true,
        value: {
          alerts,
          total: parseInt(countResult.rows[0]?.total ?? '0', 10),
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get alert statistics
   */
  async getAlertStats(options: {
    startTime: Date;
    endTime: Date;
  }): Promise<Result<{
    totalAlerts: number;
    bySeverity: Record<string, number>;
    byRule: Array<{ ruleId: string; ruleName: string; count: number }>;
    averageTTAcknowledge: number;
    averageTTResolve: number;
    currentlyFiring: number;
  }>> {
    try {
      // By severity
      const severityResult = await this.db.query(`
        SELECT severity, COUNT(*) as count
        FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
        GROUP BY severity
      `, [options.startTime, options.endTime]);

      // By rule
      const ruleResult = await this.db.query(`
        SELECT rule_id, rule_name, COUNT(*) as count
        FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
        GROUP BY rule_id, rule_name
        ORDER BY count DESC
        LIMIT 20
      `, [options.startTime, options.endTime]);

      // Average times
      const timesResult = await this.db.query(`
        SELECT 
          AVG(EXTRACT(EPOCH FROM (acknowledged_at - fired_at))) as avg_tta,
          AVG(EXTRACT(EPOCH FROM (resolved_at - fired_at))) as avg_ttr
        FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
          AND acknowledged_at IS NOT NULL
      `, [options.startTime, options.endTime]);

      // Total count
      const totalResult = await this.db.query(`
        SELECT COUNT(*) as total FROM obs_alerts
        WHERE fired_at >= $1 AND fired_at <= $2
      `, [options.startTime, options.endTime]);

      const bySeverity: Record<string, number> = {};
      for (const row of severityResult.rows) {
        bySeverity[row.severity] = parseInt(row.count);
      }

      const currentlyFiring = Array.from(this.activeAlerts.values())
        .filter(a => a.status === AlertStatus.FIRING).length;

      return {
        ok: true,
        value: {
          totalAlerts: parseInt(totalResult.rows[0]?.total ?? '0', 10),
          bySeverity,
          byRule: ruleResult.rows.map(row => ({
            ruleId: row.rule_id,
            ruleName: row.rule_name,
            count: parseInt(row.count, 10),
          })),
          averageTTAcknowledge: parseFloat(timesResult.rows[0]?.avg_tta) || 0,
          averageTTResolve: parseFloat(timesResult.rows[0]?.avg_ttr) || 0,
          currentlyFiring,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  // Private methods

  /**
   * G-219: Validate alert rule parameters — duration and expression thresholds.
   * Returns an error message string if invalid, or null if valid.
   */
  private validateRuleParams(rule: Partial<AlertRule>): string | null {
    // Duration must be a positive integer (seconds)
    if (rule.duration !== undefined) {
      if (typeof rule.duration !== 'number' || !isFinite(rule.duration) || rule.duration < 0) {
        return 'G-219: Alert rule duration must be a finite non-negative number (seconds)';
      }
      // Cap at 7 days — longer durations are almost certainly a misconfiguration
      if (rule.duration > 604800) {
        return 'G-219: Alert rule duration exceeds maximum of 604800 seconds (7 days)';
      }
    }

    // Validate expression threshold if present
    if (rule.expression) {
      const match = rule.expression.match(/(>|<|>=|<=|==)\s*([\d.]+)/);
      if (match) {
        const threshold = parseFloat(match[2] ?? '');
        if (!isFinite(threshold) || threshold < 0) {
          return 'G-219: Alert expression threshold must be a finite non-negative number';
        }
        if (threshold > 1_000_000_000) {
          return 'G-219: Alert expression threshold exceeds maximum allowed value (1,000,000,000)';
        }
      }
    }

    // Name must not be empty
    if (rule.name !== undefined && (!rule.name || rule.name.trim().length === 0)) {
      return 'G-219: Alert rule name must not be empty';
    }

    return null;
  }

  private async loadRules(): Promise<void> {
    try {
      const result = await this.db.query('SELECT * FROM obs_alert_rules WHERE enabled = true');
      for (const row of result.rows) {
        const rule: AlertRule = {
          id: row.id,
          name: row.name,
          description: row.description,
          enabled: row.enabled,
          expression: row.expression,
          duration: row.duration,
          severity: row.severity,
          labels: row.labels || {},
          annotations: row.annotations || {},
          notificationChannels: row.notification_channels || [],
          runbook: row.runbook,
          createdAt: new Date(row.created_at),
          updatedAt: new Date(row.updated_at),
        };
        this.rules.set(rule.id, rule);
      }
    } catch (error) {
      logger.warn('[Alerting] Could not load rules:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async loadChannels(): Promise<void> {
    try {
      const result = await this.db.query('SELECT * FROM obs_notification_channels WHERE enabled = true');
      for (const row of result.rows) {
        const channel: NotificationChannel = {
          id: row.id,
          name: row.name,
          type: row.type,
          config: row.config || {},
          enabled: row.enabled,
          createdAt: new Date(row.created_at),
        };
        this.channels.set(channel.id, channel);
      }
    } catch (error) {
      logger.warn('[Alerting] Could not load channels:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async loadSilences(): Promise<void> {
    try {
      const result = await this.db.query(`
        SELECT * FROM obs_silences WHERE ends_at > NOW()
      `);
      for (const row of result.rows) {
        const silence: Silence = {
          id: row.id,
          matchers: row.matchers || [],
          startsAt: new Date(row.starts_at),
          endsAt: new Date(row.ends_at),
          createdBy: row.created_by,
          comment: row.comment,
        };
        this.silences.set(silence.id, silence);
      }
    } catch (error) {
      logger.warn('[Alerting] Could not load silences:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async loadActiveAlerts(): Promise<void> {
    try {
      const result = await this.db.query(`
        SELECT * FROM obs_alerts WHERE status IN ('pending', 'firing', 'acknowledged')
      `);
      for (const row of result.rows) {
        const alert = this.rowToAlert(row);
        this.activeAlerts.set(alert.id, alert);
      }
    } catch (error) {
      logger.warn('[Alerting] Could not load active alerts:', { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async evaluateRules(): Promise<void> {
    // FIX-500-187: Acquire PostgreSQL advisory lock to prevent multiple instances
    // from evaluating rules concurrently (avoiding duplicate alerts).
    const ADVISORY_LOCK_ID = 867530987; // arbitrary stable integer for alerting
    const lockResult = await this.db.query<{ acquired: boolean }>(
      'SELECT pg_try_advisory_lock($1) AS acquired',
      [ADVISORY_LOCK_ID],
    );
    if (!lockResult.rows[0]?.acquired) {
      logger.debug('[Alerting] Another instance holds the evaluation lock, skipping');
      return;
    }

    try {
    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      // FIX-500-186: Skip rules that have failed too many times consecutively
      const failCount = this.ruleFailureCounts.get(rule.id) ?? 0;
      if (failCount >= AlertingService.MAX_CONSECUTIVE_FAILURES) {
        logger.warn(`[Alerting] Rule ${rule.name} skipped — ${failCount} consecutive failures (circuit-open)`, { ruleId: rule.id });
        continue;
      }

      try {
        const result = await this.evaluateExpression(rule.expression);
        
        // FIX-500-186: Reset failure counter on success
        if (failCount > 0) {
          this.ruleFailureCounts.delete(rule.id);
        }

        if (result.shouldFire) {
          // Check if there's already an active alert for this rule
          const existingAlert = Array.from(this.activeAlerts.values())
            .find(a => a.ruleId === rule.id && a.status === AlertStatus.FIRING);
          
          if (!existingAlert) {
            await this.fireAlert({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              summary: this.interpolate(rule.annotations.summary || rule.name, result.labels),
              description: this.interpolate(rule.annotations.description || rule.description, result.labels),
              labels: { ...rule.labels, ...result.labels },
              value: result.value,
              threshold: result.threshold,
            });
          }
        } else {
          // Check if we should resolve any active alerts for this rule
          for (const alert of this.activeAlerts.values()) {
            if (alert.ruleId === rule.id && alert.status === AlertStatus.FIRING) {
              await this.resolveAlert(alert.id);
            }
          }
        }
      } catch (error) {
        // FIX-500-186: Track consecutive failures per rule
        const prevFails = this.ruleFailureCounts.get(rule.id) ?? 0;
        this.ruleFailureCounts.set(rule.id, prevFails + 1);
        logger.error(`[Alerting] Failed to evaluate rule ${rule.name} (${prevFails + 1}/${AlertingService.MAX_CONSECUTIVE_FAILURES}):`, { error: error instanceof Error ? error.message : String(error) });
      }
    }
    } finally {
      // FIX-500-187: Release advisory lock
      await this.db.query('SELECT pg_advisory_unlock($1)', [ADVISORY_LOCK_ID]);
    }
  }

  private async evaluateExpression(expression: string): Promise<{
    shouldFire: boolean;
    value: number;
    threshold: number;
    labels: Record<string, string>;
  }> {
    // Parse and evaluate expression
    // Example: "avg(apexmail_error_rate) > 0.05"
    const match = expression.match(/(\w+)\(([^)]+)\)\s*(>|<|>=|<=|==)\s*([\d.]+)/);
    
    if (!match) {
      return { shouldFire: false, value: 0, threshold: 0, labels: {} };
    }

    const matchResult = match;
    const aggregation = matchResult[1] ?? 'avg';
    const metric = matchResult[2] ?? '';
    const operator = matchResult[3] ?? '>';
    const thresholdStr = matchResult[4] ?? '0';
    const threshold = parseFloat(thresholdStr);

    // FIX-500-272: Whitelist aggregation function to prevent SQL injection
    const ALLOWED_AGGS = new Set(['sum', 'avg', 'min', 'max', 'count']);
    if (!ALLOWED_AGGS.has(aggregation.toLowerCase())) {
      return { shouldFire: false, value: 0, threshold: 0, labels: {} }; // Invalid aggregation
    }

    // Query metric value from database
    try {
      const result = await this.db.query(`
        SELECT ${aggregation}(value) as value
        FROM obs_metrics
        WHERE name = $1 AND recorded_at > NOW() - INTERVAL '5 minutes'
      `, [metric]);

      const value = parseFloat(result.rows[0]?.value) || 0;

      let shouldFire = false;
      switch (operator) {
        case '>': shouldFire = value > threshold; break;
        case '<': shouldFire = value < threshold; break;
        case '>=': shouldFire = value >= threshold; break;
        case '<=': shouldFire = value <= threshold; break;
        case '==': shouldFire = value === threshold; break;
      }

      return {
        shouldFire,
        value,
        threshold,
        labels: { metric },
      };
    } catch {
      return { shouldFire: false, value: 0, threshold, labels: {} };
    }
  }

  private async sendNotifications(alert: Alert, type: 'fired' | 'resolved' = 'fired'): Promise<void> {
    // Check cooldown via Redis (automatic TTL expiry — no in-memory Map growth)
    const cooldownKey = `${AlertingService.COOLDOWN_PREFIX}${alert.ruleId}:${type}`;
    const cooldownMs = config.alerting.cooldownMinutes * 60 * 1000;

    try {
      const existing = await this.redis.get(cooldownKey);
      if (existing) {
        const lastTs = parseInt(existing, 10);
        if (Date.now() - lastTs < cooldownMs) {
          return;
        }
      }
    } catch {
      // If Redis is unavailable, fall through and send (better noisy than silent)
    }

    const rule = this.rules.get(alert.ruleId);
    const channelIds = rule?.notificationChannels || [];

    for (const channelId of channelIds) {
      const channel = this.channels.get(channelId);
      if (!channel || !channel.enabled) continue;

      // FIX-500-474: Retry alert notification with exponential backoff
      const MAX_ALERT_RETRIES = 3;
      for (let attempt = 0; attempt < MAX_ALERT_RETRIES; attempt++) {
        try {
          await this.sendToChannel(channel, alert, type);
          alert.notificationsSent++;
          alert.lastNotificationAt = new Date();
          break;
        } catch (error) {
          if (attempt === MAX_ALERT_RETRIES - 1) {
            logger.error(`[Alerting] Failed to send to channel ${channel.name} after ${MAX_ALERT_RETRIES} attempts:`, { error: error instanceof Error ? error.message : String(error) });
          } else {
            await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
          }
        }
      }
    }

    // Record cooldown in Redis with TTL (auto-expires — no unbounded map)
    try {
      const ttlSeconds = Math.ceil(cooldownMs / 1000);
      await this.redis.setex(cooldownKey, ttlSeconds, String(Date.now()));
    } catch {
      // best-effort
    }
  }

  private async sendToChannel(channel: NotificationChannel, alert: Alert, type: string): Promise<void> {
    const message = this.formatAlertMessage(alert, type);

    switch (channel.type) {
      case 'slack':
        await this.sendSlackNotification(channel.config, message);
        break;
      case 'email':
        await this.sendEmailNotification(channel.config, alert, type);
        break;
      case 'webhook':
        await this.sendWebhookNotification(channel.config, alert);
        break;
      case 'pagerduty':
        await this.sendPagerDutyNotification(channel.config, alert, type);
        break;
      case 'opsgenie':
        await this.sendOpsGenieNotification(channel.config, alert, type);
        break;
    }
  }

  private async sendSlackNotification(config: Record<string, unknown>, message: string): Promise<void> {
    const alertingConfig = config.alerting as { slackWebhook?: string } | undefined;
    const webhookUrl = config.webhookUrl as string || alertingConfig?.slackWebhook;
    if (!webhookUrl) return;

    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: message }),
    });
  }

  private async sendEmailNotification(_channelConfig: Record<string, unknown>, alert: Alert, type: string): Promise<void> {
    // In production, would send via email service
    logger.info(`[Alerting] Email notification: ${alert.summary} (${type})`);
  }

  private async sendWebhookNotification(config: Record<string, unknown>, alert: Alert): Promise<void> {
    const url = config.url as string;
    if (!url) return;

    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });
  }

  private async sendPagerDutyNotification(config: Record<string, unknown>, alert: Alert, type: string): Promise<void> {
    const alertingConfig = config.alerting as { pagerdutyKey?: string } | undefined;
    const routingKey = config.routingKey as string || alertingConfig?.pagerdutyKey;
    if (!routingKey) return;

    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: type === 'resolved' ? 'resolve' : 'trigger',
        dedup_key: alert.id,
        payload: {
          summary: alert.summary,
          severity: alert.severity,
          source: 'apexmail',
          custom_details: alert,
        },
      }),
    });
  }

  private async sendOpsGenieNotification(config: Record<string, unknown>, alert: Alert, type: string): Promise<void> {
    const alertingConfig = config.alerting as { opsgenieKey?: string } | undefined;
    const apiKey = config.apiKey as string || alertingConfig?.opsgenieKey;
    if (!apiKey) return;

    if (type === 'resolved') {
      await fetch(`https://api.opsgenie.com/v2/alerts/${alert.id}/close`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `GenieKey ${apiKey}`,
        },
        body: JSON.stringify({ source: 'apexmail' }),
      });
    } else {
      await fetch('https://api.opsgenie.com/v2/alerts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `GenieKey ${apiKey}`,
        },
        body: JSON.stringify({
          message: alert.summary,
          alias: alert.id,
          description: alert.description,
          priority: this.severityToPriority(alert.severity),
          source: 'apexmail',
          details: alert.labels,
        }),
      });
    }
  }

  private formatAlertMessage(alert: Alert, type: string): string {
    const icon = type === 'resolved' ? '✅' : this.severityIcon(alert.severity);
    const status = type === 'resolved' ? 'RESOLVED' : 'FIRING';
    
    return `${icon} [${status}] ${alert.summary}\n` +
           `Severity: ${alert.severity}\n` +
           `Description: ${alert.description}\n` +
           `Value: ${alert.value} (threshold: ${alert.threshold})`;
  }

  private severityIcon(severity: AlertSeverity): string {
    const icons: Record<AlertSeverity, string> = {
      [AlertSeverity.INFO]: 'ℹ️',
      [AlertSeverity.WARNING]: '⚠️',
      [AlertSeverity.CRITICAL]: '🔴',
      [AlertSeverity.EMERGENCY]: '🚨',
    };
    return icons[severity] || '⚠️';
  }

  private severityToPriority(severity: AlertSeverity): string {
    const priorities: Record<AlertSeverity, string> = {
      [AlertSeverity.INFO]: 'P5',
      [AlertSeverity.WARNING]: 'P3',
      [AlertSeverity.CRITICAL]: 'P2',
      [AlertSeverity.EMERGENCY]: 'P1',
    };
    return priorities[severity] || 'P3';
  }

  private isAlertSilenced(alert: Alert): boolean {
    const now = new Date();
    for (const silence of this.silences.values()) {
      if (silence.startsAt <= now && silence.endsAt >= now) {
        if (this.matchesSilence(alert, silence)) {
          return true;
        }
      }
    }
    return false;
  }

  private matchesSilence(alert: Alert, silence: Silence): boolean {
    for (const matcher of silence.matchers) {
      const labelValue = alert.labels[matcher.name];
      if (!labelValue) return false;

      if (matcher.isRegex) {
        const regex = new RegExp(matcher.value);
        if (!regex.test(labelValue)) return false;
      } else {
        if (labelValue !== matcher.value) return false;
      }
    }
    return true;
  }

  private interpolate(template: string, labels: Record<string, string>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key) => labels[key] || `{{${key}}}`);
  }

  private async saveAlert(alert: Alert): Promise<void> {
    await this.db.query(`
      INSERT INTO obs_alerts (
        id, rule_id, rule_name, status, severity, summary, description,
        labels, annotations, value, threshold, fired_at, resolved_at,
        acknowledged_at, acknowledged_by, silenced_until, notifications_sent,
        last_notification_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      ON CONFLICT (id) DO UPDATE SET
        status = $4, resolved_at = $13, acknowledged_at = $14, acknowledged_by = $15,
        silenced_until = $16, notifications_sent = $17, last_notification_at = $18
    `, [
      alert.id,
      alert.ruleId,
      alert.ruleName,
      alert.status,
      alert.severity,
      alert.summary,
      alert.description,
      JSON.stringify(alert.labels),
      JSON.stringify(alert.annotations),
      alert.value,
      alert.threshold,
      alert.firedAt,
      alert.resolvedAt,
      alert.acknowledgedAt,
      alert.acknowledgedBy,
      alert.silencedUntil,
      alert.notificationsSent,
      alert.lastNotificationAt,
    ]);
  }

  private rowToAlert(row: Record<string, unknown>): Alert {
    return {
      id: row.id as string,
      ruleId: row.rule_id as string,
      ruleName: row.rule_name as string,
      status: row.status as AlertStatus,
      severity: row.severity as AlertSeverity,
      summary: row.summary as string,
      description: row.description as string,
      labels: (row.labels as Record<string, string>) || {},
      annotations: (row.annotations as Record<string, string>) || {},
      value: row.value as number,
      threshold: row.threshold as number,
      firedAt: new Date(row.fired_at as string),
      resolvedAt: row.resolved_at ? new Date(row.resolved_at as string) : null,
      acknowledgedAt: row.acknowledged_at ? new Date(row.acknowledged_at as string) : null,
      acknowledgedBy: row.acknowledged_by as string | null,
      silencedUntil: row.silenced_until ? new Date(row.silenced_until as string) : null,
      notificationsSent: row.notifications_sent as number,
      lastNotificationAt: row.last_notification_at ? new Date(row.last_notification_at as string) : null,
    };
  }

  /**
   * Shutdown
   */
  shutdown(): void {
    if (this.evaluationInterval) {
      clearInterval(this.evaluationInterval);
    }
    logger.info('[Alerting] Service shut down');
  }
}
