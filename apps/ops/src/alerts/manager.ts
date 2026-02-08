/**
 * @apexmail/ops - Alert Manager
 * 
 * Centralized alerting system with multi-channel notifications.
 */

import {
    Alert,
    AlertRule,
    AlertSeverity,
    AlertChannel,
} from '../types.js';
import { EventEmitter } from 'events';
import crypto from 'node:crypto';
import pino from 'pino';

const logger = pino({ name: 'alert-manager' });

export interface AlertManagerConfig {
    defaultChannels: AlertChannel[];
    escalationTimeoutMs: number;
    deduplicationWindowMs: number;
    maxActiveAlerts: number;
}

interface AlertNotification {
    alertId: string;
    channel: AlertChannel;
    sentAt: Date;
    success: boolean;
    error?: string;
}

interface EscalationPolicy {
    id: string;
    name: string;
    levels: {
        level: number;
        delayMinutes: number;
        channels: AlertChannel[];
        recipients: string[];
    }[];
}

export class AlertManager extends EventEmitter {
    private config: AlertManagerConfig;
    private rules: Map<string, AlertRule> = new Map();
    private activeAlerts: Map<string, Alert> = new Map();
    private alertHistory: Alert[] = [];
    private notifications: AlertNotification[] = [];
    private escalationPolicies: Map<string, EscalationPolicy> = new Map();
    private deduplicationCache: Map<string, number> = new Map();
    private escalationTimers: Map<string, NodeJS.Timeout[]> = new Map();
    private deduplicationCleanupInterval: NodeJS.Timeout | null = null;
    private static readonly MAX_ALERT_HISTORY_SIZE = 10000;
    private static readonly MAX_NOTIFICATION_HISTORY_SIZE = 10000;

    constructor(config: AlertManagerConfig) {
        super();
        this.setMaxListeners(50); // FIX-500-332: Prevent maxListeners warning
        this.config = config;
        this.initializeDefaultRules();
        this.initializeDefaultEscalationPolicies();
        this.startDeduplicationCleanup();
    }

    /**
     * Initializes default alert rules
     */
    private initializeDefaultRules(): void {
        // API Error Rate
        this.registerRule({
            id: 'api-error-rate',
            name: 'API Error Rate High',
            description: 'Triggers when API error rate exceeds threshold',
            condition: {
                metric: 'api.error_rate',
                operator: 'greater_than',
                threshold: 5,
                duration: 300, // 5 minutes
            },
            severity: 'warning',
            channels: ['slack', 'email'],
            labels: { service: 'api', category: 'availability' },
            enabled: true,
        });

        // API Latency
        this.registerRule({
            id: 'api-latency-high',
            name: 'API Latency High',
            description: 'Triggers when API p95 latency exceeds threshold',
            condition: {
                metric: 'api.latency_p95',
                operator: 'greater_than',
                threshold: 500, // 500ms
                duration: 180,
            },
            severity: 'warning',
            channels: ['slack'],
            labels: { service: 'api', category: 'performance' },
            enabled: true,
        });

        // Email Delivery Failure Rate
        this.registerRule({
            id: 'email-delivery-failure',
            name: 'Email Delivery Failure Rate High',
            description: 'Triggers when email delivery failure rate exceeds threshold',
            condition: {
                metric: 'email.delivery_failure_rate',
                operator: 'greater_than',
                threshold: 2,
                duration: 300,
            },
            severity: 'critical',
            channels: ['pagerduty', 'slack', 'email'],
            labels: { service: 'email', category: 'availability' },
            enabled: true,
        });

        // Database Connection Pool
        this.registerRule({
            id: 'db-pool-exhausted',
            name: 'Database Connection Pool Near Exhaustion',
            description: 'Triggers when database connection pool usage exceeds 80%',
            condition: {
                metric: 'database.pool_usage',
                operator: 'greater_than',
                threshold: 80,
                duration: 60,
            },
            severity: 'warning',
            channels: ['slack'],
            labels: { service: 'database', category: 'resources' },
            enabled: true,
        });

        // Memory Usage
        this.registerRule({
            id: 'memory-usage-high',
            name: 'Memory Usage High',
            description: 'Triggers when memory usage exceeds 85%',
            condition: {
                metric: 'system.memory_usage',
                operator: 'greater_than',
                threshold: 85,
                duration: 300,
            },
            severity: 'warning',
            channels: ['slack'],
            labels: { service: 'system', category: 'resources' },
            enabled: true,
        });

        // SLO Burn Rate
        this.registerRule({
            id: 'slo-burn-rate-high',
            name: 'SLO Burn Rate Critical',
            description: 'Triggers when SLO burn rate indicates potential budget exhaustion',
            condition: {
                metric: 'slo.burn_rate',
                operator: 'greater_than',
                threshold: 10,
                duration: 60,
            },
            severity: 'critical',
            channels: ['pagerduty', 'slack'],
            labels: { service: 'slo', category: 'availability' },
            enabled: true,
        });

        // Queue Backlog
        this.registerRule({
            id: 'queue-backlog-high',
            name: 'Queue Backlog Growing',
            description: 'Triggers when queue backlog exceeds threshold',
            condition: {
                metric: 'queue.backlog_size',
                operator: 'greater_than',
                threshold: 10000,
                duration: 300,
            },
            severity: 'warning',
            channels: ['slack'],
            labels: { service: 'queue', category: 'performance' },
            enabled: true,
        });

        // Certificate Expiry
        this.registerRule({
            id: 'cert-expiry-soon',
            name: 'Certificate Expiring Soon',
            description: 'Triggers when certificate expires within 14 days',
            condition: {
                metric: 'security.cert_days_until_expiry',
                operator: 'less_than',
                threshold: 14,
                duration: 0,
            },
            severity: 'warning',
            channels: ['email', 'slack'],
            labels: { service: 'security', category: 'compliance' },
            enabled: true,
        });
    }

    /**
     * Initializes default escalation policies
     */
    private initializeDefaultEscalationPolicies(): void {
        this.escalationPolicies.set('default', {
            id: 'default',
            name: 'Default Escalation',
            levels: [
                {
                    level: 1,
                    delayMinutes: 0,
                    channels: ['slack'],
                    recipients: ['on-call-primary'],
                },
                {
                    level: 2,
                    delayMinutes: 15,
                    channels: ['slack', 'email'],
                    recipients: ['on-call-primary', 'on-call-secondary'],
                },
                {
                    level: 3,
                    delayMinutes: 30,
                    channels: ['pagerduty', 'slack', 'email'],
                    recipients: ['on-call-primary', 'on-call-secondary', 'engineering-lead'],
                },
            ],
        });

        this.escalationPolicies.set('critical', {
            id: 'critical',
            name: 'Critical Escalation',
            levels: [
                {
                    level: 1,
                    delayMinutes: 0,
                    channels: ['pagerduty', 'slack'],
                    recipients: ['on-call-primary'],
                },
                {
                    level: 2,
                    delayMinutes: 5,
                    channels: ['pagerduty', 'slack', 'email'],
                    recipients: ['on-call-primary', 'on-call-secondary', 'engineering-lead'],
                },
                {
                    level: 3,
                    delayMinutes: 15,
                    channels: ['pagerduty', 'slack', 'email', 'sms'],
                    recipients: ['engineering-lead', 'vp-engineering', 'cto'],
                },
            ],
        });
    }

    /**
     * Starts deduplication cache cleanup
     */
    private startDeduplicationCleanup(): void {
        this.deduplicationCleanupInterval = setInterval(() => {
            const now = Date.now();
            for (const [key, timestamp] of this.deduplicationCache) {
                if (now - timestamp > this.config.deduplicationWindowMs) {
                    this.deduplicationCache.delete(key);
                }
            }
            // FIX-500-328: Use splice for in-place trimming instead of slice copy
            const alertExcess = this.alertHistory.length - AlertManager.MAX_ALERT_HISTORY_SIZE;
            if (alertExcess > 0) {
                this.alertHistory.splice(0, alertExcess);
            }
        }, 60000); // Clean every minute
        if (this.deduplicationCleanupInterval) {
            this.deduplicationCleanupInterval.unref(); // FIX-500-331: Don't block process exit
        }
    }

    /**
     * Stops the alert manager and cleans up resources
     */
    stop(): void {
        if (this.deduplicationCleanupInterval) {
            clearInterval(this.deduplicationCleanupInterval);
            this.deduplicationCleanupInterval = null;
        }
        // Clear all escalation timers
        for (const timers of this.escalationTimers.values()) {
            for (const timer of timers) {
                clearTimeout(timer);
            }
        }
        this.escalationTimers.clear();
        logger.info('Alert manager stopped');
    }

    /**
     * Registers an alert rule
     */
    registerRule(rule: AlertRule): void {
        this.rules.set(rule.id, rule);
        this.emit('rule:registered', rule);
        logger.info({ ruleId: rule.id }, 'Alert rule registered');
    }

    /**
     * Updates an alert rule
     */
    updateRule(ruleId: string, updates: Partial<AlertRule>): void {
        const rule = this.rules.get(ruleId);
        if (!rule) return;

        Object.assign(rule, updates);
        this.emit('rule:updated', rule);
    }

    /**
     * Disables an alert rule
     */
    disableRule(ruleId: string): void {
        const rule = this.rules.get(ruleId);
        if (!rule) return;

        rule.enabled = false;
        this.emit('rule:disabled', rule);
    }

    /**
     * Enables an alert rule
     */
    enableRule(ruleId: string): void {
        const rule = this.rules.get(ruleId);
        if (!rule) return;

        rule.enabled = true;
        this.emit('rule:enabled', rule);
    }

    /**
     * Evaluates a metric value against all rules
     */
    evaluateMetric(metricName: string, value: number, labels: Record<string, string> = {}): void {
        for (const rule of this.rules.values()) {
            if (!rule.enabled || !rule.condition || rule.condition.metric !== metricName) {
                continue;
            }

            const triggered = this.evaluateCondition(rule.condition, value);

            if (triggered) {
                this.triggerAlert(rule, value, labels);
            } else {
                this.resolveAlertForRule(rule);
            }
        }
    }

    /**
     * Evaluates a single condition
     */
    private evaluateCondition(
        condition: AlertRule['condition'],
        value: number
    ): boolean {
        if (!condition) return false;
        switch (condition.operator) {
            case 'greater_than':
                return value > condition.threshold;
            case 'less_than':
                return value < condition.threshold;
            case 'equals':
                return value === condition.threshold;
            case 'not_equals':
                return value !== condition.threshold;
            default:
                return false;
        }
    }

    /**
     * Triggers an alert from a rule
     */
    triggerAlert(
        rule: AlertRule,
        value: number,
        labels: Record<string, string>
    ): Alert {
        // Check deduplication
        const dedupKey = `${rule.id}:${JSON.stringify(labels)}`;
        if (this.deduplicationCache.has(dedupKey)) {
            const existing = this.findActiveAlertByRule(rule.id);
            if (existing) {
                return existing;
            }
        }

        // Check max active alerts
        if (this.activeAlerts.size >= this.config.maxActiveAlerts) {
            logger.warn(
                { maxAlerts: this.config.maxActiveAlerts },
                'Max active alerts reached'
            );
            // Still trigger but log warning
        }

        const alert: Alert = {
            id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            ruleId: rule.id,
            name: rule.name,
            description: `${rule.description || rule.name}. Current value: ${value}`,
            severity: rule.severity,
            status: 'firing',
            labels: { ...rule.labels, ...labels },
            annotations: {
                value: String(value),
                threshold: String(rule.condition?.threshold || 0),
                metric: rule.condition?.metric || '',
            },
            startsAt: new Date(),
            endsAt: undefined,
        };

        this.activeAlerts.set(alert.id, alert);
        this.deduplicationCache.set(dedupKey, Date.now());

        this.emit('alert:triggered', alert);
        logger.warn({ alertId: alert.id, rule: rule.id }, 'Alert triggered');

        // Send notifications
        this.sendNotifications(alert, rule.channels || this.config.defaultChannels);

        // Setup escalation
        this.setupEscalation(alert, rule.severity);

        return alert;
    }

    /**
     * Finds an active alert by rule ID
     */
    private findActiveAlertByRule(ruleId: string): Alert | undefined {
        for (const alert of this.activeAlerts.values()) {
            if (alert.ruleId === ruleId) {
                return alert;
            }
        }
        return undefined;
    }

    /**
     * Manually triggers an alert
     */
    createManualAlert(params: {
        name: string;
        description: string;
        severity: AlertSeverity;
        labels?: Record<string, string>;
        annotations?: Record<string, string>;
    }): Alert {
        const alert: Alert = {
            id: `alert-${crypto.randomUUID()}`,
            ruleId: 'manual',
            name: params.name,
            description: params.description,
            severity: params.severity,
            status: 'firing',
            labels: params.labels || {},
            annotations: params.annotations || {},
            startsAt: new Date(),
            endsAt: undefined,
        };

        this.activeAlerts.set(alert.id, alert);
        this.emit('alert:triggered', alert);

        this.sendNotifications(alert, this.config.defaultChannels);

        return alert;
    }

    /**
     * Acknowledges an alert
     */
    acknowledgeAlert(alertId: string, acknowledgedBy: string): void {
        const alert = this.activeAlerts.get(alertId);
        if (!alert) return;

        alert.status = 'acknowledged';
        alert.acknowledgedBy = acknowledgedBy;
        alert.acknowledgedAt = new Date();

        // Cancel escalation timers
        this.cancelEscalation(alertId);

        this.emit('alert:acknowledged', alert);
        logger.info({ alertId, acknowledgedBy }, 'Alert acknowledged');
    }

    /**
     * Resolves an alert
     */
    resolveAlert(alertId: string, resolvedBy?: string): void {
        const alert = this.activeAlerts.get(alertId);
        if (!alert) return;

        alert.status = 'resolved';
        alert.endsAt = new Date();

        // Cancel escalation timers
        this.cancelEscalation(alertId);

        // Move to history
        this.alertHistory.push(alert);
        this.activeAlerts.delete(alertId);

        this.emit('alert:resolved', alert);
        logger.info({ alertId, resolvedBy }, 'Alert resolved');

        // Send resolution notification
        if (alert.ruleId) {
            const rule = this.rules.get(alert.ruleId);
            if (rule) {
                this.sendNotifications(alert, rule.channels || this.config.defaultChannels, true);
            }
        }
    }

    /**
     * Resolves alerts for a specific rule
     */
    private resolveAlertForRule(rule: AlertRule): void {
        const alert = this.findActiveAlertByRule(rule.id);
        if (alert) {
            this.resolveAlert(alert.id, 'auto');
        }
    }

    /**
     * Silences an alert
     */
    silenceAlert(
        alertId: string,
        duration: number,
        silencedBy: string,
        reason: string
    ): void {
        const alert = this.activeAlerts.get(alertId);
        if (!alert) return;

        alert.status = 'silenced';
        alert.silencedUntil = new Date(Date.now() + duration);

        this.cancelEscalation(alertId);

        this.emit('alert:silenced', { alert, silencedBy, reason, duration });
        logger.info({ alertId, silencedBy, duration }, 'Alert silenced');

        // Schedule unsilence
        const silenceTimer = setTimeout(() => {
            if (alert.status === 'silenced') {
                alert.status = 'firing';
                this.setupEscalation(alert, alert.severity);
                this.emit('alert:unsilenced', alert);
            }
        }, duration);
        silenceTimer.unref(); // FIX-500-331: Don't block process exit
    }

    /**
     * Sends notifications to channels
     */
    private sendNotifications(
        alert: Alert,
        channels: AlertChannel[],
        isResolution: boolean = false
    ): void {
        for (const channel of channels) {
            this.sendToChannel(alert, channel, isResolution);
        }
    }

    /**
     * Sends notification to a specific channel
     */
    private async sendToChannel(
        alert: Alert,
        channel: AlertChannel,
        isResolution: boolean
    ): Promise<void> {
        const notification: AlertNotification = {
            alertId: alert.id,
            channel,
            sentAt: new Date(),
            success: false,
        };

        try {
            switch (channel) {
                case 'slack':
                    await this.sendSlackNotification(alert, isResolution);
                    break;
                case 'email':
                    await this.sendEmailNotification(alert, isResolution);
                    break;
                case 'pagerduty':
                    await this.sendPagerDutyNotification(alert, isResolution);
                    break;
                case 'webhook':
                    await this.sendWebhookNotification(alert, isResolution);
                    break;
                case 'sms':
                    await this.sendSMSNotification(alert, isResolution);
                    break;
            }

            notification.success = true;
        } catch (error) {
            notification.error = error instanceof Error ? error.message : 'Unknown error';
            logger.error({ alertId: alert.id, channel, error }, 'Failed to send notification');
        }

        this.notifications.push(notification);
        
        // FIX-500-327: Use splice to trim in-place instead of copying the entire array
        const notifExcess = this.notifications.length - AlertManager.MAX_NOTIFICATION_HISTORY_SIZE;
        if (notifExcess > 0) {
            this.notifications.splice(0, notifExcess);
        }
        
        this.emit('notification:sent', notification);
    }

    /**
     * Sends Slack notification
     */
    private async sendSlackNotification(
        alert: Alert,
        isResolution: boolean
    ): Promise<void> {
        const color = isResolution
            ? '#36a64f'
            : this.getSeverityColor(alert.severity);

        const payload = {
            attachments: [
                {
                    color,
                    title: isResolution ? `[RESOLVED] ${alert.name}` : `[${alert.severity.toUpperCase()}] ${alert.name}`,
                    text: alert.description,
                    fields: [
                        { title: 'Status', value: alert.status, short: true },
                        { title: 'Started', value: alert.startsAt.toISOString(), short: true },
                        ...Object.entries(alert.labels || {}).map(([key, value]) => ({
                            title: key,
                            value,
                            short: true,
                        })),
                    ],
                    footer: 'ApexMail Alert Manager',
                    ts: Math.floor(Date.now() / 1000),
                },
            ],
        };

        this.emit('slack:send', payload);
    }

    /**
     * Sends email notification
     */
    private async sendEmailNotification(
        alert: Alert,
        isResolution: boolean
    ): Promise<void> {
        const subject = isResolution
            ? `[RESOLVED] ${alert.name}`
            : `[${alert.severity.toUpperCase()}] ${alert.name}`;

        const body = `
Alert: ${alert.name}
Status: ${alert.status}
Severity: ${alert.severity}
Description: ${alert.description}

Labels:
${Object.entries(alert.labels || {}).map(([k, v]) => `  ${k}: ${v}`).join('\n')}

Started: ${alert.startsAt.toISOString()}
${alert.endsAt ? `Resolved: ${alert.endsAt.toISOString()}` : ''}
        `.trim();

        this.emit('email:send', { subject, body, alert });
    }

    /**
     * Sends PagerDuty notification
     */
    private async sendPagerDutyNotification(
        alert: Alert,
        isResolution: boolean
    ): Promise<void> {
        const event = {
            routing_key: process.env.PAGERDUTY_ROUTING_KEY,
            event_action: isResolution ? 'resolve' : 'trigger',
            dedup_key: alert.id,
            payload: {
                summary: alert.name,
                source: 'ApexMail',
                severity: this.mapSeverityToPagerDuty(alert.severity),
                custom_details: {
                    description: alert.description,
                    labels: alert.labels,
                    annotations: alert.annotations,
                },
            },
        };

        this.emit('pagerduty:send', event);
    }

    /**
     * Sends webhook notification
     */
    private async sendWebhookNotification(
        alert: Alert,
        isResolution: boolean
    ): Promise<void> {
        const payload = {
            type: isResolution ? 'alert.resolved' : 'alert.triggered',
            alert: {
                id: alert.id,
                name: alert.name,
                description: alert.description,
                severity: alert.severity,
                status: alert.status,
                labels: alert.labels,
                annotations: alert.annotations,
                startsAt: alert.startsAt.toISOString(),
                endsAt: alert.endsAt?.toISOString(),
            },
            timestamp: new Date().toISOString(),
        };

        this.emit('webhook:send', payload);
    }

    /**
     * Sends SMS notification
     */
    private async sendSMSNotification(
        alert: Alert,
        isResolution: boolean
    ): Promise<void> {
        const message = isResolution
            ? `[RESOLVED] ${alert.name}`
            : `[${alert.severity.toUpperCase()}] ${alert.name}: ${alert.description.substring(0, 100)}`;

        this.emit('sms:send', { message, alert });
    }

    /**
     * Sets up escalation for an alert
     */
    private setupEscalation(alert: Alert, severity: AlertSeverity): void {
        const policyId = severity === 'critical' ? 'critical' : 'default';
        const policy = this.escalationPolicies.get(policyId);
        if (!policy) return;

        const timers: NodeJS.Timeout[] = [];

        for (const level of policy.levels) {
            const timer = setTimeout(() => {
                const currentAlert = this.activeAlerts.get(alert.id);
                if (
                    currentAlert &&
                    currentAlert.status === 'firing'
                ) {
                    logger.info(
                        { alertId: alert.id, level: level.level },
                        'Escalating alert'
                    );
                    this.sendNotifications(currentAlert, level.channels);
                    this.emit('alert:escalated', { alert: currentAlert, level: level.level });
                }
            }, level.delayMinutes * 60 * 1000);
            timer.unref(); // FIX-500-331: Don't block process exit

            timers.push(timer);
        }

        this.escalationTimers.set(alert.id, timers);
    }

    /**
     * Cancels escalation timers for an alert
     */
    private cancelEscalation(alertId: string): void {
        const timers = this.escalationTimers.get(alertId);
        if (timers) {
            for (const timer of timers) {
                clearTimeout(timer);
            }
            this.escalationTimers.delete(alertId);
        }
    }

    /**
     * Gets severity color for Slack
     */
    private getSeverityColor(severity: AlertSeverity): string {
        switch (severity) {
            case 'critical':
                return '#dc2626';
            case 'error':
                return '#ea580c';
            case 'warning':
                return '#ca8a04';
            case 'info':
                return '#2563eb';
            default:
                return '#6b7280';
        }
    }

    /**
     * Maps severity to PagerDuty severity
     */
    private mapSeverityToPagerDuty(severity: AlertSeverity): string {
        switch (severity) {
            case 'critical':
                return 'critical';
            case 'error':
                return 'error';
            case 'warning':
                return 'warning';
            case 'info':
                return 'info';
            default:
                return 'info';
        }
    }

    /**
     * Gets all active alerts
     */
    getActiveAlerts(): Alert[] {
        return Array.from(this.activeAlerts.values());
    }

    /**
     * Gets alert history
     */
    getAlertHistory(options: {
        limit?: number;
        offset?: number;
        severity?: AlertSeverity[];
    } = {}): Alert[] {
        const { limit = 50, offset = 0, severity } = options;

        let alerts = [...this.alertHistory];

        if (severity) {
            alerts = alerts.filter((a) => severity.includes(a.severity));
        }

        return alerts
            .sort((a, b) => b.startsAt.getTime() - a.startsAt.getTime())
            .slice(offset, offset + limit);
    }

    /**
     * Gets all registered rules
     */
    getRules(): AlertRule[] {
        return Array.from(this.rules.values());
    }

    /**
     * Gets alert statistics
     */
    getStatistics(): {
        totalActive: number;
        bySeverity: Record<AlertSeverity, number>;
        byStatus: Record<string, number>;
        totalToday: number;
        mttr: number;
    } {
        const active = Array.from(this.activeAlerts.values());
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const bySeverity: Record<AlertSeverity, number> = {
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
        };

        const byStatus: Record<string, number> = {
            firing: 0,
            acknowledged: 0,
            silenced: 0,
            resolved: 0,
        };

        for (const alert of active) {
            bySeverity[alert.severity]++;
            byStatus[alert.status]++;
        }

        const todayAlerts = this.alertHistory.filter(
            (a) => a.startsAt >= today
        );

        // Calculate MTTR (Mean Time To Resolve)
        const resolvedWithDuration = this.alertHistory
            .filter((a) => a.endsAt)
            .map((a) => a.endsAt!.getTime() - a.startsAt.getTime());

        const mttr =
            resolvedWithDuration.length > 0
                ? resolvedWithDuration.reduce((a, b) => a + b, 0) /
                  resolvedWithDuration.length /
                  1000 / 60 // in minutes
                : 0;

        return {
            totalActive: active.length,
            bySeverity,
            byStatus,
            totalToday: todayAlerts.length + active.length,
            mttr,
        };
    }
}
