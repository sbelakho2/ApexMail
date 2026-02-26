/**
 * Reputation Repository
 * 
 * Data access for sender reputation statistics and alerts
 */

import { randomUUID } from 'node:crypto';
import { ok, err, type Result } from '@apexmail/lib';
import type { DatabasePool } from '../pool.js';

// =============================================================================
// Types
// =============================================================================

export interface ReputationStats {
    tenantId: string;
    date: Date;
    sent: number;
    delivered: number;
    bounces: number;
    complaints: number;
    opens: number;
    clicks: number;
    unsubscribes: number;
}

export interface ReputationAlert {
    id: string;
    tenantId: string;
    alertType: 'high_bounce_rate' | 'high_complaint_rate' | 'low_delivery_rate' | 'reputation_warning';
    value: number;
    threshold: number;
    acknowledged: boolean;
    createdAt: Date;
}

export interface ReputationSummary {
    deliveryRate: number;
    bounceRate: number;
    complaintRate: number;
    openRate: number;
    clickRate: number;
    unsubscribeRate: number;
    totalSent: number;
    totalDelivered: number;
    trend: 'improving' | 'stable' | 'declining';
}

// =============================================================================
// Repository
// =============================================================================

export class ReputationRepository {
    constructor(private readonly db: DatabasePool) {}

    private statColumnsValidated = false;

    private async ensureStatColumns(): Promise<void> {
        if (this.statColumnsValidated) return;

        const result = await this.db.query<{ column_name: string }>(
            `SELECT column_name
             FROM information_schema.columns
             WHERE table_name = 'reputation_stats'
               AND table_schema = current_schema()`
        );

        if (!result.ok) throw result.error;

        const columns = new Set(result.value.rows.map(row => row.column_name));
        const missing = [...ReputationRepository.ALLOWED_STAT_COLUMNS].filter(col => !columns.has(col));

        if (missing.length > 0) {
            throw new Error(
                `Reputation stats columns missing from schema: ${missing.join(', ')}`
            );
        }

        this.statColumnsValidated = true;
    }

    // -------------------------------------------------------------------------
    // Daily Stats
    // -------------------------------------------------------------------------

    // Allowed column names for incrementStat — prevents SQL injection at runtime
    private static readonly ALLOWED_STAT_COLUMNS = new Set<string>([
        'sent', 'delivered', 'bounces', 'complaints', 'opens', 'clicks', 'unsubscribes',
    ]);

    /**
     * Increment stats for a specific metric
     */
    async incrementStat(tenantId: string, metric: keyof Omit<ReputationStats, 'tenantId' | 'date'>): Promise<void> {
        await this.ensureStatColumns();

        // Runtime whitelist check to prevent SQL injection via dynamic column name
        if (!ReputationRepository.ALLOWED_STAT_COLUMNS.has(metric)) {
            throw new Error(`Invalid metric column: ${metric}`);
        }

        const today = new Date().toISOString().split('T')[0];
        
        const result = await this.db.query(
            `INSERT INTO reputation_stats (tenant_id, date, ${metric})
             VALUES ($1, $2, 1)
             ON CONFLICT (tenant_id, date)
             DO UPDATE SET ${metric} = reputation_stats.${metric} + 1`,
            [tenantId, today]
        );
        if (!result.ok) throw result.error;
    }

    /**
     * Get stats for a date range
     */
    async getStats(tenantId: string, startDate: Date, endDate: Date): Promise<ReputationStats[]> {
        const result = await this.db.query<Record<string, unknown>>(
            `SELECT * FROM reputation_stats
             WHERE tenant_id = $1 AND date >= $2 AND date <= $3
             ORDER BY date`,
            [tenantId, startDate, endDate]
        );

        if (!result.ok) throw result.error;
        return result.value.rows.map(row => this.mapStatsRow(row));
    }

    /**
     * Get aggregated stats for a period
     */
    async getAggregatedStats(tenantId: string, days: number): Promise<ReputationStats> {
        const result = await this.db.query<Record<string, unknown>>(
            `SELECT 
                $1 as tenant_id,
                NOW() as date,
                COALESCE(SUM(sent), 0) as sent,
                COALESCE(SUM(delivered), 0) as delivered,
                COALESCE(SUM(bounces), 0) as bounces,
                COALESCE(SUM(complaints), 0) as complaints,
                COALESCE(SUM(opens), 0) as opens,
                COALESCE(SUM(clicks), 0) as clicks,
                COALESCE(SUM(unsubscribes), 0) as unsubscribes
             FROM reputation_stats
             WHERE tenant_id = $1 AND date >= NOW() - INTERVAL '1 day' * $2`,
            [tenantId, days]
        );

        if (!result.ok) throw result.error;
        const row = result.value.rows[0];
        if (!row) {
            return this.mapStatsRow({
                tenant_id: tenantId,
                date: new Date().toISOString(),
                sent: '0',
                delivered: '0',
                bounces: '0',
                complaints: '0',
                opens: '0',
                clicks: '0',
                unsubscribes: '0'
            });
        }
        return this.mapStatsRow(row);
    }

    /**
     * Calculate reputation summary with trends
     */
    async getSummary(tenantId: string): Promise<ReputationSummary> {
        // Get last 7 days
        const currentStats = await this.getAggregatedStats(tenantId, 7);
        
        // Get previous 7 days for comparison
        const previousResult = await this.db.query<Record<string, unknown>>(
            `SELECT 
                COALESCE(SUM(sent), 0) as sent,
                COALESCE(SUM(delivered), 0) as delivered,
                COALESCE(SUM(bounces), 0) as bounces,
                COALESCE(SUM(complaints), 0) as complaints
             FROM reputation_stats
             WHERE tenant_id = $1 
             AND date >= NOW() - INTERVAL '14 days'
             AND date < NOW() - INTERVAL '7 days'`,
            [tenantId]
        );

        if (!previousResult.ok) throw previousResult.error;
        const previousStats = previousResult.value.rows[0];

        const deliveryRate = currentStats.sent > 0 
            ? (currentStats.delivered / currentStats.sent) * 100 
            : 100;
        const bounceRate = currentStats.sent > 0 
            ? (currentStats.bounces / currentStats.sent) * 100 
            : 0;
        const complaintRate = currentStats.delivered > 0 
            ? (currentStats.complaints / currentStats.delivered) * 100 
            : 0;
        const openRate = currentStats.delivered > 0 
            ? (currentStats.opens / currentStats.delivered) * 100 
            : 0;
        const clickRate = currentStats.opens > 0 
            ? (currentStats.clicks / currentStats.opens) * 100 
            : 0;
        const unsubscribeRate = currentStats.delivered > 0 
            ? (currentStats.unsubscribes / currentStats.delivered) * 100 
            : 0;

        // Calculate trend based on delivery rate change
        const prevSent = parseInt(previousStats?.sent as string ?? '0', 10) || 0;
        const prevDelivered = parseInt(previousStats?.delivered as string ?? '0', 10) || 0;
        const prevDeliveryRate = prevSent > 0 ? (prevDelivered / prevSent) * 100 : 100;

        let trend: 'improving' | 'stable' | 'declining' = 'stable';
        if (deliveryRate > prevDeliveryRate + 2) {
            trend = 'improving';
        } else if (deliveryRate < prevDeliveryRate - 2) {
            trend = 'declining';
        }

        return {
            deliveryRate,
            bounceRate,
            complaintRate,
            openRate,
            clickRate,
            unsubscribeRate,
            totalSent: currentStats.sent,
            totalDelivered: currentStats.delivered,
            trend
        };
    }

    // -------------------------------------------------------------------------
    // Alerts
    // -------------------------------------------------------------------------

    /**
     * Create a reputation alert
     */
    async createAlert(tenantId: string, data: {
        alertType: ReputationAlert['alertType'];
        value: number;
        threshold: number;
    }): Promise<Result<ReputationAlert, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        // FIX-500-056: Atomic upsert using CTE to prevent TOCTOU race condition
        const result = await this.db.query<Record<string, unknown>>(
            `WITH check_existing AS (
                SELECT 1 FROM reputation_alerts
                WHERE tenant_id = $2 AND alert_type = $3
                  AND created_at > NOW() - INTERVAL '24 hours'
                  AND acknowledged = false
                LIMIT 1
            )
            INSERT INTO reputation_alerts (id, tenant_id, alert_type, value, threshold)
            SELECT $1, $2, $3, $4, $5
            WHERE NOT EXISTS (SELECT 1 FROM check_existing)
            RETURNING *`,
            [id, tenantId, data.alertType, data.value, data.threshold]
        );

        if (!result.ok) {
            return err(result.error);
        }

        const row = result.value.rows[0];
        if (!row) {
            return err(new Error('Duplicate alert already exists'));
        }
        return ok(this.mapAlertRow(row));
    }

    /**
     * Get unacknowledged alerts for a tenant
     */
    async getActiveAlerts(tenantId: string): Promise<ReputationAlert[]> {
        const result = await this.db.query<Record<string, unknown>>(
            `SELECT * FROM reputation_alerts
             WHERE tenant_id = $1 AND acknowledged = false
             ORDER BY created_at DESC`,
            [tenantId]
        );

        if (!result.ok) throw result.error;
        return result.value.rows.map(row => this.mapAlertRow(row));
    }

    /**
     * Get all alerts for a tenant
     */
    async getAlerts(tenantId: string, options: {
        limit?: number;
        offset?: number;
        includeAcknowledged?: boolean;
    } = {}): Promise<{ alerts: ReputationAlert[]; total: number }> {
        const conditions = ['tenant_id = $1'];
        const values: unknown[] = [tenantId];
        let paramIndex = 2;

        if (!options.includeAcknowledged) {
            conditions.push('acknowledged = false');
        }

        const whereClause = conditions.join(' AND ');

        const [countResult, dataResult] = await Promise.all([
            this.db.query<{ count: string }>(
                `SELECT COUNT(*)::text as count FROM reputation_alerts WHERE ${whereClause}`,
                values
            ),
            this.db.query<Record<string, unknown>>(
                `SELECT * FROM reputation_alerts
                 WHERE ${whereClause}
                 ORDER BY created_at DESC
                 LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
                [...values, options.limit ?? 50, options.offset ?? 0]
            )
        ]);

        if (!countResult.ok) throw countResult.error;
        if (!dataResult.ok) throw dataResult.error;

        return {
            alerts: dataResult.value.rows.map(row => this.mapAlertRow(row)),
            total: parseInt(countResult.value.rows[0]?.count ?? '0', 10)
        };
    }

    /**
     * Acknowledge an alert
     */
    async acknowledgeAlert(id: string, tenantId: string): Promise<boolean> {
        const result = await this.db.query(
            `UPDATE reputation_alerts
             SET acknowledged = true
             WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        if (!result.ok) throw result.error;
        return (result.value.rowCount ?? 0) > 0;
    }

    /**
     * Acknowledge all alerts for a tenant
     */
    async acknowledgeAllAlerts(tenantId: string): Promise<number> {
        const result = await this.db.query(
            `UPDATE reputation_alerts
             SET acknowledged = true
             WHERE tenant_id = $1 AND acknowledged = false`,
            [tenantId]
        );

        if (!result.ok) throw result.error;
        return result.value.rowCount ?? 0;
    }

    // -------------------------------------------------------------------------
    // Threshold Checking
    // -------------------------------------------------------------------------

    /**
     * Check reputation thresholds and create alerts if needed
     */
    async checkThresholds(tenantId: string, thresholds: {
        bounceRate?: number;
        complaintRate?: number;
        deliveryRate?: number;
    } = {}): Promise<ReputationAlert[]> {
        const summary = await this.getSummary(tenantId);
        const alerts: ReputationAlert[] = [];

        const bounceThreshold = thresholds.bounceRate ?? 5; // 5% default
        const complaintThreshold = thresholds.complaintRate ?? 0.1; // 0.1% default
        const deliveryThreshold = thresholds.deliveryRate ?? 95; // 95% default

        // Only check if we have enough data
        if (summary.totalSent < 100) {
            return alerts;
        }

        if (summary.bounceRate > bounceThreshold) {
            const result = await this.createAlert(tenantId, {
                alertType: 'high_bounce_rate',
                value: summary.bounceRate,
                threshold: bounceThreshold
            });
            if (result.ok) {
                alerts.push(result.value);
            }
        }

        if (summary.complaintRate > complaintThreshold) {
            const result = await this.createAlert(tenantId, {
                alertType: 'high_complaint_rate',
                value: summary.complaintRate,
                threshold: complaintThreshold
            });
            if (result.ok) {
                alerts.push(result.value);
            }
        }

        if (summary.deliveryRate < deliveryThreshold) {
            const result = await this.createAlert(tenantId, {
                alertType: 'low_delivery_rate',
                value: summary.deliveryRate,
                threshold: deliveryThreshold
            });
            if (result.ok) {
                alerts.push(result.value);
            }
        }

        return alerts;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private mapStatsRow(row: Record<string, unknown>): ReputationStats {
        return {
            tenantId: row.tenant_id as string,
            date: new Date(row.date as string),
            sent: parseInt(row.sent as string, 10) || 0,
            delivered: parseInt(row.delivered as string, 10) || 0,
            bounces: parseInt(row.bounces as string, 10) || 0,
            complaints: parseInt(row.complaints as string, 10) || 0,
            opens: parseInt(row.opens as string, 10) || 0,
            clicks: parseInt(row.clicks as string, 10) || 0,
            unsubscribes: parseInt(row.unsubscribes as string, 10) || 0,
        };
    }

    private mapAlertRow(row: Record<string, unknown>): ReputationAlert {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            alertType: row.alert_type as ReputationAlert['alertType'],
            value: parseFloat(row.value as string),
            threshold: parseFloat(row.threshold as string),
            acknowledged: row.acknowledged as boolean,
            createdAt: new Date(row.created_at as string),
        };
    }
}
