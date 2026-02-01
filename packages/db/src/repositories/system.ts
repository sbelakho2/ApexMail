/**
 * System Repository
 * 
 * Data access for system-wide alerts, migrations, and operational data
 */

import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { ok, err, type Result } from '@apexmail/lib';

// =============================================================================
// Types
// =============================================================================

export interface SystemAlert {
    id: string;
    alertType: string;
    severity: 'info' | 'warning' | 'error' | 'critical';
    title: string;
    message?: string;
    metadata?: Record<string, unknown>;
    acknowledged: boolean;
    acknowledgedBy?: string;
    acknowledgedAt?: Date;
    createdAt: Date;
}

export interface IdempotencyRecord {
    id: string;
    tenantId: string;
    idempotencyKey: string;
    requestHash: string;
    responseStatus: number;
    responseBody: unknown;
    createdAt: Date;
    expiresAt: Date;
}

export interface CompactionLogEntry {
    date: Date;
    status: 'pending' | 'running' | 'completed' | 'failed';
    eventCount: number;
    completedAt?: Date;
}

export interface ReconciliationLogEntry {
    id: string;
    date: Date;
    status: 'pending' | 'running' | 'completed' | 'failed';
    messagesSent: number;
    eventsExpected: number;
    eventsFound: number;
    discrepancyCount: number;
    discrepancyDetails?: unknown;
    durationMs?: number;
    createdAt: Date;
    updatedAt?: Date;
}

// =============================================================================
// Repository
// =============================================================================

export class SystemRepository {
    constructor(private pool: Pool) {}

    // -------------------------------------------------------------------------
    // System Alerts
    // -------------------------------------------------------------------------

    async createAlert(data: {
        alertType: string;
        severity: SystemAlert['severity'];
        title: string;
        message?: string;
        metadata?: Record<string, unknown>;
    }): Promise<Result<SystemAlert, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO system_alerts (id, alert_type, severity, title, message, metadata)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING *`,
                [
                    id,
                    data.alertType,
                    data.severity,
                    data.title,
                    data.message,
                    data.metadata ? JSON.stringify(data.metadata) : null
                ]
            );

            return ok(this.mapAlertRow(result.rows[0]));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async getActiveAlerts(): Promise<SystemAlert[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM system_alerts
             WHERE acknowledged = false
             ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'error' THEN 2 
                    WHEN 'warning' THEN 3 
                    ELSE 4 
                END,
                created_at DESC`
        );

        return result.rows.map(row => this.mapAlertRow(row));
    }

    async getAlerts(options: {
        limit?: number;
        offset?: number;
        severity?: SystemAlert['severity'];
        alertType?: string;
        includeAcknowledged?: boolean;
    } = {}): Promise<{ alerts: SystemAlert[]; total: number }> {
        const conditions: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (!options.includeAcknowledged) {
            conditions.push('acknowledged = false');
        }
        if (options.severity) {
            conditions.push(`severity = $${paramIndex++}`);
            values.push(options.severity);
        }
        if (options.alertType) {
            conditions.push(`alert_type = $${paramIndex++}`);
            values.push(options.alertType);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const [countResult, dataResult] = await Promise.all([
            this.pool.query<{ count: string }>(
                `SELECT COUNT(*)::text as count FROM system_alerts ${whereClause}`,
                values
            ),
            this.pool.query<Record<string, unknown>>(
                `SELECT * FROM system_alerts
                 ${whereClause}
                 ORDER BY created_at DESC
                 LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
                [...values, options.limit ?? 50, options.offset ?? 0]
            )
        ]);

        return {
            alerts: dataResult.rows.map(row => this.mapAlertRow(row)),
            total: parseInt(countResult.rows[0].count, 10)
        };
    }

    async acknowledgeAlert(id: string, acknowledgedBy?: string): Promise<boolean> {
        const result = await this.pool.query(
            `UPDATE system_alerts
             SET acknowledged = true,
                 acknowledged_by = $2,
                 acknowledged_at = NOW()
             WHERE id = $1`,
            [id, acknowledgedBy]
        );

        return (result.rowCount ?? 0) > 0;
    }

    // -------------------------------------------------------------------------
    // Idempotency
    // -------------------------------------------------------------------------

    async getIdempotencyRecord(tenantId: string, key: string): Promise<IdempotencyRecord | null> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM idempotency_keys
             WHERE tenant_id = $1 AND idempotency_key = $2 AND expires_at > NOW()`,
            [tenantId, key]
        );

        return result.rows[0] ? this.mapIdempotencyRow(result.rows[0]) : null;
    }

    async createIdempotencyRecord(data: {
        tenantId: string;
        idempotencyKey: string;
        requestHash: string;
        responseStatus: number;
        responseBody: unknown;
        ttlSeconds?: number;
    }): Promise<Result<IdempotencyRecord, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);
        const ttl = data.ttlSeconds ?? 86400; // 24 hours default

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO idempotency_keys (
                    id, tenant_id, idempotency_key, request_hash,
                    response_status, response_body, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '1 second' * $7)
                ON CONFLICT (tenant_id, idempotency_key) DO UPDATE
                SET response_status = EXCLUDED.response_status,
                    response_body = EXCLUDED.response_body,
                    expires_at = NOW() + INTERVAL '1 second' * $7
                RETURNING *`,
                [
                    id,
                    data.tenantId,
                    data.idempotencyKey,
                    data.requestHash,
                    data.responseStatus,
                    JSON.stringify(data.responseBody),
                    ttl
                ]
            );

            return ok(this.mapIdempotencyRow(result.rows[0]));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async cleanupExpiredIdempotencyRecords(): Promise<number> {
        const result = await this.pool.query(
            `DELETE FROM idempotency_keys WHERE expires_at < NOW()`
        );

        return result.rowCount ?? 0;
    }

    // -------------------------------------------------------------------------
    // Compaction Log
    // -------------------------------------------------------------------------

    async getCompactionLog(date: Date): Promise<CompactionLogEntry | null> {
        const dateStr = date.toISOString().split('T')[0];
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM compaction_log WHERE date = $1`,
            [dateStr]
        );

        return result.rows[0] ? this.mapCompactionRow(result.rows[0]) : null;
    }

    async upsertCompactionLog(date: Date, data: {
        status: CompactionLogEntry['status'];
        eventCount?: number;
        completedAt?: Date;
    }): Promise<Result<CompactionLogEntry, Error>> {
        const dateStr = date.toISOString().split('T')[0];

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO compaction_log (date, status, event_count, completed_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (date) DO UPDATE
                 SET status = EXCLUDED.status,
                     event_count = COALESCE(EXCLUDED.event_count, compaction_log.event_count),
                     completed_at = EXCLUDED.completed_at
                 RETURNING *`,
                [dateStr, data.status, data.eventCount ?? 0, data.completedAt]
            );

            return ok(this.mapCompactionRow(result.rows[0]));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async getPendingCompactionDates(since: Date): Promise<Date[]> {
        const result = await this.pool.query<{ date: string }>(
            `SELECT DISTINCT date::text as date 
             FROM events 
             WHERE timestamp >= $1 
             AND date NOT IN (
                 SELECT date FROM compaction_log WHERE status = 'completed'
             )
             ORDER BY date`,
            [since]
        );

        return result.rows.map(row => new Date(row.date));
    }

    // -------------------------------------------------------------------------
    // Reconciliation Log
    // -------------------------------------------------------------------------

    async getReconciliationLog(date: Date): Promise<ReconciliationLogEntry | null> {
        const dateStr = date.toISOString().split('T')[0];
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM reconciliation_log WHERE date = $1`,
            [dateStr]
        );

        return result.rows[0] ? this.mapReconciliationRow(result.rows[0]) : null;
    }

    async createReconciliationLog(date: Date): Promise<Result<ReconciliationLogEntry, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);
        const dateStr = date.toISOString().split('T')[0];

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO reconciliation_log (id, date, status)
                 VALUES ($1, $2, 'pending')
                 ON CONFLICT (date) DO NOTHING
                 RETURNING *`,
                [id, dateStr]
            );

            if (result.rows.length === 0) {
                // Already exists, fetch it
                const existing = await this.getReconciliationLog(date);
                return existing ? ok(existing) : err(new Error('Failed to create reconciliation log'));
            }

            return ok(this.mapReconciliationRow(result.rows[0]));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async updateReconciliationLog(id: string, data: Partial<{
        status: ReconciliationLogEntry['status'];
        messagesSent: number;
        eventsExpected: number;
        eventsFound: number;
        discrepancyCount: number;
        discrepancyDetails: unknown;
        durationMs: number;
    }>): Promise<Result<ReconciliationLogEntry, Error>> {
        const fields: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (data.status !== undefined) {
            fields.push(`status = $${paramIndex++}`);
            values.push(data.status);
        }
        if (data.messagesSent !== undefined) {
            fields.push(`messages_sent = $${paramIndex++}`);
            values.push(data.messagesSent);
        }
        if (data.eventsExpected !== undefined) {
            fields.push(`events_expected = $${paramIndex++}`);
            values.push(data.eventsExpected);
        }
        if (data.eventsFound !== undefined) {
            fields.push(`events_found = $${paramIndex++}`);
            values.push(data.eventsFound);
        }
        if (data.discrepancyCount !== undefined) {
            fields.push(`discrepancy_count = $${paramIndex++}`);
            values.push(data.discrepancyCount);
        }
        if (data.discrepancyDetails !== undefined) {
            fields.push(`discrepancy_details = $${paramIndex++}`);
            values.push(JSON.stringify(data.discrepancyDetails));
        }
        if (data.durationMs !== undefined) {
            fields.push(`duration_ms = $${paramIndex++}`);
            values.push(data.durationMs);
        }

        fields.push('updated_at = NOW()');
        values.push(id);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `UPDATE reconciliation_log
                 SET ${fields.join(', ')}
                 WHERE id = $${paramIndex}
                 RETURNING *`,
                values
            );

            if (result.rows.length === 0) {
                return err(new Error('Reconciliation log not found'));
            }

            return ok(this.mapReconciliationRow(result.rows[0]));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async getRecentReconciliations(limit: number = 30): Promise<ReconciliationLogEntry[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM reconciliation_log
             ORDER BY date DESC
             LIMIT $1`,
            [limit]
        );

        return result.rows.map(row => this.mapReconciliationRow(row));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private mapAlertRow(row: Record<string, unknown>): SystemAlert {
        return {
            id: row.id as string,
            alertType: row.alert_type as string,
            severity: row.severity as SystemAlert['severity'],
            title: row.title as string,
            message: row.message as string | undefined,
            metadata: row.metadata as Record<string, unknown> | undefined,
            acknowledged: row.acknowledged as boolean,
            acknowledgedBy: row.acknowledged_by as string | undefined,
            acknowledgedAt: row.acknowledged_at ? new Date(row.acknowledged_at as string) : undefined,
            createdAt: new Date(row.created_at as string),
        };
    }

    private mapIdempotencyRow(row: Record<string, unknown>): IdempotencyRecord {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            idempotencyKey: row.idempotency_key as string,
            requestHash: row.request_hash as string,
            responseStatus: row.response_status as number,
            responseBody: row.response_body,
            createdAt: new Date(row.created_at as string),
            expiresAt: new Date(row.expires_at as string),
        };
    }

    private mapCompactionRow(row: Record<string, unknown>): CompactionLogEntry {
        return {
            date: new Date(row.date as string),
            status: row.status as CompactionLogEntry['status'],
            eventCount: row.event_count as number,
            completedAt: row.completed_at ? new Date(row.completed_at as string) : undefined,
        };
    }

    private mapReconciliationRow(row: Record<string, unknown>): ReconciliationLogEntry {
        return {
            id: row.id as string,
            date: new Date(row.date as string),
            status: row.status as ReconciliationLogEntry['status'],
            messagesSent: row.messages_sent as number,
            eventsExpected: row.events_expected as number,
            eventsFound: row.events_found as number,
            discrepancyCount: row.discrepancy_count as number,
            discrepancyDetails: row.discrepancy_details,
            durationMs: row.duration_ms as number | undefined,
            createdAt: new Date(row.created_at as string),
            updatedAt: row.updated_at ? new Date(row.updated_at as string) : undefined,
        };
    }
}
