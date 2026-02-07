/**
 * Webhooks Repository
 * 
 * Data access for webhook configurations and delivery queue
 */

import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { ok, err, type Result } from '@apexmail/lib';

// =============================================================================
// Types
// =============================================================================

export interface Webhook {
    id: string;
    tenantId: string;
    name: string;
    url: string;
    secret: string;
    events: string[];
    enabled: boolean;
    headers?: Record<string, string>;
    failureCount: number;
    lastTriggeredAt?: Date;
    lastSuccessAt?: Date;
    lastFailureAt?: Date;
    disabledReason?: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface WebhookInsert {
    tenantId: string;
    name: string;
    url: string;
    secret: string;
    events?: string[];
    headers?: Record<string, string>;
}

export interface WebhookUpdate {
    name?: string;
    url?: string;
    secret?: string;
    events?: string[];
    enabled?: boolean;
    headers?: Record<string, string>;
}

export interface WebhookQueueItem {
    id: string;
    webhookId: string;
    tenantId: string;
    eventType: string;
    payload: unknown;
    status: 'pending' | 'delivered' | 'failed';
    attempt: number;
    maxAttempts: number;
    nextAttemptAt?: Date;
    responseStatus?: number;
    responseBody?: string;
    errorMessage?: string;
    createdAt: Date;
    completedAt?: Date;
}

export interface WebhookQueueInsert {
    webhookId: string;
    tenantId: string;
    eventType: string;
    payload: unknown;
}

// =============================================================================
// Repository
// =============================================================================

export class WebhooksRepository {
    constructor(private pool: Pool) {}

    // -------------------------------------------------------------------------
    // Webhook CRUD
    // -------------------------------------------------------------------------

    async create(data: WebhookInsert): Promise<Result<Webhook, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);
        
        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO webhooks (id, tenant_id, name, url, secret, events, headers)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (tenant_id, url) DO NOTHING
                 RETURNING *`,
                [
                    id,
                    data.tenantId,
                    data.name,
                    data.url,
                    data.secret,
                    JSON.stringify(data.events ?? ['*']),
                    data.headers ? JSON.stringify(data.headers) : null
                ]
            );

            const row = result.rows[0];
            if (!row) {
                // B-050: ON CONFLICT (tenant_id, url) DO NOTHING produces no rows on duplicate
                return err(new Error('Webhook URL already exists for this tenant'));
            }
            return ok(this.mapRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async findById(id: string, tenantId: string): Promise<Webhook | null> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM webhooks WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );
        
        return result.rows[0] ? this.mapRow(result.rows[0]) : null;
    }

    async findByTenant(tenantId: string): Promise<Webhook[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC`,
            [tenantId]
        );
        
        return result.rows.map(row => this.mapRow(row));
    }

    async findEnabledByEvent(tenantId: string, eventType: string): Promise<Webhook[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM webhooks 
             WHERE tenant_id = $1 
             AND enabled = true 
             AND (events @> '["*"]'::jsonb OR events @> $2::jsonb)`,
            [tenantId, JSON.stringify([eventType])]
        );
        
        return result.rows.map(row => this.mapRow(row));
    }

    async update(id: string, tenantId: string, data: WebhookUpdate): Promise<Result<Webhook, Error>> {
        const fields: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (data.name !== undefined) {
            fields.push(`name = $${paramIndex++}`);
            values.push(data.name);
        }
        if (data.url !== undefined) {
            fields.push(`url = $${paramIndex++}`);
            values.push(data.url);
        }
        if (data.secret !== undefined) {
            fields.push(`secret = $${paramIndex++}`);
            values.push(data.secret);
        }
        if (data.events !== undefined) {
            fields.push(`events = $${paramIndex++}`);
            values.push(JSON.stringify(data.events));
        }
        if (data.enabled !== undefined) {
            fields.push(`enabled = $${paramIndex++}`);
            values.push(data.enabled);
        }
        if (data.headers !== undefined) {
            fields.push(`headers = $${paramIndex++}`);
            values.push(JSON.stringify(data.headers));
        }

        if (fields.length === 0) {
            const existing = await this.findById(id, tenantId);
            return existing ? ok(existing) : err(new Error('Webhook not found'));
        }

        fields.push('updated_at = NOW()');
        values.push(id, tenantId);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `UPDATE webhooks 
                 SET ${fields.join(', ')}
                 WHERE id = $${paramIndex++} AND tenant_id = $${paramIndex}
                 RETURNING *`,
                values
            );

            if (result.rows.length === 0) {
                return err(new Error('Webhook not found'));
            }

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Webhook not found'));
            }
            return ok(this.mapRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async delete(id: string, tenantId: string): Promise<boolean> {
        const result = await this.pool.query(
            `DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );
        
        return (result.rowCount ?? 0) > 0;
    }

    /**
     * F-200: Rotate the signing secret for a webhook.
     * Generates a new cryptographically-random secret, persists it, and returns
     * the updated webhook so the caller can distribute the new secret.
     */
    async rotateSecret(id: string, tenantId: string): Promise<Result<Webhook, Error>> {
        const newSecret = randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '');

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `UPDATE webhooks
                 SET secret = $1, updated_at = NOW()
                 WHERE id = $2 AND tenant_id = $3
                 RETURNING *`,
                [newSecret, id, tenantId]
            );

            if (result.rows.length === 0) {
                return err(new Error('Webhook not found'));
            }

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Webhook not found'));
            }
            return ok(this.mapRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async recordTrigger(id: string, success: boolean, errorMessage?: string): Promise<void> {
        if (success) {
            await this.pool.query(
                `UPDATE webhooks 
                 SET last_triggered_at = NOW(),
                     last_success_at = NOW(),
                     failure_count = 0,
                     disabled_reason = NULL
                 WHERE id = $1`,
                [id]
            );
        } else {
            await this.pool.query(
                `UPDATE webhooks 
                 SET last_triggered_at = NOW(),
                     last_failure_at = NOW(),
                     failure_count = failure_count + 1,
                     enabled = CASE WHEN failure_count >= 9 THEN false ELSE enabled END,
                     disabled_reason = CASE WHEN failure_count >= 9 THEN $2 ELSE disabled_reason END
                 WHERE id = $1`,
                [id, errorMessage ?? 'Too many consecutive failures']
            );
        }
    }

    // -------------------------------------------------------------------------
    // Webhook Queue
    // -------------------------------------------------------------------------

    async enqueue(data: WebhookQueueInsert): Promise<Result<WebhookQueueItem, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO webhook_queue (id, webhook_id, tenant_id, event_type, payload, next_attempt_at)
                 VALUES ($1, $2, $3, $4, $5, NOW())
                 RETURNING *`,
                [id, data.webhookId, data.tenantId, data.eventType, JSON.stringify(data.payload)]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to enqueue webhook'));
            }
            return ok(this.mapQueueRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    /**
     * FIX-013: Set status to 'processing' instead of back to 'pending'.
     * Previously items remained in 'pending' during delivery, meaning
     * they could be re-dequeued by another worker once next_attempt_at
     * passed — causing duplicate deliveries.
     */
    async dequeue(batchSize: number = 10): Promise<WebhookQueueItem[]> {
        const result = await this.pool.query<Record<string, unknown>>(
            `UPDATE webhook_queue
             SET status = 'processing',
                 attempt = attempt + 1,
                 next_attempt_at = NOW() + INTERVAL '1 minute' * POW(2, attempt)
             WHERE id IN (
                 SELECT id FROM webhook_queue
                 WHERE status = 'pending'
                 AND next_attempt_at <= NOW()
                 AND attempt < max_attempts
                 ORDER BY created_at
                 FOR UPDATE SKIP LOCKED
                 LIMIT $1
             )
             RETURNING *`,
            [batchSize]
        );

        return result.rows.map(row => this.mapQueueRow(row));
    }

    async markDelivered(id: string, responseStatus: number, responseBody?: string): Promise<void> {
        await this.pool.query(
            `UPDATE webhook_queue
             SET status = 'delivered',
                 response_status = $2,
                 response_body = $3,
                 completed_at = NOW()
             WHERE id = $1`,
            [id, responseStatus, responseBody]
        );
    }

    async markFailed(id: string, errorMessage: string): Promise<void> {
        await this.pool.query(
            `UPDATE webhook_queue
             SET status = CASE WHEN attempt >= max_attempts THEN 'failed' ELSE status END,
                 error_message = $2,
                 completed_at = CASE WHEN attempt >= max_attempts THEN NOW() ELSE completed_at END
             WHERE id = $1`,
            [id, errorMessage]
        );
    }

    async getQueueStats(tenantId: string): Promise<{
        pending: number;
        delivered: number;
        failed: number;
    }> {
        const result = await this.pool.query<{ status: string; count: string }>(
            `SELECT status, COUNT(*)::text as count
             FROM webhook_queue
             WHERE tenant_id = $1
             AND created_at > NOW() - INTERVAL '24 hours'
             GROUP BY status`,
            [tenantId]
        );

        const stats = { pending: 0, delivered: 0, failed: 0 };
        for (const row of result.rows) {
            if (row.status === 'pending') stats.pending = parseInt(row.count, 10);
            if (row.status === 'delivered') stats.delivered = parseInt(row.count, 10);
            if (row.status === 'failed') stats.failed = parseInt(row.count, 10);
        }

        return stats;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private mapRow(row: Record<string, unknown>): Webhook {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            name: row.name as string,
            url: row.url as string,
            secret: row.secret as string,
            events: row.events as string[],
            enabled: row.enabled as boolean,
            headers: row.headers as Record<string, string> | undefined,
            failureCount: row.failure_count as number,
            lastTriggeredAt: row.last_triggered_at ? new Date(row.last_triggered_at as string) : undefined,
            lastSuccessAt: row.last_success_at ? new Date(row.last_success_at as string) : undefined,
            lastFailureAt: row.last_failure_at ? new Date(row.last_failure_at as string) : undefined,
            disabledReason: row.disabled_reason as string | undefined,
            createdAt: new Date(row.created_at as string),
            updatedAt: new Date(row.updated_at as string),
        };
    }

    private mapQueueRow(row: Record<string, unknown>): WebhookQueueItem {
        return {
            id: row.id as string,
            webhookId: row.webhook_id as string,
            tenantId: row.tenant_id as string,
            eventType: row.event_type as string,
            payload: row.payload,
            status: row.status as 'pending' | 'delivered' | 'failed',
            attempt: row.attempt as number,
            maxAttempts: row.max_attempts as number,
            nextAttemptAt: row.next_attempt_at ? new Date(row.next_attempt_at as string) : undefined,
            responseStatus: row.response_status as number | undefined,
            responseBody: row.response_body as string | undefined,
            errorMessage: row.error_message as string | undefined,
            createdAt: new Date(row.created_at as string),
            completedAt: row.completed_at ? new Date(row.completed_at as string) : undefined,
        };
    }
}
