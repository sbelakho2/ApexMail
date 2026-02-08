/**
 * Inbound Messages Repository
 * 
 * Data access for received inbound emails and unmatched bounces/complaints
 */

import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { ok, err, type Result } from '@apexmail/lib';

// =============================================================================
// Types
// =============================================================================

export interface InboundMessage {
    id: string;
    tenantId: string;
    domainId?: string;
    messageIdHeader?: string;
    fromAddress: string;
    toAddress: string;
    subject?: string;
    textBody?: string;
    htmlBody?: string;
    rawMessage?: Buffer;
    headers?: Record<string, string | string[]>;
    attachments?: Array<{
        filename: string;
        contentType: string;
        size: number;
        contentId?: string;
        checksum?: string;
    }>;
    spamScore?: number;
    spamStatus?: string;
    virusStatus?: string;
    spfResult?: string;
    dkimResult?: string;
    dmarcResult?: string;
    receivedAt: Date;
    clientIp?: string;
    sessionId?: string;
}

export interface InboundMessageInsert {
    tenantId: string;
    domainId?: string;
    messageIdHeader?: string;
    fromAddress: string;
    toAddress: string;
    subject?: string;
    textBody?: string;
    htmlBody?: string;
    rawMessage?: Buffer;
    headers?: Record<string, string | string[]>;
    attachments?: InboundMessage['attachments'];
    spamScore?: number;
    spamStatus?: string;
    virusStatus?: string;
    spfResult?: string;
    dkimResult?: string;
    dmarcResult?: string;
    clientIp?: string;
    sessionId?: string;
}

export interface UnmatchedBounce {
    id: string;
    recipient?: string;
    fromAddress?: string;
    bounceType?: string;
    bounceSubtype?: string;
    diagnosticCode?: string;
    originalMessageId?: string;
    rawMessage?: Buffer;
    createdAt: Date;
}

export interface UnmatchedComplaint {
    id: string;
    recipient?: string;
    fromAddress?: string;
    feedbackType?: string;
    userAgent?: string;
    originalMessageId?: string;
    originalRecipient?: string;
    rawMessage?: Buffer;
    createdAt: Date;
}

// =============================================================================
// Repository
// =============================================================================

export class InboundMessagesRepository {
    constructor(private pool: Pool) {}

    // -------------------------------------------------------------------------
    // Inbound Messages
    // -------------------------------------------------------------------------

    async create(data: InboundMessageInsert): Promise<Result<InboundMessage, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO inbound_messages (
                    id, tenant_id, domain_id, message_id_header,
                    from_address, to_address, subject, text_body, html_body,
                    raw_message, headers, attachments,
                    spam_score, spam_status, virus_status,
                    spf_result, dkim_result, dmarc_result,
                    client_ip, session_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                RETURNING *`,
                [
                    id,
                    data.tenantId,
                    data.domainId,
                    data.messageIdHeader,
                    data.fromAddress,
                    data.toAddress,
                    data.subject,
                    data.textBody,
                    data.htmlBody,
                    data.rawMessage,
                    data.headers ? JSON.stringify(data.headers) : null,
                    data.attachments ? JSON.stringify(data.attachments) : null,
                    data.spamScore,
                    data.spamStatus,
                    data.virusStatus,
                    data.spfResult,
                    data.dkimResult,
                    data.dmarcResult,
                    data.clientIp,
                    data.sessionId
                ]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to create inbound message'));
            }
            return ok(this.mapInboundRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async findById(id: string, tenantId: string): Promise<InboundMessage | null> {
        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM inbound_messages WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return result.rows[0] ? this.mapInboundRow(result.rows[0]) : null;
    }

    async findByTenant(
        tenantId: string,
        options: {
            limit?: number;
            offset?: number;
            fromAddress?: string;
            toAddress?: string;
            since?: Date;
            until?: Date;
        } = {}
    ): Promise<{ messages: InboundMessage[]; total: number }> {
        const conditions: string[] = ['tenant_id = $1'];
        const values: unknown[] = [tenantId];
        let paramIndex = 2;

        if (options.fromAddress) {
            conditions.push(`from_address ILIKE $${paramIndex++}`);
            values.push(`%${options.fromAddress}%`);
        }
        if (options.toAddress) {
            conditions.push(`to_address ILIKE $${paramIndex++}`);
            values.push(`%${options.toAddress}%`);
        }
        if (options.since) {
            conditions.push(`received_at >= $${paramIndex++}`);
            values.push(options.since);
        }
        if (options.until) {
            conditions.push(`received_at <= $${paramIndex++}`);
            values.push(options.until);
        }

        const whereClause = conditions.join(' AND ');

        const [countResult, dataResult] = await Promise.all([
            this.pool.query<{ count: string }>(
                `SELECT COUNT(*)::text as count FROM inbound_messages WHERE ${whereClause}`,
                values
            ),
            this.pool.query<Record<string, unknown>>(
                `SELECT * FROM inbound_messages 
                 WHERE ${whereClause}
                 ORDER BY received_at DESC
                 LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
                [...values, options.limit ?? 50, options.offset ?? 0]
            )
        ]);

        return {
            messages: dataResult.rows.map(row => this.mapInboundRow(row)),
            total: parseInt(countResult.rows[0]?.count ?? '0', 10)
        };
    }

    async delete(id: string, tenantId: string): Promise<boolean> {
        const result = await this.pool.query(
            `DELETE FROM inbound_messages WHERE id = $1 AND tenant_id = $2`,
            [id, tenantId]
        );

        return (result.rowCount ?? 0) > 0;
    }

    // -------------------------------------------------------------------------
    // Unmatched Bounces
    // -------------------------------------------------------------------------

    async createUnmatchedBounce(data: Omit<UnmatchedBounce, 'id' | 'createdAt'>): Promise<Result<UnmatchedBounce, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO unmatched_bounces (
                    id, recipient, from_address, bounce_type, bounce_subtype,
                    diagnostic_code, original_message_id, raw_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *`,
                [
                    id,
                    data.recipient,
                    data.fromAddress,
                    data.bounceType,
                    data.bounceSubtype,
                    data.diagnosticCode,
                    data.originalMessageId,
                    data.rawMessage
                ]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to create unmatched bounce'));
            }
            return ok(this.mapBounceRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async findUnmatchedBounces(options: {
        limit?: number;
        offset?: number;
        since?: Date;
    } = {}): Promise<UnmatchedBounce[]> {
        const conditions: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (options.since) {
            conditions.push(`created_at >= $${paramIndex++}`);
            values.push(options.since);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM unmatched_bounces 
             ${whereClause}
             ORDER BY created_at DESC
             LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
            [...values, options.limit ?? 100, options.offset ?? 0]
        );

        return result.rows.map(row => this.mapBounceRow(row));
    }

    // -------------------------------------------------------------------------
    // Unmatched Complaints
    // -------------------------------------------------------------------------

    async createUnmatchedComplaint(data: Omit<UnmatchedComplaint, 'id' | 'createdAt'>): Promise<Result<UnmatchedComplaint, Error>> {
        const id = randomUUID().replace(/-/g, '').slice(0, 26);

        try {
            const result = await this.pool.query<Record<string, unknown>>(
                `INSERT INTO unmatched_complaints (
                    id, recipient, from_address, feedback_type, user_agent,
                    original_message_id, original_recipient, raw_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *`,
                [
                    id,
                    data.recipient,
                    data.fromAddress,
                    data.feedbackType,
                    data.userAgent,
                    data.originalMessageId,
                    data.originalRecipient,
                    data.rawMessage
                ]
            );

            const row = result.rows[0];
            if (!row) {
                return err(new Error('Failed to create unmatched complaint'));
            }
            return ok(this.mapComplaintRow(row));
        } catch (error) {
            return err(error instanceof Error ? error : new Error(String(error)));
        }
    }

    async findUnmatchedComplaints(options: {
        limit?: number;
        offset?: number;
        since?: Date;
    } = {}): Promise<UnmatchedComplaint[]> {
        const conditions: string[] = [];
        const values: unknown[] = [];
        let paramIndex = 1;

        if (options.since) {
            conditions.push(`created_at >= $${paramIndex++}`);
            values.push(options.since);
        }

        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

        const result = await this.pool.query<Record<string, unknown>>(
            `SELECT * FROM unmatched_complaints 
             ${whereClause}
             ORDER BY created_at DESC
             LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
            [...values, options.limit ?? 100, options.offset ?? 0]
        );

        return result.rows.map(row => this.mapComplaintRow(row));
    }

    // -------------------------------------------------------------------------
    // Cleanup
    // -------------------------------------------------------------------------

    // FIX-500-052: Batch deletes with LIMIT to avoid long-running table locks
    async cleanupOld(olderThanDays: number = 30, batchSize: number = 1000): Promise<{ inbound: number; bounces: number; complaints: number }> {
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - olderThanDays);

        const batchDelete = async (table: string, col: string): Promise<number> => {
            let total = 0;
            while (true) {
                const result = await this.pool.query<{ count: string }>(
                    `WITH deleted AS (
                        DELETE FROM ${table}
                        WHERE id IN (
                            SELECT id FROM ${table} WHERE ${col} < $1 LIMIT $2
                        )
                        RETURNING 1
                    ) SELECT COUNT(*) as count FROM deleted`,
                    [cutoff, batchSize]
                );
                const n = parseInt(result.rows[0]?.count ?? '0', 10);
                total += n;
                if (n < batchSize) break;
            }
            return total;
        };

        return {
            inbound: await batchDelete('inbound_messages', 'received_at'),
            bounces: await batchDelete('unmatched_bounces', 'created_at'),
            complaints: await batchDelete('unmatched_complaints', 'created_at'),
        };
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private mapInboundRow(row: Record<string, unknown>): InboundMessage {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string,
            domainId: row.domain_id as string | undefined,
            messageIdHeader: row.message_id_header as string | undefined,
            fromAddress: row.from_address as string,
            toAddress: row.to_address as string,
            subject: row.subject as string | undefined,
            textBody: row.text_body as string | undefined,
            htmlBody: row.html_body as string | undefined,
            rawMessage: row.raw_message as Buffer | undefined,
            headers: row.headers as Record<string, string | string[]> | undefined,
            attachments: row.attachments as InboundMessage['attachments'],
            spamScore: row.spam_score ? parseFloat(row.spam_score as string) : undefined,
            spamStatus: row.spam_status as string | undefined,
            virusStatus: row.virus_status as string | undefined,
            spfResult: row.spf_result as string | undefined,
            dkimResult: row.dkim_result as string | undefined,
            dmarcResult: row.dmarc_result as string | undefined,
            receivedAt: new Date(row.received_at as string),
            clientIp: row.client_ip as string | undefined,
            sessionId: row.session_id as string | undefined,
        };
    }

    private mapBounceRow(row: Record<string, unknown>): UnmatchedBounce {
        return {
            id: row.id as string,
            recipient: row.recipient as string | undefined,
            fromAddress: row.from_address as string | undefined,
            bounceType: row.bounce_type as string | undefined,
            bounceSubtype: row.bounce_subtype as string | undefined,
            diagnosticCode: row.diagnostic_code as string | undefined,
            originalMessageId: row.original_message_id as string | undefined,
            rawMessage: row.raw_message as Buffer | undefined,
            createdAt: new Date(row.created_at as string),
        };
    }

    private mapComplaintRow(row: Record<string, unknown>): UnmatchedComplaint {
        return {
            id: row.id as string,
            recipient: row.recipient as string | undefined,
            fromAddress: row.from_address as string | undefined,
            feedbackType: row.feedback_type as string | undefined,
            userAgent: row.user_agent as string | undefined,
            originalMessageId: row.original_message_id as string | undefined,
            originalRecipient: row.original_recipient as string | undefined,
            rawMessage: row.raw_message as Buffer | undefined,
            createdAt: new Date(row.created_at as string),
        };
    }
}
