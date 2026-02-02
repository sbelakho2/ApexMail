/**
 * Hash-Chain Audit Logger
 *
 * Provides cryptographically signed, tamper-evident audit logging
 * using hash chains. Each log entry contains a hash of the previous
 * entry, creating an immutable, verifiable audit trail.
 */

import * as CryptoJS from 'crypto-js';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { generateUUID, timingSafeCompareBuffers } from '@apexmail/lib/crypto';
import {
    AuditLogEntry,
    AuditAction,
    AuditResource,
    AuditLogQuery,
} from '../types';

interface LogContext {
    tenantId?: string;
    userId?: string;
    sessionId?: string;
    ipAddress?: string;
    userAgent?: string;
}

interface ChainValidationResult {
    valid: boolean;
    entriesChecked: number;
    firstInvalidEntry?: string;
    error?: string;
}

export class AuditLogger {
    private db: Pool;
    private redis: Redis;
    private signingKey: string;
    private lastHash: Map<string, string> = new Map();

    constructor(db: Pool, redis: Redis, signingKey: string) {
        this.db = db;
        this.redis = redis;
        this.signingKey = signingKey;
    }

    /**
     * Initialize the audit logger and load last hashes
     */
    async initialize(): Promise<void> {
        await this.loadLastHashes();
    }

    /**
     * Log an audit event
     */
    async log(
        action: AuditAction,
        resource: AuditResource,
        resourceId: string | null,
        details: Record<string, unknown>,
        outcome: 'success' | 'failure',
        errorMessage: string | null,
        context: LogContext
    ): Promise<AuditLogEntry> {
        const id = generateUUID();
        const timestamp = new Date();

        // Get the previous hash for this tenant (or global if no tenant)
        const chainKey = context.tenantId || 'global';
        const previousHash = await this.getLastHash(chainKey);

        // Create the entry data for hashing
        const entryData = {
            id,
            tenantId: context.tenantId || null,
            userId: context.userId || null,
            sessionId: context.sessionId || null,
            action,
            resource,
            resourceId,
            details,
            outcome,
            errorMessage,
            timestamp: timestamp.toISOString(),
            previousHash,
        };

        // Calculate hash of this entry
        const hash = this.calculateHash(entryData);

        // Create signature
        const signature = this.sign(hash);

        const entry: AuditLogEntry = {
            id,
            tenantId: context.tenantId || null,
            userId: context.userId || null,
            sessionId: context.sessionId || null,
            action,
            resource,
            resourceId,
            details,
            ipAddress: context.ipAddress || null,
            userAgent: context.userAgent || null,
            outcome,
            errorMessage,
            timestamp,
            hash,
            previousHash,
            signature,
        };

        await this.saveEntry(entry);
        await this.updateLastHash(chainKey, hash);

        return entry;
    }

    /**
     * Quick log helper methods
     */
    async logCreate(
        resource: AuditResource,
        resourceId: string,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('create', resource, resourceId, details, 'success', null, context);
    }

    async logRead(
        resource: AuditResource,
        resourceId: string,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('read', resource, resourceId, details, 'success', null, context);
    }

    async logUpdate(
        resource: AuditResource,
        resourceId: string,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('update', resource, resourceId, details, 'success', null, context);
    }

    async logDelete(
        resource: AuditResource,
        resourceId: string,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('delete', resource, resourceId, details, 'success', null, context);
    }

    async logLogin(
        userId: string,
        success: boolean,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log(
            'login',
            'user',
            userId,
            details,
            success ? 'success' : 'failure',
            success ? null : 'Authentication failed',
            context
        );
    }

    async logLogout(userId: string, context: LogContext): Promise<AuditLogEntry> {
        return this.log('logout', 'user', userId, {}, 'success', null, context);
    }

    async logExport(
        resource: AuditResource,
        resourceId: string | null,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('export', resource, resourceId, details, 'success', null, context);
    }

    async logSend(
        messageId: string,
        details: Record<string, unknown>,
        context: LogContext
    ): Promise<AuditLogEntry> {
        return this.log('send', 'message', messageId, details, 'success', null, context);
    }

    /**
     * Query audit logs
     */
    async query(query: AuditLogQuery): Promise<{
        entries: AuditLogEntry[];
        total: number;
    }> {
        let sql = `
            SELECT * FROM audit_logs
            WHERE 1=1
        `;
        const params: unknown[] = [];
        let paramIndex = 1;

        if (query.tenantId) {
            sql += ` AND tenant_id = $${paramIndex++}`;
            params.push(query.tenantId);
        }

        if (query.userId) {
            sql += ` AND user_id = $${paramIndex++}`;
            params.push(query.userId);
        }

        if (query.action) {
            sql += ` AND action = $${paramIndex++}`;
            params.push(query.action);
        }

        if (query.resource) {
            sql += ` AND resource = $${paramIndex++}`;
            params.push(query.resource);
        }

        if (query.resourceId) {
            sql += ` AND resource_id = $${paramIndex++}`;
            params.push(query.resourceId);
        }

        if (query.startDate) {
            sql += ` AND timestamp >= $${paramIndex++}`;
            params.push(query.startDate);
        }

        if (query.endDate) {
            sql += ` AND timestamp <= $${paramIndex++}`;
            params.push(query.endDate);
        }

        if (query.outcome) {
            sql += ` AND outcome = $${paramIndex++}`;
            params.push(query.outcome);
        }

        // Get total count
        const countResult = await this.db.query<{ count: string }>(
            `SELECT COUNT(*) as count FROM (${sql}) as subquery`,
            params
        );
        const total = parseInt(countResult.rows[0]?.count ?? '0', 10);

        // Add ordering and pagination
        sql += ` ORDER BY timestamp DESC`;

        if (query.limit) {
            sql += ` LIMIT $${paramIndex++}`;
            params.push(query.limit);
        }

        if (query.offset) {
            sql += ` OFFSET $${paramIndex++}`;
            params.push(query.offset);
        }

        const result = await this.db.query(sql, params);

        return {
            entries: result.rows.map(this.mapRowToEntry),
            total,
        };
    }

    /**
     * Get a single audit entry by ID
     */
    async getEntry(id: string): Promise<AuditLogEntry | null> {
        const result = await this.db.query(
            `SELECT * FROM audit_logs WHERE id = $1`,
            [id]
        );

        if (result.rows.length === 0) return null;

        return this.mapRowToEntry(result.rows[0]);
    }

    /**
     * Verify the integrity of the audit chain
     */
    async verifyChain(
        tenantId?: string,
        startDate?: Date,
        endDate?: Date
    ): Promise<ChainValidationResult> {
        let sql = `
            SELECT * FROM audit_logs
            WHERE 1=1
        `;
        const params: unknown[] = [];
        let paramIndex = 1;

        if (tenantId) {
            sql += ` AND tenant_id = $${paramIndex++}`;
            params.push(tenantId);
        } else {
            sql += ` AND tenant_id IS NULL`;
        }

        if (startDate) {
            sql += ` AND timestamp >= $${paramIndex++}`;
            params.push(startDate);
        }

        if (endDate) {
            sql += ` AND timestamp <= $${paramIndex++}`;
            params.push(endDate);
        }

        sql += ` ORDER BY timestamp ASC`;

        const result = await this.db.query(sql, params);

        if (result.rows.length === 0) {
            return { valid: true, entriesChecked: 0 };
        }

        let entriesChecked = 0;
        let previousHash: string | null = null;

        for (const row of result.rows) {
            const entry = this.mapRowToEntry(row);
            entriesChecked++;

            // Verify the previous hash matches
            if (entry.previousHash !== previousHash) {
                return {
                    valid: false,
                    entriesChecked,
                    firstInvalidEntry: entry.id,
                    error: 'Previous hash mismatch - chain has been tampered with',
                };
            }

            // Verify the hash is correct
            const calculatedHash = this.calculateHash({
                id: entry.id,
                tenantId: entry.tenantId,
                userId: entry.userId,
                sessionId: entry.sessionId,
                action: entry.action,
                resource: entry.resource,
                resourceId: entry.resourceId,
                details: entry.details,
                outcome: entry.outcome,
                errorMessage: entry.errorMessage,
                timestamp: entry.timestamp.toISOString(),
                previousHash: entry.previousHash,
            });

            if (calculatedHash !== entry.hash) {
                return {
                    valid: false,
                    entriesChecked,
                    firstInvalidEntry: entry.id,
                    error: 'Hash mismatch - entry has been modified',
                };
            }

            // Verify the signature
            if (!this.verifySignature(entry.hash, entry.signature)) {
                return {
                    valid: false,
                    entriesChecked,
                    firstInvalidEntry: entry.id,
                    error: 'Invalid signature - entry may have been tampered with',
                };
            }

            previousHash = entry.hash;
        }

        return { valid: true, entriesChecked };
    }

    /**
     * Export audit logs to various formats
     */
    async export(
        query: AuditLogQuery,
        format: 'json' | 'csv' | 'pdf'
    ): Promise<{ data: string; contentType: string; filename: string }> {
        const { entries } = await this.query({ ...query, limit: 100000 });

        switch (format) {
            case 'json':
                return {
                    data: JSON.stringify(entries, null, 2),
                    contentType: 'application/json',
                    filename: `audit-log-${Date.now()}.json`,
                };

            case 'csv':
                return {
                    data: this.entriesToCsv(entries),
                    contentType: 'text/csv',
                    filename: `audit-log-${Date.now()}.csv`,
                };

            case 'pdf':
                return {
                    data: await this.entriesToPdf(entries),
                    contentType: 'application/pdf',
                    filename: `audit-log-${Date.now()}.pdf`,
                };

            default:
                throw new Error(`Unsupported export format: ${format}`);
        }
    }

    /**
     * Get audit statistics
     */
    async getStats(
        tenantId?: string,
        startDate?: Date,
        endDate?: Date
    ): Promise<{
        totalEntries: number;
        byAction: Record<AuditAction, number>;
        byResource: Record<AuditResource, number>;
        byOutcome: { success: number; failure: number };
        uniqueUsers: number;
        uniqueSessions: number;
    }> {
        let sql = `
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE action = 'create') as action_create,
                COUNT(*) FILTER (WHERE action = 'read') as action_read,
                COUNT(*) FILTER (WHERE action = 'update') as action_update,
                COUNT(*) FILTER (WHERE action = 'delete') as action_delete,
                COUNT(*) FILTER (WHERE action = 'login') as action_login,
                COUNT(*) FILTER (WHERE action = 'logout') as action_logout,
                COUNT(*) FILTER (WHERE action = 'export') as action_export,
                COUNT(*) FILTER (WHERE action = 'import') as action_import,
                COUNT(*) FILTER (WHERE action = 'send') as action_send,
                COUNT(*) FILTER (WHERE action = 'receive') as action_receive,
                COUNT(*) FILTER (WHERE action = 'configure') as action_configure,
                COUNT(*) FILTER (WHERE action = 'approve') as action_approve,
                COUNT(*) FILTER (WHERE action = 'reject') as action_reject,
                COUNT(*) FILTER (WHERE action = 'escalate') as action_escalate,
                COUNT(*) FILTER (WHERE outcome = 'success') as success_count,
                COUNT(*) FILTER (WHERE outcome = 'failure') as failure_count,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT session_id) as unique_sessions
            FROM audit_logs
            WHERE 1=1
        `;

        const params: unknown[] = [];
        let paramIndex = 1;

        if (tenantId) {
            sql += ` AND tenant_id = $${paramIndex++}`;
            params.push(tenantId);
        }

        if (startDate) {
            sql += ` AND timestamp >= $${paramIndex++}`;
            params.push(startDate);
        }

        if (endDate) {
            sql += ` AND timestamp <= $${paramIndex++}`;
            params.push(endDate);
        }

        const result = await this.db.query(sql, params);
        const row = result.rows[0];

        // Get resource counts separately
        const resourceResult = await this.db.query(
            `SELECT resource, COUNT(*) as count
            FROM audit_logs
            WHERE tenant_id ${tenantId ? '= $1' : 'IS NULL'}
            ${startDate ? `AND timestamp >= $${tenantId ? 2 : 1}` : ''}
            ${endDate ? `AND timestamp <= $${(tenantId ? 1 : 0) + (startDate ? 1 : 0) + 1}` : ''}
            GROUP BY resource`,
            [tenantId, startDate, endDate].filter(Boolean)
        );

        const byResource: Record<string, number> = {};
        for (const r of resourceResult.rows) {
            byResource[r.resource] = parseInt(r.count, 10);
        }

        return {
            totalEntries: parseInt(row.total, 10),
            byAction: {
                create: parseInt(row.action_create, 10),
                read: parseInt(row.action_read, 10),
                update: parseInt(row.action_update, 10),
                delete: parseInt(row.action_delete, 10),
                login: parseInt(row.action_login, 10),
                logout: parseInt(row.action_logout, 10),
                export: parseInt(row.action_export, 10),
                import: parseInt(row.action_import, 10),
                send: parseInt(row.action_send, 10),
                receive: parseInt(row.action_receive, 10),
                configure: parseInt(row.action_configure, 10),
                approve: parseInt(row.action_approve, 10),
                reject: parseInt(row.action_reject, 10),
                escalate: parseInt(row.action_escalate, 10),
            },
            byResource: byResource as Record<AuditResource, number>,
            byOutcome: {
                success: parseInt(row.success_count, 10),
                failure: parseInt(row.failure_count, 10),
            },
            uniqueUsers: parseInt(row.unique_users, 10),
            uniqueSessions: parseInt(row.unique_sessions, 10),
        };
    }

    /**
     * Archive old audit logs
     */
    async archive(olderThan: Date): Promise<{ archivedCount: number }> {
        // First, export to archive table
        await this.db.query(
            `INSERT INTO audit_logs_archive
            SELECT * FROM audit_logs
            WHERE timestamp < $1`,
            [olderThan]
        );

        // Then delete from main table
        const result = await this.db.query(
            `DELETE FROM audit_logs WHERE timestamp < $1`,
            [olderThan]
        );

        return { archivedCount: result.rowCount || 0 };
    }

    /**
     * Calculate SHA-256 hash of entry data
     */
    private calculateHash(data: Record<string, unknown>): string {
        const jsonString = JSON.stringify(data, Object.keys(data).sort());
        return CryptoJS.SHA256(jsonString).toString(CryptoJS.enc.Hex);
    }

    /**
     * Sign a hash using HMAC-SHA256
     */
    private sign(hash: string): string {
        return CryptoJS.HmacSHA256(hash, this.signingKey).toString(CryptoJS.enc.Hex);
    }

    /**
     * Verify a signature using timing-safe comparison
     * to prevent timing attacks
     */
    private verifySignature(hash: string, signature: string): boolean {
        const expectedSignature = this.sign(hash);
        
        // Use timing-safe comparison to prevent timing attacks
        try {
            const sigBuffer = Buffer.from(signature, 'hex');
            const expectedBuffer = Buffer.from(expectedSignature, 'hex');
            return timingSafeCompareBuffers(sigBuffer, expectedBuffer);
        } catch {
            return false;
        }
    }

    /**
     * Load last hashes from Redis or database
     */
    private async loadLastHashes(): Promise<void> {
        // Try to load from Redis first
        const keys = await this.redis.keys('audit:lasthash:*');

        for (const key of keys) {
            const hash = await this.redis.get(key);
            if (hash) {
                const chainKey = key.replace('audit:lasthash:', '');
                this.lastHash.set(chainKey, hash);
            }
        }

        // If no hashes in Redis, load from database
        if (this.lastHash.size === 0) {
            const result = await this.db.query(`
                SELECT COALESCE(tenant_id, 'global') as chain_key, hash
                FROM audit_logs
                WHERE (tenant_id, timestamp) IN (
                    SELECT tenant_id, MAX(timestamp)
                    FROM audit_logs
                    GROUP BY tenant_id
                )
            `);

            for (const row of result.rows) {
                this.lastHash.set(row.chain_key, row.hash);
                await this.redis.set(`audit:lasthash:${row.chain_key}`, row.hash);
            }
        }
    }

    /**
     * Get the last hash for a chain
     */
    private async getLastHash(chainKey: string): Promise<string | null> {
        // Check in-memory cache first
        if (this.lastHash.has(chainKey)) {
            return this.lastHash.get(chainKey) || null;
        }

        // Check Redis
        const hash = await this.redis.get(`audit:lasthash:${chainKey}`);
        if (hash) {
            this.lastHash.set(chainKey, hash);
            return hash;
        }

        return null;
    }

    /**
     * Update the last hash for a chain
     */
    private async updateLastHash(chainKey: string, hash: string): Promise<void> {
        this.lastHash.set(chainKey, hash);
        await this.redis.set(`audit:lasthash:${chainKey}`, hash);
    }

    /**
     * Save entry to database
     */
    private async saveEntry(entry: AuditLogEntry): Promise<void> {
        await this.db.query(
            `INSERT INTO audit_logs (
                id, tenant_id, user_id, session_id, action, resource,
                resource_id, details, ip_address, user_agent, outcome,
                error_message, timestamp, hash, previous_hash, signature
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
            [
                entry.id,
                entry.tenantId,
                entry.userId,
                entry.sessionId,
                entry.action,
                entry.resource,
                entry.resourceId,
                JSON.stringify(entry.details),
                entry.ipAddress,
                entry.userAgent,
                entry.outcome,
                entry.errorMessage,
                entry.timestamp,
                entry.hash,
                entry.previousHash,
                entry.signature,
            ]
        );
    }

    /**
     * Map database row to entry
     */
    private mapRowToEntry(row: Record<string, unknown>): AuditLogEntry {
        return {
            id: row.id as string,
            tenantId: row.tenant_id as string | null,
            userId: row.user_id as string | null,
            sessionId: row.session_id as string | null,
            action: row.action as AuditAction,
            resource: row.resource as AuditResource,
            resourceId: row.resource_id as string | null,
            details: row.details as Record<string, unknown>,
            ipAddress: row.ip_address as string | null,
            userAgent: row.user_agent as string | null,
            outcome: row.outcome as 'success' | 'failure',
            errorMessage: row.error_message as string | null,
            timestamp: new Date(row.timestamp as string),
            hash: row.hash as string,
            previousHash: row.previous_hash as string | null,
            signature: row.signature as string,
        };
    }

    /**
     * Convert entries to CSV format
     */
    private entriesToCsv(entries: AuditLogEntry[]): string {
        const headers = [
            'ID',
            'Timestamp',
            'Tenant ID',
            'User ID',
            'Session ID',
            'Action',
            'Resource',
            'Resource ID',
            'Outcome',
            'Error',
            'IP Address',
            'User Agent',
            'Details',
        ];

        const rows = entries.map((e) => [
            e.id,
            e.timestamp.toISOString(),
            e.tenantId || '',
            e.userId || '',
            e.sessionId || '',
            e.action,
            e.resource,
            e.resourceId || '',
            e.outcome,
            e.errorMessage || '',
            e.ipAddress || '',
            e.userAgent || '',
            JSON.stringify(e.details),
        ]);

        const csvContent = [headers, ...rows]
            .map((row) =>
                row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
            )
            .join('\n');

        return csvContent;
    }

    /**
     * Convert entries to PDF format
     */
    private async entriesToPdf(entries: AuditLogEntry[]): Promise<string> {
        // Generate a simple PDF-like structure
        // In production, use a proper PDF library like pdfkit
        const content = {
            title: 'Audit Log Export',
            generated: new Date().toISOString(),
            totalEntries: entries.length,
            entries: entries.map((e) => ({
                id: e.id,
                timestamp: e.timestamp.toISOString(),
                action: e.action,
                resource: e.resource,
                resourceId: e.resourceId,
                outcome: e.outcome,
                userId: e.userId,
                tenantId: e.tenantId,
            })),
        };

        // Return Base64-encoded JSON as placeholder
        // Replace with actual PDF generation in production
        return Buffer.from(JSON.stringify(content, null, 2)).toString('base64');
    }

    /**
     * Create webhook for real-time audit notifications
     */
    async registerWebhook(
        tenantId: string,
        url: string,
        events: AuditAction[]
    ): Promise<string> {
        const id = generateUUID();

        await this.db.query(
            `INSERT INTO audit_webhooks (id, tenant_id, url, events, active)
            VALUES ($1, $2, $3, $4, true)`,
            [id, tenantId, url, JSON.stringify(events)]
        );

        return id;
    }

    /**
     * Notify webhooks of audit events
     */
    // @ts-expect-error Reserved for future webhook notifications
    private async notifyWebhooks(entry: AuditLogEntry): Promise<void> {
        if (!entry.tenantId) return;

        const result = await this.db.query(
            `SELECT * FROM audit_webhooks
            WHERE tenant_id = $1 AND active = true`,
            [entry.tenantId]
        );

        for (const webhook of result.rows) {
            const events = webhook.events as AuditAction[];
            if (events.includes(entry.action)) {
                // Queue webhook notification
                await this.redis.lpush(
                    'audit:webhooks:queue',
                    JSON.stringify({
                        webhookId: webhook.id,
                        url: webhook.url,
                        entry: {
                            id: entry.id,
                            action: entry.action,
                            resource: entry.resource,
                            resourceId: entry.resourceId,
                            timestamp: entry.timestamp,
                            outcome: entry.outcome,
                        },
                    })
                );
            }
        }
    }
}

export default AuditLogger;
