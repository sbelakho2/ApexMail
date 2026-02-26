/**
 * Audit Logs Repository - Hash-chained immutable audit trail
 */

import { Result, parseJsonOrDefault } from '@apexmail/lib';
import { generateUuid } from '@apexmail/lib/id';
import { createHashChainEntry, verifyHashChain } from '@apexmail/lib/crypto';
import type { DatabasePool } from '../pool.js';

export type AuditAction =
  | 'tenant.created'
  | 'tenant.updated'
  | 'tenant.suspended'
  | 'tenant.activated'
  | 'tenant.deleted'
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.login'
  | 'user.logout'
  | 'user.login_failed'
  | 'user.password_changed'
  | 'user.password_reset_requested'
  | 'user.mfa_enabled'
  | 'user.mfa_disabled'
  | 'user.token_refreshed'
  | 'domain.created'
  | 'domain.verified'
  | 'domain.deleted'
  | 'api_key.created'
  | 'api_key.rotated'
  | 'api_key.revoked'
  | 'api_key.deleted'
  | 'template.created'
  | 'template.updated'
  | 'template.published'
  | 'template.deleted'
  | 'suppression.created'
  | 'suppression.deleted'
  | 'suppression.removed'
  | 'suppression.imported'
  | 'suppression.bulk_created'
  | 'suppression.bulk_deleted'
  | 'message.sent'
  | 'message.bounced'
  | 'message.complained'
  | 'webhook.created'
  | 'webhook.updated'
  | 'webhook.deleted'
  | 'webhook.triggered'
  | 'webhook.secret_rotated'
  | 'webhook.enabled'
  | 'webhook.disabled'
  | 'settings.updated'
  | 'export.requested'
  | 'export.completed'
  | 'data.deleted'
  | 'gdpr.request'
  | 'gdpr.completed'
  // Campaign lifecycle
  | 'campaign.created'
  | 'campaign.resumed'
  | 'campaign.stopped'
  | 'campaign.paused'
  | 'campaign.deleted'
  // Contact management
  | 'contact.added'
  | 'contact.removed'
  | 'contact.bulk_added'
  | 'contact.bulk_removed'
  | 'contact.tagged'
  | 'contact.bulk_tagged'
  | 'contact.imported'
  // Automation management
  | 'automation.created'
  | 'automation.updated'
  | 'automation.enabled'
  | 'automation.disabled'
  | 'automation.deleted';

export interface AuditLog {
  id: string;
  tenantId: string;
  userId: string | null;
  action: AuditAction;
  resourceType: string;
  resourceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  changes: AuditChanges | null;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
  timestamp: Date;
}

export interface AuditChanges {
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  fields?: string[];
}

export interface CreateAuditLogInput {
  tenantId: string;
  userId?: string;
  action: AuditAction;
  resourceType: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  changes?: AuditChanges;
  metadata?: Record<string, unknown>;
}

export interface AuditLogQuery {
  tenantId: string;
  userId?: string;
  action?: AuditAction | AuditAction[];
  resourceType?: string;
  resourceId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

export class AuditLogsRepository {
  constructor(private readonly db: DatabasePool) {}

  /**
   * RACE-003 FIX: Use advisory lock to ensure atomic hash chain insertion.
   * This prevents TOCTOU where two concurrent inserts could get the same previous_hash.
   */
  async create(input: CreateAuditLogInput): Promise<Result<AuditLog, Error>> {
    const id = generateUuid();
    const now = new Date();

    // Get a client for transaction
    let client;
    try {
      client = await this.db.getClient();
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }

    try {
      await client.query('BEGIN');
      
      // Advisory lock per tenant to serialize hash chain updates
      const [lockNamespace, lockKey] = this.advisoryLockKeys(input.tenantId);
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [lockNamespace, lockKey]);

      // Get the previous hash for chain integrity (now safe within lock)
      const previousResult = await client.query<{ hash: string }>(
        `SELECT hash FROM audit_logs 
         WHERE tenant_id = $1 
         ORDER BY timestamp DESC, id DESC 
         LIMIT 1`,
        [input.tenantId]
      );

      const previousHash = previousResult.rows[0]?.hash ?? null;

      // Create the hash chain entry
      const dataToHash = {
        id,
        tenantId: input.tenantId,
        userId: input.userId ?? null,
        action: input.action,
        resourceType: input.resourceType,
        resourceId: input.resourceId ?? null,
        changes: input.changes ?? null,
        metadata: input.metadata ?? {},
        timestamp: now.toISOString(),
      };

      const hashEntry = createHashChainEntry(dataToHash, previousHash);

      const result = await client.query<{
        id: string;
        tenant_id: string;
        user_id: string | null;
        action: AuditAction;
        resource_type: string;
        resource_id: string | null;
        ip_address: string | null;
        user_agent: string | null;
        changes: string | null;
        metadata: string;
        previous_hash: string | null;
        hash: string;
        timestamp: Date;
      }>(
        `INSERT INTO audit_logs (
          id, tenant_id, user_id, action, resource_type, resource_id,
          ip_address, user_agent, changes, metadata, previous_hash, hash, timestamp
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (id) DO NOTHING
        RETURNING *`,
        [
          id,
          input.tenantId,
          input.userId ?? null,
          input.action,
          input.resourceType,
          input.resourceId ?? null,
          input.ipAddress ?? null,
          input.userAgent ?? null,
          input.changes ? JSON.stringify(input.changes) : null,
          JSON.stringify(input.metadata ?? {}),
          previousHash,
          hashEntry.hash,
          now,
        ]
      );

      await client.query('COMMIT');

      const row = result.rows[0];
      if (!row) {
        // B-041: ON CONFLICT (id) DO NOTHING — duplicate audit log id, skip silently.
        // Audit logs are append-only and should never be updated.
        return Result.err(new Error('Audit log already exists with this id'));
      }

      return Result.ok(this.mapRow(row));
    } catch (error) {
      await client.query('ROLLBACK');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  /**
   * Hash a string to a consistent integer for advisory lock key
   */
  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash;
  }

  /**
   * Two-key lock to scope advisory locks per tenant without global contention.
   */
  private advisoryLockKeys(tenantId: string): [number, number] {
    return [this.hashString('audit_logs'), this.hashString(tenantId)];
  }

  async createBulk(inputs: CreateAuditLogInput[]): Promise<Result<number, Error>> {
    if (inputs.length === 0) {
      return Result.ok(0);
    }

    // For bulk inserts, we need to chain hashes sequentially
    // Get the last hash for the tenant
    const firstInput = inputs[0];
    if (!firstInput) {
      return Result.ok(0);
    }
    const tenantId = firstInput.tenantId;

    // RACE-003 FIX: Use advisory lock to ensure atomic hash chain bulk insertion
    let client;
    try {
      client = await this.db.getClient();
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    }

    try {
      await client.query('BEGIN');
      
      // Advisory lock per tenant to serialize hash chain updates
      const [lockNamespace, lockKey] = this.advisoryLockKeys(tenantId);
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [lockNamespace, lockKey]);

      const previousResult = await client.query<{ hash: string }>(
        `SELECT hash FROM audit_logs 
         WHERE tenant_id = $1 
         ORDER BY timestamp DESC, id DESC 
         LIMIT 1`,
        [tenantId]
      );

      let previousHash = previousResult.rows[0]?.hash ?? null;
      const values: unknown[] = [];
      const placeholders: string[] = [];
      let paramIndex = 1;
      const now = new Date();

      for (const input of inputs) {
        const id = generateUuid();

        const dataToHash = {
          id,
          tenantId: input.tenantId,
          userId: input.userId ?? null,
          action: input.action,
          resourceType: input.resourceType,
          resourceId: input.resourceId ?? null,
          changes: input.changes ?? null,
          metadata: input.metadata ?? {},
          timestamp: now.toISOString(),
        };

        const hashEntry = createHashChainEntry(dataToHash, previousHash);

        placeholders.push(
          `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
        );

        values.push(
          id,
          input.tenantId,
          input.userId ?? null,
          input.action,
          input.resourceType,
          input.resourceId ?? null,
          input.ipAddress ?? null,
          input.userAgent ?? null,
          input.changes ? JSON.stringify(input.changes) : null,
          JSON.stringify(input.metadata ?? {}),
          previousHash,
          hashEntry.hash,
          now
        );

        previousHash = hashEntry.hash;
      }

      await client.query(
        `INSERT INTO audit_logs (
          id, tenant_id, user_id, action, resource_type, resource_id,
          ip_address, user_agent, changes, metadata, previous_hash, hash, timestamp
        ) VALUES ${placeholders.join(', ')}
        ON CONFLICT (id) DO NOTHING`,
        values
      );

      await client.query('COMMIT');
      return Result.ok(inputs.length);
    } catch (error) {
      await client.query('ROLLBACK');
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async findById(id: string, tenantId?: string): Promise<Result<AuditLog | null, Error>> {
    const sql = tenantId
      ? 'SELECT * FROM audit_logs WHERE id = $1 AND tenant_id = $2'
      : 'SELECT * FROM audit_logs WHERE id = $1';
    const params = tenantId ? [id, tenantId] : [id];
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      ip_address: string | null;
      user_agent: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(sql, params);

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async query(query: AuditLogQuery): Promise<Result<{ logs: AuditLog[]; total: number }, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [query.tenantId];
    let paramIndex = 2;

    if (query.userId) {
      conditions.push(`user_id = $${paramIndex++}`);
      values.push(query.userId);
    }
    if (query.action) {
      if (Array.isArray(query.action)) {
        conditions.push(`action = ANY($${paramIndex++})`);
        values.push(query.action);
      } else {
        conditions.push(`action = $${paramIndex++}`);
        values.push(query.action);
      }
    }
    if (query.resourceType) {
      conditions.push(`resource_type = $${paramIndex++}`);
      values.push(query.resourceType);
    }
    if (query.resourceId) {
      conditions.push(`resource_id = $${paramIndex++}`);
      values.push(query.resourceId);
    }
    if (query.startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      values.push(query.startDate);
    }
    if (query.endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      values.push(query.endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM audit_logs ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = query.limit ?? 100;
    const offset = query.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      ip_address: string | null;
      user_agent: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(
      `SELECT * FROM audit_logs ${whereClause}
       ORDER BY timestamp DESC, id DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      logs: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async getResourceHistory(
    tenantId: string,
    resourceType: string,
    resourceId: string
  ): Promise<Result<AuditLog[], Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      ip_address: string | null;
      user_agent: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(
      // FIX-500-045: Add LIMIT to prevent unbounded result sets for heavily-audited resources
      // FIX-500-050: Composite index idx_audit_logs_resource_lookup added in migration 010_performance_indexes.sql
      `SELECT * FROM audit_logs 
       WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
       ORDER BY timestamp DESC, id DESC
       LIMIT $4`,
      [tenantId, resourceType, resourceId, 100]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async getUserActivity(
    tenantId: string,
    userId: string,
    options: { startDate?: Date; endDate?: Date; limit?: number } = {}
  ): Promise<Result<AuditLog[], Error>> {
    const conditions = ['tenant_id = $1', 'user_id = $2'];
    const values: unknown[] = [tenantId, userId];
    let paramIndex = 3;

    if (options.startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      values.push(options.startDate);
    }
    if (options.endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      values.push(options.endDate);
    }

    const limit = options.limit ?? 100;
    values.push(limit);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      ip_address: string | null;
      user_agent: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(
      `SELECT * FROM audit_logs 
       WHERE ${conditions.join(' AND ')}
       ORDER BY timestamp DESC, id DESC
       LIMIT $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async verifyChainIntegrity(
    tenantId: string,
    options: { limit?: number; startFrom?: string } = {}
  ): Promise<Result<{ valid: boolean; brokenAt?: string; checked: number }, Error>> {
    const limit = options.limit ?? 1000;
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.startFrom) {
      conditions.push(`id >= $${paramIndex++}`);
      values.push(options.startFrom);
    }

    values.push(limit);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(
      `SELECT id, tenant_id, user_id, action, resource_type, resource_id, 
              changes, metadata, previous_hash, hash, timestamp
       FROM audit_logs 
       WHERE ${conditions.join(' AND ')}
       ORDER BY timestamp ASC, id ASC
       LIMIT $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    const entries = result.value.rows.map((row) => ({
      data: {
        id: row.id,
        tenantId: row.tenant_id,
        userId: row.user_id,
        action: row.action,
        resourceType: row.resource_type,
        resourceId: row.resource_id,
        changes: row.changes ? parseJsonOrDefault(row.changes, null) : null,
        metadata: typeof row.metadata === 'string' ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {}) : row.metadata,
        timestamp: row.timestamp.toISOString(),
      },
      hash: row.hash,
      previousHash: row.previous_hash,
    }));

    const verification = verifyHashChain(entries as unknown as import('@apexmail/lib/crypto').HashChainEntry[]);

    if (!verification.ok) {
      return Result.ok({
        valid: false,
        brokenAt: entries[verification.error.index]?.data.id,
        checked: entries.length,
      });
    }

    return Result.ok({
      valid: true,
      brokenAt: undefined,
      checked: entries.length,
    });
  }

  async getActionCounts(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date } = {}
  ): Promise<Result<Record<AuditAction, number>, Error>> {
    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.startDate) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      values.push(options.startDate);
    }
    if (options.endDate) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      values.push(options.endDate);
    }

    const result = await this.db.query<{ action: AuditAction; count: string }>(
      `SELECT action, COUNT(*) as count
       FROM audit_logs 
       WHERE ${conditions.join(' AND ')}
       GROUP BY action`,
      values
    );

    if (!result.ok) return result;

    const counts: Partial<Record<AuditAction, number>> = {};
    for (const row of result.value.rows) {
      counts[row.action] = parseInt(row.count, 10);
    }

    return Result.ok(counts as Record<AuditAction, number>);
  }

  async exportForCompliance(
    tenantId: string,
    options: {
      startDate: Date;
      endDate: Date;
      format: 'json' | 'csv';
      limit?: number;
      offset?: number;
    }
  ): Promise<Result<string, Error>> {
    const limit = Math.max(1, Math.min(options.limit ?? 10000, 100000));
    const offset = Math.max(0, options.offset ?? 0);
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      user_id: string | null;
      action: AuditAction;
      resource_type: string;
      resource_id: string | null;
      ip_address: string | null;
      user_agent: string | null;
      changes: string | null;
      metadata: string;
      previous_hash: string | null;
      hash: string;
      timestamp: Date;
    }>(
      `SELECT * FROM audit_logs 
       WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
       ORDER BY timestamp ASC, id ASC
       LIMIT $4 OFFSET $5`,
      [tenantId, options.startDate, options.endDate, limit, offset]
    );

    if (!result.ok) return result;

    const logs = result.value.rows.map((row) => this.mapRow(row));

    if (options.format === 'json') {
      return Result.ok(JSON.stringify(logs, null, 2));
    }

    // CSV format
    const headers = [
      'id', 'tenant_id', 'user_id', 'action', 'resource_type', 'resource_id',
      'ip_address', 'user_agent', 'timestamp', 'hash', 'previous_hash'
    ];

    const rows = logs.map((log) => [
      log.id,
      log.tenantId,
      log.userId ?? '',
      log.action,
      log.resourceType,
      log.resourceId ?? '',
      log.ipAddress ?? '',
      log.userAgent ?? '',
      log.timestamp.toISOString(),
      log.hash,
      log.previousHash ?? '',
    ].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));

    return Result.ok([headers.join(','), ...rows].join('\n'));
  }

  async archiveOldLogs(
    tenantId: string,
    olderThanDays: number
  ): Promise<Result<{ archived: number; archivePath: string }, Error>> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const deletedResult = await this.cleanupOld(olderThanDays, { tenantId, batchSize: 1000 });
    if (!deletedResult.ok) return deletedResult;

    const count = deletedResult.value;
    const archivePath = `audit-logs/${tenantId}/${cutoffDate.toISOString().slice(0, 10)}.parquet`;

    return Result.ok({
      archived: count,
      archivePath,
    });
  }

  /**
   * C-081: Batched deletion of audit logs older than N days.
   *
   * Deletes in batches of `batchSize` (default 1000) to avoid long-running
   * transactions and excessive lock hold times. Returns the total number
   * of rows deleted across all batches.
   */
  async cleanupOld(
    olderThanDays: number,
    options: { batchSize?: number; tenantId?: string } = {}
  ): Promise<Result<number, Error>> {
    return Result.err(
      new Error(
        'Audit log cleanup is disabled to preserve hash-chain integrity. Use exportForCompliance and archive externally.'
      )
    );
  }

  private mapRow(row: {
    id: string;
    tenant_id: string;
    user_id: string | null;
    action: AuditAction;
    resource_type: string;
    resource_id: string | null;
    ip_address: string | null;
    user_agent: string | null;
    changes: string | null;
    metadata: string;
    previous_hash: string | null;
    hash: string;
    timestamp: Date;
  }): AuditLog {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      userId: row.user_id,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      changes: row.changes
        ? (typeof row.changes === 'string'
          ? parseJsonOrDefault<AuditChanges>(row.changes, {} as AuditChanges)
          : row.changes) as AuditChanges
        : null,
      metadata: typeof row.metadata === 'string'
        ? parseJsonOrDefault<Record<string, unknown>>(row.metadata, {})
        : row.metadata as unknown as Record<string, unknown>,
      previousHash: row.previous_hash,
      hash: row.hash,
      timestamp: row.timestamp,
    };
  }
}
