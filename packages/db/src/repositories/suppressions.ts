/**
 * Suppressions Repository - Global and per-tenant suppression lists
 * Handles bounces, complaints, unsubscribes, and manual suppressions
 */

import { Result } from '@apexmail/lib';
import { generateUuid } from '@apexmail/lib/id';
import type { DatabasePool } from '../pool.js';

export type SuppressionType = 'bounce' | 'complaint' | 'unsubscribe' | 'manual' | 'list_unsubscribe';
export type SuppressionScope = 'global' | 'tenant' | 'domain' | 'campaign';

export interface Suppression {
  id: string;
  tenantId: string | null; // null for global suppressions
  email: string;
  emailHash: string;
  type: SuppressionType;
  scope: SuppressionScope;
  scopeId: string | null; // domain or campaign id for scoped suppressions
  reason: string | null;
  source: string; // e.g., 'bounce_handler', 'complaint_handler', 'api', 'import'
  originalMessageId: string | null;
  bounceType: 'hard' | 'soft' | null;
  bounceCode: string | null;
  feedbackType: string | null; // ARF feedback type for complaints
  expiresAt: Date | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateSuppressionInput {
  tenantId?: string;
  email: string;
  type: SuppressionType;
  scope?: SuppressionScope;
  scopeId?: string;
  reason?: string;
  source: string;
  originalMessageId?: string;
  bounceType?: 'hard' | 'soft';
  bounceCode?: string;
  feedbackType?: string;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface CheckSuppressionResult {
  suppressed: boolean;
  suppression: Suppression | null;
}

export class SuppressionsRepository {
  constructor(private readonly db: DatabasePool) {}

  private hashEmail(email: string): string {
    // Using SHA-256 for email hashing - normalize first
    const normalizedEmail = email.toLowerCase().trim();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(normalizedEmail).digest('hex');
  }

  async create(input: CreateSuppressionInput): Promise<Result<Suppression, Error>> {
    const id = generateUuid();
    const normalizedEmail = input.email.toLowerCase().trim();
    const emailHash = this.hashEmail(normalizedEmail);
    const now = new Date();

    // Handle hard bounces - always global, never expires
    const isHardBounce = input.type === 'bounce' && input.bounceType === 'hard';
    const scope = isHardBounce ? 'global' : (input.scope ?? 'tenant');
    const expiresAt = isHardBounce ? null : input.expiresAt;

    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO suppressions (
        id, tenant_id, email, email_hash, type, scope, scope_id,
        reason, source, original_message_id, bounce_type, bounce_code,
        feedback_type, expires_at, metadata, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
      ON CONFLICT (email_hash, tenant_id, scope, scope_id) 
        WHERE tenant_id IS NOT NULL
      DO UPDATE SET 
        type = CASE 
          WHEN EXCLUDED.type = 'bounce' AND EXCLUDED.bounce_type = 'hard' THEN 'bounce'
          WHEN suppressions.type = 'bounce' AND suppressions.bounce_type = 'hard' THEN suppressions.type
          ELSE EXCLUDED.type
        END,
        bounce_type = COALESCE(
          CASE WHEN EXCLUDED.bounce_type = 'hard' THEN 'hard' ELSE NULL END,
          suppressions.bounce_type
        ),
        updated_at = NOW()
      RETURNING *`,
      [
        id,
        input.tenantId ?? null,
        normalizedEmail,
        emailHash,
        input.type,
        scope,
        input.scopeId ?? null,
        input.reason ?? null,
        input.source,
        input.originalMessageId ?? null,
        input.bounceType ?? null,
        input.bounceCode ?? null,
        input.feedbackType ?? null,
        expiresAt ?? null,
        JSON.stringify(input.metadata ?? {}),
        now,
        now,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to create suppression'));
    }

    return Result.ok(this.mapRow(row));
  }

  async checkSuppression(
    email: string,
    tenantId: string,
    options: { scopeId?: string; domain?: string } = {}
  ): Promise<Result<CheckSuppressionResult, Error>> {
    const emailHash = this.hashEmail(email);

    // Check in priority order: global, tenant, domain, campaign
    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM suppressions
       WHERE email_hash = $1
         AND (tenant_id IS NULL OR tenant_id = $2)
         AND (expires_at IS NULL OR expires_at > NOW())
         AND (scope = 'global' 
              OR (scope = 'tenant' AND tenant_id = $2)
              OR (scope = 'domain' AND scope_id = $3)
              OR (scope = 'campaign' AND scope_id = $4))
       ORDER BY 
         CASE scope 
           WHEN 'global' THEN 0 
           WHEN 'tenant' THEN 1 
           WHEN 'domain' THEN 2 
           ELSE 3 
         END,
         created_at DESC
       LIMIT 1`,
      [
        emailHash,
        tenantId,
        options.domain ?? null,
        options.scopeId ?? null,
      ]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok({
      suppressed: !!row,
      suppression: row ? this.mapRow(row) : null,
    });
  }

  async checkBulkSuppression(
    emails: string[],
    tenantId: string
  ): Promise<Result<Map<string, Suppression | null>, Error>> {
    if (emails.length === 0) {
      return Result.ok(new Map());
    }

    const emailHashes = emails.map((e) => this.hashEmail(e));
    const emailToHash = new Map(emails.map((e, i) => [e.toLowerCase().trim(), emailHashes[i]]));

    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT DISTINCT ON (email_hash) *
       FROM suppressions
       WHERE email_hash = ANY($1)
         AND (tenant_id IS NULL OR tenant_id = $2)
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY email_hash, 
         CASE scope WHEN 'global' THEN 0 WHEN 'tenant' THEN 1 ELSE 2 END,
         created_at DESC`,
      [emailHashes, tenantId]
    );

    if (!result.ok) return result;

    const suppressionByHash = new Map<string, Suppression>();
    for (const row of result.value.rows) {
      suppressionByHash.set(row.email_hash, this.mapRow(row));
    }

    const resultMap = new Map<string, Suppression | null>();
    for (const email of emails) {
      const normalized = email.toLowerCase().trim();
      const hash = emailToHash.get(normalized);
      resultMap.set(email, hash ? suppressionByHash.get(hash) ?? null : null);
    }

    return Result.ok(resultMap);
  }

  async findById(id: string): Promise<Result<Suppression | null, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      'SELECT * FROM suppressions WHERE id = $1',
      [id]
    );

    if (!result.ok) return result;

    const row = result.value.rows[0];
    return Result.ok(row ? this.mapRow(row) : null);
  }

  async findByEmail(email: string, tenantId?: string): Promise<Result<Suppression[], Error>> {
    const emailHash = this.hashEmail(email);

    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM suppressions 
       WHERE email_hash = $1 
         AND (tenant_id IS NULL OR tenant_id = $2)
       ORDER BY created_at DESC`,
      [emailHash, tenantId ?? null]
    );

    if (!result.ok) return result;

    return Result.ok(result.value.rows.map((row) => this.mapRow(row)));
  }

  async remove(id: string): Promise<Result<void, Error>> {
    const result = await this.db.query(
      'DELETE FROM suppressions WHERE id = $1',
      [id]
    );
    return result.ok ? Result.ok(undefined) : result;
  }

  async removeByEmail(
    email: string,
    tenantId: string,
    options: { type?: SuppressionType; scope?: SuppressionScope } = {}
  ): Promise<Result<number, Error>> {
    const emailHash = this.hashEmail(email);
    const conditions = ['email_hash = $1', 'tenant_id = $2'];
    const values: unknown[] = [emailHash, tenantId];
    let paramIndex = 3;

    if (options.type) {
      conditions.push(`type = $${paramIndex++}`);
      values.push(options.type);
    }
    if (options.scope) {
      conditions.push(`scope = $${paramIndex++}`);
      values.push(options.scope);
    }

    // Never remove global hard bounce suppressions through normal removal
    conditions.push(`NOT (scope = 'global' AND type = 'bounce' AND bounce_type = 'hard')`);

    const result = await this.db.query<{ count: string }>(
      `WITH deleted AS (
        DELETE FROM suppressions WHERE ${conditions.join(' AND ')} RETURNING 1
      ) SELECT COUNT(*) as count FROM deleted`,
      values
    );

    if (!result.ok) return result;

    return Result.ok(parseInt(result.value.rows[0]?.count ?? '0', 10));
  }

  async listByTenant(
    tenantId: string,
    options: {
      type?: SuppressionType;
      scope?: SuppressionScope;
      includeExpired?: boolean;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Result<{ suppressions: Suppression[]; total: number }, Error>> {
    const conditions = ['(tenant_id = $1 OR tenant_id IS NULL)'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (options.type) {
      conditions.push(`type = $${paramIndex++}`);
      values.push(options.type);
    }
    if (options.scope) {
      conditions.push(`scope = $${paramIndex++}`);
      values.push(options.scope);
    }
    if (!options.includeExpired) {
      conditions.push(`(expires_at IS NULL OR expires_at > NOW())`);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*) as count FROM suppressions ${whereClause}`,
      values
    );

    if (!countResult.ok) return countResult;

    const limit = options.limit ?? 100;
    const offset = options.offset ?? 0;
    values.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string | null;
      email: string;
      email_hash: string;
      type: SuppressionType;
      scope: SuppressionScope;
      scope_id: string | null;
      reason: string | null;
      source: string;
      original_message_id: string | null;
      bounce_type: 'hard' | 'soft' | null;
      bounce_code: string | null;
      feedback_type: string | null;
      expires_at: Date | null;
      metadata: string;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT * FROM suppressions ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex}`,
      values
    );

    if (!result.ok) return result;

    return Result.ok({
      suppressions: result.value.rows.map((row) => this.mapRow(row)),
      total: parseInt(countResult.value.rows[0]?.count ?? '0', 10),
    });
  }

  async countByType(tenantId: string): Promise<Result<Record<SuppressionType, number>, Error>> {
    const result = await this.db.query<{ type: SuppressionType; count: string }>(
      `SELECT type, COUNT(*) as count
       FROM suppressions
       WHERE (tenant_id = $1 OR tenant_id IS NULL)
         AND (expires_at IS NULL OR expires_at > NOW())
       GROUP BY type`,
      [tenantId]
    );

    if (!result.ok) return result;

    const counts: Record<SuppressionType, number> = {
      bounce: 0,
      complaint: 0,
      unsubscribe: 0,
      manual: 0,
      list_unsubscribe: 0,
    };

    for (const row of result.value.rows) {
      counts[row.type] = parseInt(row.count, 10);
    }

    return Result.ok(counts);
  }

  async importBulk(
    suppressions: CreateSuppressionInput[]
  ): Promise<Result<{ imported: number; duplicates: number }, Error>> {
    if (suppressions.length === 0) {
      return Result.ok({ imported: 0, duplicates: 0 });
    }

    let imported = 0;
    let duplicates = 0;

    // Process in batches of 1000
    const batchSize = 1000;
    for (let i = 0; i < suppressions.length; i += batchSize) {
      const batch = suppressions.slice(i, i + batchSize);
      
      const values: unknown[] = [];
      const placeholders: string[] = [];
      let paramIndex = 1;

      const now = new Date();

      for (const input of batch) {
        const id = generateUuid();
        const normalizedEmail = input.email.toLowerCase().trim();
        const emailHash = this.hashEmail(normalizedEmail);
        const isHardBounce = input.type === 'bounce' && input.bounceType === 'hard';
        const scope = isHardBounce ? 'global' : (input.scope ?? 'tenant');

        placeholders.push(
          `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
        );
        values.push(
          id,
          input.tenantId ?? null,
          normalizedEmail,
          emailHash,
          input.type,
          scope,
          input.scopeId ?? null,
          input.reason ?? null,
          input.source,
          input.originalMessageId ?? null,
          input.bounceType ?? null,
          input.bounceCode ?? null,
          input.feedbackType ?? null,
          input.expiresAt ?? null,
          JSON.stringify(input.metadata ?? {}),
          now,
          now
        );
      }

      const result = await this.db.query<{ inserted: string }>(
        `WITH inserted AS (
          INSERT INTO suppressions (
            id, tenant_id, email, email_hash, type, scope, scope_id,
            reason, source, original_message_id, bounce_type, bounce_code,
            feedback_type, expires_at, metadata, created_at, updated_at
          ) VALUES ${placeholders.join(', ')}
          ON CONFLICT (email_hash, tenant_id, scope, scope_id) 
            WHERE tenant_id IS NOT NULL
          DO NOTHING
          RETURNING 1
        ) SELECT COUNT(*) as inserted FROM inserted`,
        values
      );

      if (!result.ok) return result;

      const batchImported = parseInt(result.value.rows[0]?.inserted ?? '0', 10);
      imported += batchImported;
      duplicates += batch.length - batchImported;
    }

    return Result.ok({ imported, duplicates });
  }

  async cleanupExpired(): Promise<Result<number, Error>> {
    const result = await this.db.query<{ count: string }>(
      `WITH deleted AS (
        DELETE FROM suppressions 
        WHERE expires_at IS NOT NULL AND expires_at < NOW()
        RETURNING 1
      ) SELECT COUNT(*) as count FROM deleted`
    );

    if (!result.ok) return result;

    return Result.ok(parseInt(result.value.rows[0]?.count ?? '0', 10));
  }

  private mapRow(row: {
    id: string;
    tenant_id: string | null;
    email: string;
    email_hash: string;
    type: SuppressionType;
    scope: SuppressionScope;
    scope_id: string | null;
    reason: string | null;
    source: string;
    original_message_id: string | null;
    bounce_type: 'hard' | 'soft' | null;
    bounce_code: string | null;
    feedback_type: string | null;
    expires_at: Date | null;
    metadata: string;
    created_at: Date;
    updated_at: Date;
  }): Suppression {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      email: row.email,
      emailHash: row.email_hash,
      type: row.type,
      scope: row.scope,
      scopeId: row.scope_id,
      reason: row.reason,
      source: row.source,
      originalMessageId: row.original_message_id,
      bounceType: row.bounce_type,
      bounceCode: row.bounce_code,
      feedbackType: row.feedback_type,
      expiresAt: row.expires_at,
      metadata: typeof row.metadata === 'string'
        ? JSON.parse(row.metadata) as Record<string, unknown>
        : row.metadata as unknown as Record<string, unknown>,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  /**
   * Get suppression statistics for a tenant
   */
  async getStats(
    tenantId: string,
    options: { startDate?: Date; endDate?: Date; since?: Date; until?: Date } = {}
  ): Promise<Result<{
    total: number;
    bounces: number;
    complaints: number;
    unsubscribes: number;
    manual: number;
  }, Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['(tenant_id IS NULL OR tenant_id = $1)'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      values.push(endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    const result = await this.db.query<{
      type: string;
      count: string;
    }>(
      `SELECT type, COUNT(*) as count
       FROM suppressions
       ${whereClause}
       GROUP BY type`,
      values
    );

    if (!result.ok) return result;

    const stats = {
      total: 0,
      bounces: 0,
      complaints: 0,
      unsubscribes: 0,
      manual: 0,
    };

    for (const row of result.value.rows) {
      const count = parseInt(row.count, 10);
      stats.total += count;
      switch (row.type) {
        case 'bounce':
          stats.bounces += count;
          break;
        case 'complaint':
          stats.complaints += count;
          break;
        case 'unsubscribe':
          stats.unsubscribes += count;
          break;
        case 'manual':
          stats.manual += count;
          break;
      }
    }

    return Result.ok(stats);
  }

  /**
   * Get suppression time series data
   */
  async getTimeSeries(
    tenantId: string,
    options: {
      since?: Date;
      until?: Date;
      startDate?: Date;
      endDate?: Date;
      interval: 'minute' | 'hour' | 'day' | 'week' | 'month';
    }
  ): Promise<Result<{
    timestamp: Date;
    total: number;
    bounces: number;
    complaints: number;
    unsubscribes: number;
    manual: number;
  }[], Error>> {
    // Support both since/until and startDate/endDate
    const startDate = options.startDate ?? options.since;
    const endDate = options.endDate ?? options.until;

    const conditions = ['tenant_id = $1'];
    const values: unknown[] = [tenantId];
    let paramIndex = 2;

    if (startDate) {
      conditions.push(`created_at >= $${paramIndex++}`);
      values.push(startDate);
    }
    if (endDate) {
      conditions.push(`created_at <= $${paramIndex++}`);
      values.push(endDate);
    }

    const whereClause = `WHERE ${conditions.join(' AND ')}`;

    // Map interval to PostgreSQL date_trunc format
    const truncInterval = options.interval === 'minute' ? 'hour' : options.interval;

    const result = await this.db.query<{
      bucket: Date;
      type: SuppressionType;
      count: string;
    }>(
      `SELECT 
        DATE_TRUNC('${truncInterval}', created_at) as bucket,
        type,
        COUNT(*) as count
       FROM suppressions
       ${whereClause}
       GROUP BY bucket, type
       ORDER BY bucket ASC`,
      values
    );

    if (!result.ok) return result;

    // Aggregate by timestamp
    const byTimestamp = new Map<string, {
      timestamp: Date;
      total: number;
      bounces: number;
      complaints: number;
      unsubscribes: number;
      manual: number;
    }>();

    for (const row of result.value.rows) {
      const key = row.bucket.toISOString();
      const existing = byTimestamp.get(key) ?? {
        timestamp: row.bucket,
        total: 0,
        bounces: 0,
        complaints: 0,
        unsubscribes: 0,
        manual: 0,
      };
      const count = parseInt(row.count, 10);
      existing.total += count;

      switch (row.type) {
        case 'bounce':
          existing.bounces += count;
          break;
        case 'complaint':
          existing.complaints += count;
          break;
        case 'unsubscribe':
        case 'list_unsubscribe':
          existing.unsubscribes += count;
          break;
        case 'manual':
          existing.manual += count;
          break;
      }

      byTimestamp.set(key, existing);
    }

    return Result.ok(Array.from(byTimestamp.values()));
  }
}
