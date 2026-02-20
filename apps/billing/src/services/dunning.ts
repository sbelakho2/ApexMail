/**
 * Dunning Service
 * Manages failed payment retry sequences and account suspension
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger();

export interface DunningState {
  tenantId: string;
  status: 'healthy' | 'warning' | 'soft_suspended' | 'hard_suspended';
  failedPaymentCount: number;
  firstFailedAt: Date | null;
  lastFailedAt: Date | null;
  nextRetryAt: Date | null;
  suspendedAt: Date | null;
  queuedMessagesCount: number;
  gracePeriodEndsAt: Date | null;
}

export interface DunningConfig {
  retryScheduleDays: number[];    // Days after first failure to retry
  softSuspendAfterDays: number;   // Soft suspend (queue but don't send)
  hardSuspendAfterDays: number;   // Hard suspend (reject new messages)
  gracePeriodDays: number;        // Days to retain queued messages after hard suspend
}

// FIX-500-362: Moved dunning schedule configuration to a database table (dunning_config)
// so it can be updated at runtime per-tenant without redeployment.
// Current in-memory defaults are used as fallbacks when no DB config exists.
const DEFAULT_CONFIG: DunningConfig = {
  retryScheduleDays: [1, 3, 7, 14],
  softSuspendAfterDays: 7,
  hardSuspendAfterDays: 21,
  gracePeriodDays: 7,
};

/**
 * Dunning sequence management
 */
export class DunningService {
  private readonly config: DunningConfig;
  private configTableEnsured = false;

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    config?: Partial<DunningConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Record a failed payment
   * CRITICAL: Uses atomic transaction to ensure consistency
   */
  async recordFailedPayment(
    tenantId: string,
    invoiceId: string,
    amount: number
  ): Promise<Result<DunningState, Error>> {
    const tenantConfig = await this.getConfigForTenant(tenantId);
    const now = new Date();

    // Get or create dunning record
    const existingResult = await this.db.query<{
      id: string;
      failed_payment_count: number;
      first_failed_at: Date | null;
      status: DunningState['status'];
    }>(
      `SELECT id, failed_payment_count, first_failed_at, status
       FROM dunning_records
       WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!existingResult.ok) return Result.err(existingResult.error);

    const existing = existingResult.value.rows[0];
    const isFirstFailure = !existing || existing.status === 'healthy';
    const firstFailedAt = isFirstFailure ? now : existing.first_failed_at!;
    const failedCount = isFirstFailure ? 1 : existing.failed_payment_count + 1;

    // Calculate next retry date
    const nextRetryAt = this.calculateNextRetry(firstFailedAt, failedCount, tenantConfig);

    // Calculate status based on days since first failure
    const daysSinceFirstFailure = Math.floor(
      (now.getTime() - firstFailedAt.getTime()) / (1000 * 60 * 60 * 24)
    );

    let newStatus: DunningState['status'] = 'warning';
    let suspendedAt: Date | null = null;
    let gracePeriodEndsAt: Date | null = null;

    if (daysSinceFirstFailure >= tenantConfig.hardSuspendAfterDays) {
      newStatus = 'hard_suspended';
      suspendedAt = existing?.status === 'hard_suspended' ? null : now;
      gracePeriodEndsAt = new Date(now.getTime() + tenantConfig.gracePeriodDays * 24 * 60 * 60 * 1000);
    } else if (daysSinceFirstFailure >= tenantConfig.softSuspendAfterDays) {
      newStatus = 'soft_suspended';
      suspendedAt = existing?.status.includes('suspended') ? null : now;
    }

    // Use atomic CTE to upsert dunning record, log event, and update tenant if needed
    const metadata = JSON.stringify({ attempt: failedCount, daysSinceFirstFailure });
    const shouldSuspendTenant = newStatus === 'hard_suspended';

    const upsertResult = await this.db.query<{
      dunning_updated: boolean;
      event_logged: boolean;
      tenant_suspended: boolean;
    }>(
      `WITH upsert_dunning AS (
        INSERT INTO dunning_records (
          id, tenant_id, status, failed_payment_count, first_failed_at,
          last_failed_at, next_retry_at, suspended_at, grace_period_ends_at,
          created_at, updated_at
        )
        VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
          status = $2,
          failed_payment_count = $3,
          last_failed_at = $5,
          next_retry_at = $6,
          suspended_at = COALESCE(dunning_records.suspended_at, $7),
          grace_period_ends_at = COALESCE($8, dunning_records.grace_period_ends_at),
          updated_at = NOW()
        RETURNING tenant_id
      ),
      log_event AS (
        INSERT INTO dunning_events (
          id, tenant_id, event_type, invoice_id, amount, metadata, created_at
        )
        VALUES (gen_random_uuid(), $1, 'payment_failed', $9, $10, $11, NOW())
        RETURNING tenant_id
      ),
      suspend_tenant AS (
        UPDATE tenants 
        SET status = 'suspended', updated_at = NOW() 
        WHERE id = $1 AND $12 = true
        RETURNING id
      )
      SELECT 
        EXISTS (SELECT 1 FROM upsert_dunning) as dunning_updated,
        EXISTS (SELECT 1 FROM log_event) as event_logged,
        EXISTS (SELECT 1 FROM suspend_tenant) as tenant_suspended`,
      [
        tenantId,
        newStatus,
        failedCount,
        firstFailedAt,
        now,
        nextRetryAt,
        suspendedAt,
        gracePeriodEndsAt,
        invoiceId,
        amount,
        metadata,
        shouldSuspendTenant,
      ]
    );

    if (!upsertResult.ok) return Result.err(upsertResult.error);

    // Send notification (non-critical, doesn't need transaction)
    await this.sendDunningNotification(tenantId, newStatus, {
      failedCount,
      daysSinceFirstFailure,
      nextRetryAt,
    });

    // Cache status in Redis for fast checks
    await this.redis.setex(
      `dunning:status:${tenantId}`,
      3600,
      newStatus
    );

    return Result.ok({
      tenantId,
      status: newStatus,
      failedPaymentCount: failedCount,
      firstFailedAt,
      lastFailedAt: now,
      nextRetryAt,
      suspendedAt,
      queuedMessagesCount: await this.getQueuedMessagesCount(tenantId),
      gracePeriodEndsAt,
    });
  }

  /**
   * Record successful payment (clears dunning state)
   * CRITICAL: Uses atomic transaction to ensure consistency
   */
  async recordSuccessfulPayment(tenantId: string): Promise<Result<void, Error>> {
    // Use atomic CTE to update dunning record, log event, and reactivate tenant
    const result = await this.db.query(
      `WITH update_dunning AS (
        UPDATE dunning_records
        SET status = 'healthy', 
            failed_payment_count = 0,
            first_failed_at = NULL,
            last_failed_at = NULL,
            next_retry_at = NULL,
            suspended_at = NULL,
            grace_period_ends_at = NULL,
            updated_at = NOW()
        WHERE tenant_id = $1
        RETURNING tenant_id
      ),
      log_recovery AS (
        INSERT INTO dunning_events (id, tenant_id, event_type, created_at)
        VALUES (gen_random_uuid(), $1, 'payment_recovered', NOW())
        RETURNING tenant_id
      ),
      reactivate_tenant AS (
        UPDATE tenants 
        SET status = 'active', updated_at = NOW() 
        WHERE id = $1
        RETURNING id
      )
      SELECT 
        EXISTS (SELECT 1 FROM update_dunning) as dunning_updated,
        EXISTS (SELECT 1 FROM log_recovery) as event_logged,
        EXISTS (SELECT 1 FROM reactivate_tenant) as tenant_reactivated`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    // Clear Redis cache
    await this.redis.del(`dunning:status:${tenantId}`);

    // Drain queued messages if any
    const queuedCount = await this.getQueuedMessagesCount(tenantId);
    if (queuedCount > 0) {
      await this.releaseQueuedMessages(tenantId);
      logger.info('Released queued messages after payment recovery', { tenantId, queuedCount });
    }

    return Result.ok(undefined);
  }

  /**
   * Get dunning status (fast path from Redis)
   */
  async getStatus(tenantId: string): Promise<Result<DunningState['status'], Error>> {
    // Try Redis first
    const cached = await this.redis.get(`dunning:status:${tenantId}`);
    if (cached) {
      return Result.ok(cached as DunningState['status']);
    }

    // Fall back to database
    const result = await this.db.query<{ status: DunningState['status'] }>(
      `SELECT status FROM dunning_records WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const status = result.value.rows[0]?.status ?? 'healthy';

    // Cache for 1 hour
    await this.redis.setex(`dunning:status:${tenantId}`, 3600, status);

    return Result.ok(status);
  }

  /**
   * Check if tenant can send emails
   */
  async canSend(tenantId: string): Promise<Result<{
    allowed: boolean;
    reason?: string;
    shouldQueue?: boolean;
  }, Error>> {
    const statusResult = await this.getStatus(tenantId);
    if (!statusResult.ok) return Result.err(statusResult.error);

    switch (statusResult.value) {
      case 'healthy':
      case 'warning':
        return Result.ok({ allowed: true });

      case 'soft_suspended':
        return Result.ok({
          allowed: true,
          shouldQueue: true,
          reason: 'Payment past due - emails will be queued',
        });

      case 'hard_suspended':
        return Result.ok({
          allowed: false,
          reason: 'Account suspended due to failed payment. Please update payment method.',
        });
    }
  }

  /**
   * Process grace period expirations (run daily)
   * CRITICAL: Uses atomic CTE to ensure consistency
   */
  async processGracePeriodExpirations(): Promise<Result<{
    processedCount: number;
    purgedMessagesCount: number;
  }, Error>> {
    const now = new Date();

    // Use atomic CTE to: find expired, delete messages, queue notifications, update records
    const result = await this.db.query<{
      tenant_id: string;
      purged_count: number;
    }>(
      `WITH expired_tenants AS (
        SELECT tenant_id FROM dunning_records
        WHERE status = 'hard_suspended'
          AND grace_period_ends_at IS NOT NULL
          AND grace_period_ends_at < $1
        FOR UPDATE
      ),
      purge_messages AS (
        DELETE FROM messages 
        WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants) 
          AND status = 'dunning_queued'
        RETURNING tenant_id
      ),
      purge_counts AS (
        SELECT tenant_id, COUNT(*) as purged_count
        FROM purge_messages
        GROUP BY tenant_id
      ),
      queue_notifications AS (
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        SELECT gen_random_uuid(), et.tenant_id, 'messages_purged', 
               jsonb_build_object('purgedCount', COALESCE(pc.purged_count, 0)), 
               'pending', NOW()
        FROM expired_tenants et
        LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id
        RETURNING tenant_id
      ),
      update_dunning AS (
        UPDATE dunning_records
        SET grace_period_ends_at = NULL, updated_at = NOW()
        WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants)
        RETURNING tenant_id
      )
      SELECT et.tenant_id, COALESCE(pc.purged_count, 0)::int as purged_count
      FROM expired_tenants et
      LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id`,
      [now]
    );

    if (!result.ok) return Result.err(result.error);

    const processedCount = result.value.rows.length;
    const purgedMessagesCount = result.value.rows.reduce((sum, r) => sum + r.purged_count, 0);

    for (const row of result.value.rows) {
      logger.info('Purged queued messages after grace period', { 
        tenantId: row.tenant_id, 
        purgedCount: row.purged_count 
      });
    }

    return Result.ok({
      processedCount,
      purgedMessagesCount,
    });
  }

  /**
   * Get full dunning state
   */
  async getFullState(tenantId: string): Promise<Result<DunningState | null, Error>> {
    const result = await this.db.query<{
      tenant_id: string;
      status: DunningState['status'];
      failed_payment_count: number;
      first_failed_at: Date | null;
      last_failed_at: Date | null;
      next_retry_at: Date | null;
      suspended_at: Date | null;
      grace_period_ends_at: Date | null;
    }>(
      `SELECT * FROM dunning_records WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok({
      tenantId: row.tenant_id,
      status: row.status,
      failedPaymentCount: row.failed_payment_count,
      firstFailedAt: row.first_failed_at,
      lastFailedAt: row.last_failed_at,
      nextRetryAt: row.next_retry_at,
      suspendedAt: row.suspended_at,
      queuedMessagesCount: await this.getQueuedMessagesCount(tenantId),
      gracePeriodEndsAt: row.grace_period_ends_at,
    });
  }

  private calculateNextRetry(firstFailedAt: Date, attemptCount: number, config: DunningConfig): Date | null {
    const { retryScheduleDays } = config;

    if (attemptCount > retryScheduleDays.length) {
      return null; // No more retries
    }

    const daysToAdd = retryScheduleDays[attemptCount - 1];
    if (daysToAdd === undefined) {
      return null;
    }
    return new Date(firstFailedAt.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
  }

  private async ensureConfigTable(): Promise<void> {
    if (this.configTableEnsured) return;

    const result = await this.db.query(`
      CREATE TABLE IF NOT EXISTS dunning_config (
        tenant_id VARCHAR(36) PRIMARY KEY,
        retry_schedule_days INTEGER[] NOT NULL,
        soft_suspend_after_days INTEGER NOT NULL,
        hard_suspend_after_days INTEGER NOT NULL,
        grace_period_days INTEGER NOT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);

    if (!result.ok) {
      throw result.error;
    }
    this.configTableEnsured = true;
  }

  private async getConfigForTenant(tenantId: string): Promise<DunningConfig> {
    try {
      await this.ensureConfigTable();

      const result = await this.db.query<{
        retry_schedule_days: number[];
        soft_suspend_after_days: number;
        hard_suspend_after_days: number;
        grace_period_days: number;
      }>(
        `SELECT retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days
         FROM dunning_config
         WHERE tenant_id = $1`,
        [tenantId]
      );

      if (!result.ok) {
        return this.config;
      }

      const row = result.value.rows[0];
      if (!row) {
        return this.config;
      }

      const retryScheduleDays = Array.isArray(row.retry_schedule_days)
        ? row.retry_schedule_days.map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0)
        : this.config.retryScheduleDays;

      return {
        retryScheduleDays: retryScheduleDays.length > 0 ? retryScheduleDays : this.config.retryScheduleDays,
        softSuspendAfterDays: row.soft_suspend_after_days,
        hardSuspendAfterDays: row.hard_suspend_after_days,
        gracePeriodDays: row.grace_period_days,
      };
    } catch {
      return this.config;
    }
  }

  private async sendDunningNotification(
    tenantId: string,
    status: DunningState['status'],
    details: Record<string, unknown>
  ): Promise<void> {
    try {
      const notificationType = status === 'warning' 
        ? 'payment_reminder'
        : status === 'soft_suspended'
        ? 'account_soft_suspended'
        : 'account_hard_suspended';

      await this.db.query(
        `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
         VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW())`,
        [tenantId, notificationType, JSON.stringify(details)]
      );
    } catch (error) {
      console.error(`[Dunning] Failed to send notification for tenant ${tenantId}:`, error);
      // Don't throw - notification failure shouldn't block dunning process
    }
  }

  private async getQueuedMessagesCount(tenantId: string): Promise<number> {
    try {
      const result = await this.db.query<{ count: string }>(
        `SELECT COUNT(*)::text as count FROM messages
         WHERE tenant_id = $1 AND status = 'dunning_queued'`,
        [tenantId]
      );

      return result.ok ? parseInt(result.value.rows[0]?.count ?? '0', 10) : 0;
    } catch (error) {
      console.error(`[Dunning] Failed to get queued messages count for tenant ${tenantId}:`, error);
      return 0;
    }
  }

  private async releaseQueuedMessages(tenantId: string): Promise<number> {
    try {
      const result = await this.db.query<{ count: string }>(
        `WITH updated AS (
          UPDATE messages
          SET status = 'queued', updated_at = NOW()
          WHERE tenant_id = $1 AND status = 'dunning_queued'
          RETURNING id
        )
        SELECT COUNT(*)::text as count FROM updated`,
        [tenantId]
      );

      return result.ok ? parseInt(result.value.rows[0]?.count ?? '0', 10) : 0;
    } catch (error) {
      console.error(`[Dunning] Failed to release queued messages for tenant ${tenantId}:`, error);
      throw new Error(`Failed to release queued messages: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Purge dunning-queued messages (used for account termination)
   * Note: Kept as internal method for future use
   */
  async purgeQueuedMessages(tenantId: string): Promise<number> {
    try {
      const result = await this.db.query<{ count: string }>(
        `WITH deleted AS (
          DELETE FROM messages
          WHERE tenant_id = $1 AND status = 'dunning_queued'
          RETURNING id
        )
        SELECT COUNT(*)::text as count FROM deleted`,
        [tenantId]
      );

      return result.ok ? parseInt(result.value.rows[0]?.count ?? '0', 10) : 0;
    } catch (error) {
      console.error(`[Dunning] Failed to purge queued messages for tenant ${tenantId}:`, error);
      throw new Error(`Failed to purge queued messages: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
