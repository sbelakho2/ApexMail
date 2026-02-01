/**
 * Dunning Service
 * Manages failed payment retry sequences and account suspension
 */

import Redis from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger('dunning');

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

  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis,
    config?: Partial<DunningConfig>
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Record a failed payment
   */
  async recordFailedPayment(
    tenantId: string,
    invoiceId: string,
    amount: number
  ): Promise<Result<DunningState, Error>> {
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
    const nextRetryAt = this.calculateNextRetry(firstFailedAt, failedCount);

    // Calculate status based on days since first failure
    const daysSinceFirstFailure = Math.floor(
      (now.getTime() - firstFailedAt.getTime()) / (1000 * 60 * 60 * 24)
    );

    let newStatus: DunningState['status'] = 'warning';
    let suspendedAt: Date | null = null;
    let gracePeriodEndsAt: Date | null = null;

    if (daysSinceFirstFailure >= this.config.hardSuspendAfterDays) {
      newStatus = 'hard_suspended';
      suspendedAt = existing?.status === 'hard_suspended' ? null : now;
      gracePeriodEndsAt = new Date(now.getTime() + this.config.gracePeriodDays * 24 * 60 * 60 * 1000);
    } else if (daysSinceFirstFailure >= this.config.softSuspendAfterDays) {
      newStatus = 'soft_suspended';
      suspendedAt = existing?.status.includes('suspended') ? null : now;
    }

    // Upsert dunning record
    const upsertResult = await this.db.query(
      `INSERT INTO dunning_records (
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
        updated_at = NOW()`,
      [
        tenantId,
        newStatus,
        failedCount,
        firstFailedAt,
        now,
        nextRetryAt,
        suspendedAt,
        gracePeriodEndsAt,
      ]
    );

    if (!upsertResult.ok) return Result.err(upsertResult.error);

    // Log payment failure
    await this.db.query(
      `INSERT INTO dunning_events (
        id, tenant_id, event_type, invoice_id, amount, metadata, created_at
      )
      VALUES (gen_random_uuid(), $1, 'payment_failed', $2, $3, $4, NOW())`,
      [tenantId, invoiceId, amount, JSON.stringify({ attempt: failedCount, daysSinceFirstFailure })]
    );

    // Send notification
    await this.sendDunningNotification(tenantId, newStatus, {
      failedCount,
      daysSinceFirstFailure,
      nextRetryAt,
    });

    // Update tenant status if suspended
    if (newStatus === 'hard_suspended') {
      await this.db.query(
        `UPDATE tenants SET status = 'suspended', updated_at = NOW() WHERE id = $1`,
        [tenantId]
      );
    }

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
   */
  async recordSuccessfulPayment(tenantId: string): Promise<Result<void, Error>> {
    // Update dunning record
    await this.db.query(
      `UPDATE dunning_records
       SET status = 'healthy', 
           failed_payment_count = 0,
           first_failed_at = NULL,
           last_failed_at = NULL,
           next_retry_at = NULL,
           suspended_at = NULL,
           grace_period_ends_at = NULL,
           updated_at = NOW()
       WHERE tenant_id = $1`,
      [tenantId]
    );

    // Log recovery
    await this.db.query(
      `INSERT INTO dunning_events (id, tenant_id, event_type, created_at)
       VALUES (gen_random_uuid(), $1, 'payment_recovered', NOW())`,
      [tenantId]
    );

    // Reactivate tenant
    await this.db.query(
      `UPDATE tenants SET status = 'active', updated_at = NOW() WHERE id = $1`,
      [tenantId]
    );

    // Clear Redis cache
    await this.redis.del(`dunning:status:${tenantId}`);

    // Drain queued messages if any
    const queuedCount = await this.getQueuedMessagesCount(tenantId);
    if (queuedCount > 0) {
      await this.releaseQueuedMessages(tenantId);
      logger.info({ tenantId, queuedCount }, 'Released queued messages after payment recovery');
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
   */
  async processGracePeriodExpirations(): Promise<Result<{
    processedCount: number;
    purgedMessagesCount: number;
  }, Error>> {
    const now = new Date();

    // Find tenants with expired grace periods
    const expiredResult = await this.db.query<{
      tenant_id: string;
    }>(
      `SELECT tenant_id FROM dunning_records
       WHERE status = 'hard_suspended'
         AND grace_period_ends_at IS NOT NULL
         AND grace_period_ends_at < $1`,
      [now]
    );

    if (!expiredResult.ok) return Result.err(expiredResult.error);

    let totalPurged = 0;

    for (const row of expiredResult.value.rows) {
      const purgedCount = await this.purgeQueuedMessages(row.tenant_id);
      totalPurged += purgedCount;

      // Send final notification
      await this.db.query(
        `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
         VALUES (gen_random_uuid(), $1, 'messages_purged', $2, 'pending', NOW())`,
        [row.tenant_id, JSON.stringify({ purgedCount })]
      );

      // Update dunning record
      await this.db.query(
        `UPDATE dunning_records
         SET grace_period_ends_at = NULL, updated_at = NOW()
         WHERE tenant_id = $1`,
        [row.tenant_id]
      );

      logger.info({ tenantId: row.tenant_id, purgedCount }, 'Purged queued messages after grace period');
    }

    return Result.ok({
      processedCount: expiredResult.value.rows.length,
      purgedMessagesCount: totalPurged,
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

  private calculateNextRetry(firstFailedAt: Date, attemptCount: number): Date | null {
    const { retryScheduleDays } = this.config;

    if (attemptCount > retryScheduleDays.length) {
      return null; // No more retries
    }

    const daysToAdd = retryScheduleDays[attemptCount - 1] ?? retryScheduleDays[retryScheduleDays.length - 1];
    return new Date(firstFailedAt.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
  }

  private async sendDunningNotification(
    tenantId: string,
    status: DunningState['status'],
    details: Record<string, unknown>
  ): Promise<void> {
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
  }

  private async getQueuedMessagesCount(tenantId: string): Promise<number> {
    const result = await this.db.query<{ count: string }>(
      `SELECT COUNT(*)::text as count FROM messages
       WHERE tenant_id = $1 AND status = 'dunning_queued'`,
      [tenantId]
    );

    return result.ok ? parseInt(result.value.rows[0]?.count ?? '0', 10) : 0;
  }

  private async releaseQueuedMessages(tenantId: string): Promise<number> {
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
  }

  private async purgeQueuedMessages(tenantId: string): Promise<number> {
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
  }
}
