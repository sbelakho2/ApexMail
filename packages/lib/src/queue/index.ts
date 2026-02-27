/**
 * Queue Wrapper - Postgres-backed Queue with SKIP LOCKED
 * 
 * Provides:
 * - Reliable job processing
 * - Visibility timeouts
 * - Dead-letter queue
 * - Priority queues
 * - Fair scheduling across tenants
 */

import { Result } from '../result.js';
import { getLogger, type Logger } from '../logger/index.js';
import type { Pool, PoolClient } from 'pg';
import { randomUUID } from 'node:crypto';

export interface QueueJob<T = unknown> {
  id: string;
  queue: string;
  payload: T;
  priority: number;
  attempts: number;
  maxAttempts: number;
  visibilityTimeout: number;
  createdAt: Date;
  scheduledAt: Date;
  lockedUntil: Date | null;
  tenantId: string | null;
  metadata: Record<string, unknown>;
}

export interface EnqueueOptions {
  priority?: number;
  delaySeconds?: number;
  maxAttempts?: number;
  visibilityTimeout?: number;
  tenantId?: string;
  metadata?: Record<string, unknown>;
}

export interface DequeueOptions {
  visibilityTimeout?: number;
  maxJobs?: number;
  tenantId?: string;
}

export interface QueueClientContext {
  client?: PoolClient;
}

export interface QueueStats {
  queue: string;
  pending: number;
  processing: number;
  deadLetter: number;
  completedToday: number;
  failedToday: number;
}

// Internal database row type
interface QueueJobRow {
  id: string;
  queue: string;
  payload: string;
  priority: number;
  attempts: number;
  max_attempts: number;
  visibility_timeout: number;
  created_at: Date;
  scheduled_at: Date;
  locked_until: Date | null;
  tenant_id: string | null;
  metadata: string;
  status: string;
}

export interface QueueProvider {
  enqueue<T>(queue: string, payload: T, options?: EnqueueOptions): Promise<Result<string, Error>>;
  dequeue<T>(queue: string, options?: DequeueOptions): Promise<Result<QueueJob<T>[], Error>>;
  complete(jobId: string): Promise<Result<void, Error>>;
  fail(jobId: string, error: Error): Promise<Result<void, Error>>;
  retry(jobId: string, delaySeconds?: number, options?: { resetAttempt?: boolean }): Promise<Result<void, Error>>;
  deadLetter(jobId: string, reason: string): Promise<Result<void, Error>>;
  getStats(queue: string): Promise<Result<QueueStats, Error>>;
  purge(queue: string): Promise<Result<number, Error>>;
  waitForJob?(queue: string, timeoutMs?: number): Promise<Result<boolean, Error>>;
  createSession?(): Promise<QueueSession>;
}

/**
 * Postgres-backed queue implementation using SELECT ... FOR UPDATE SKIP LOCKED
 */
export class PostgresQueueProvider implements QueueProvider {
  private readonly pool: Pool;
  private readonly logger: Logger;
  private readonly defaultVisibilityTimeout: number;
  private readonly defaultMaxAttempts: number;

  constructor(pool: Pool, options: {
    defaultVisibilityTimeout?: number;
    defaultMaxAttempts?: number;
  } = {}) {
    this.pool = pool;
    this.logger = getLogger().child({ component: 'queue' });
    this.defaultVisibilityTimeout = options.defaultVisibilityTimeout ?? 300; // 5 minutes
    this.defaultMaxAttempts = options.defaultMaxAttempts ?? 3;
  }

  private async withClient<T>(
    client: PoolClient | undefined,
    fn: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    if (client) {
      return fn(client);
    }
    const owned = await this.pool.connect();
    try {
      return await fn(owned);
    } finally {
      owned.release();
    }
  }

  async createSession(): Promise<QueueSession> {
    const client = await this.pool.connect();
    return new QueueSession(this, client);
  }

  async enqueue<T>(
    queue: string,
    payload: T,
    options: EnqueueOptions = {},
    context: QueueClientContext = {}
  ): Promise<Result<string, Error>> {
    return this.withClient(context.client, async (client) => {
      const id = randomUUID();
      const now = new Date();
      const scheduledAt = options.delaySeconds
        ? new Date(now.getTime() + options.delaySeconds * 1000)
        : now;

      await client.query(
        `INSERT INTO queue_jobs (
          id, queue, payload, priority, attempts, max_attempts,
          visibility_timeout, created_at, scheduled_at, tenant_id, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          id,
          queue,
          JSON.stringify(payload),
          options.priority ?? 0,
          0,
          options.maxAttempts ?? this.defaultMaxAttempts,
          options.visibilityTimeout ?? this.defaultVisibilityTimeout,
          now,
          scheduledAt,
          options.tenantId ?? null,
          JSON.stringify(options.metadata ?? {}),
        ]
      );

      await client.query('NOTIFY queue_jobs, $1', [queue]);

      this.logger.debug('Job enqueued', { jobId: id, queue });
      return Result.ok(id);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async dequeue<T>(
    queue: string,
    options: DequeueOptions = {},
    context: QueueClientContext = {}
  ): Promise<Result<QueueJob<T>[], Error>> {
    return this.withClient(context.client, async (client) => {
      const visibilityTimeout = options.visibilityTimeout ?? this.defaultVisibilityTimeout;
      const maxJobs = options.maxJobs ?? 1;
      const now = new Date();
      const lockUntil = new Date(now.getTime() + visibilityTimeout * 1000);

      // Build tenant filter for fair scheduling
      let tenantFilter = '';
      const params: unknown[] = [queue, now, lockUntil, maxJobs];
      
      if (options.tenantId) {
        tenantFilter = 'AND tenant_id = $5';
        params.push(options.tenantId);
      }

      // Use SKIP LOCKED for concurrent workers
      const result = await client.query<{
        id: string;
        queue: string;
        payload: string;
        priority: number;
        attempts: number;
        max_attempts: number;
        visibility_timeout: number;
        created_at: Date;
        scheduled_at: Date;
        locked_until: Date | null;
        tenant_id: string | null;
        metadata: string;
      }>(
        `UPDATE queue_jobs
         SET locked_until = $3,
           attempts = attempts + CASE WHEN locked_until IS NULL THEN 1 ELSE 0 END
         WHERE id IN (
           SELECT id FROM queue_jobs
           WHERE queue = $1
             AND scheduled_at <= $2
             AND (locked_until IS NULL OR locked_until < $2)
             AND status = 'pending'
             ${tenantFilter}
           ORDER BY priority DESC, scheduled_at ASC
           FOR UPDATE SKIP LOCKED
           LIMIT $4
         )
         RETURNING *`,
        params
      );

      // FIX-500-372: Wrap JSON.parse in try-catch to handle corrupt job payloads
      // without crashing the entire dequeue batch
      // BUG-005 FIX: Move corrupt jobs to dead-letter queue instead of silently skipping
      const jobs: QueueJob<T>[] = [];
      for (const row of result.rows as QueueJobRow[]) {
        try {
          jobs.push({
            id: row.id,
            queue: row.queue,
            payload: JSON.parse(row.payload) as T,
            priority: row.priority,
            attempts: row.attempts,
            maxAttempts: row.max_attempts,
            visibilityTimeout: row.visibility_timeout,
            createdAt: row.created_at,
            scheduledAt: row.scheduled_at,
            lockedUntil: row.locked_until,
            tenantId: row.tenant_id,
            metadata: JSON.parse(row.metadata) as Record<string, unknown>,
          });
        } catch (parseError) {
          // BUG-005 FIX: Move corrupt jobs to DLQ instead of silently dropping
          const errorMsg = parseError instanceof Error ? parseError.message : String(parseError);
          this.logger.error('Moving corrupt job to DLQ', {
            jobId: row.id,
            queue,
            error: errorMsg,
          });
          // Move to dead letter queue asynchronously (don't block dequeue)
          void client.query(
            `UPDATE queue_jobs SET status = 'dead_letter', error = $2, failed_at = NOW() WHERE id = $1`,
            [row.id, `JSON parse error: ${errorMsg}`]
          ).catch((dlqErr) => {
            this.logger.error('Failed to move corrupt job to DLQ', { 
              jobId: row.id, 
              error: dlqErr instanceof Error ? dlqErr.message : String(dlqErr) 
            });
          });
        }
      }

      if (jobs.length > 0) {
        this.logger.debug('Jobs dequeued', { queue, count: jobs.length });
      }

      return Result.ok(jobs);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async waitForJob(queue: string, timeoutMs = 30000): Promise<Result<boolean, Error>> {
    const client = await this.pool.connect();

    try {
      await client.query('LISTEN queue_jobs');

      const result = await new Promise<Result<boolean, Error>>((resolve) => {
        const timer = setTimeout(() => {
          cleanup();
          resolve(Result.ok(false));
        }, timeoutMs);

        const onNotification = (msg: { channel: string; payload?: string | null }) => {
          if (msg.channel !== 'queue_jobs') return;
          if (msg.payload && msg.payload !== queue) return;
          cleanup();
          resolve(Result.ok(true));
        };

        const cleanup = () => {
          clearTimeout(timer);
          client.removeListener('notification', onNotification);
        };

        client.on('notification', onNotification);
      });

      return result;
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      try {
        await client.query('UNLISTEN queue_jobs');
      } catch {
        // Ignore unlisten errors
      }
      client.release();
    }
  }

  async complete(jobId: string, context: QueueClientContext = {}): Promise<Result<void, Error>> {
    return this.withClient(context.client, async (client) => {
      await client.query(
        `UPDATE queue_jobs 
         SET status = 'completed', completed_at = NOW()
         WHERE id = $1`,
        [jobId]
      );

      this.logger.debug('Job completed', { jobId });
      return Result.ok(undefined);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async fail(jobId: string, error: Error, context: QueueClientContext = {}): Promise<Result<void, Error>> {
    return this.withClient(context.client, async (client) => {
      const result = await client.query<{ status: string }>(
        `UPDATE queue_jobs
         SET status = CASE WHEN attempts >= max_attempts THEN 'dead_letter' ELSE 'pending' END,
             failed_at = CASE WHEN attempts >= max_attempts THEN NOW() ELSE failed_at END,
             error_message = CASE WHEN attempts >= max_attempts THEN $2 ELSE error_message END,
             locked_until = NULL,
             scheduled_at = CASE
               WHEN attempts >= max_attempts THEN scheduled_at
               ELSE NOW() + (LEAST(visibility_timeout * POWER(2, GREATEST(attempts - 1, 0)), 3600) || ' seconds')::interval
             END
         WHERE id = $1
         RETURNING status`,
        [jobId, error.message]
      );

      const row = result.rows[0];
      if (!row) {
        return Result.err(new Error(`Job not found: ${jobId}`));
      }

      if (row.status === 'dead_letter') {
        this.logger.warn('Job moved to dead-letter queue', { jobId, reason: error.message });
      } else {
        this.logger.debug('Job scheduled for retry', { jobId });
      }

      return Result.ok(undefined);
    }).catch((err) =>
      Result.err(err instanceof Error ? err : new Error(String(err)))
    );
  }

  async retry(
    jobId: string,
    delaySeconds = 0,
    options: { resetAttempt?: boolean } = {},
    context: QueueClientContext = {}
  ): Promise<Result<void, Error>> {
    return this.withClient(context.client, async (client) => {
      const scheduledAt = new Date(Date.now() + delaySeconds * 1000);

      const resetClause = options.resetAttempt ? ', attempts = GREATEST(attempts - 1, 0)' : '';
      await client.query(
        `UPDATE queue_jobs 
         SET locked_until = NULL, scheduled_at = $2${resetClause}
         WHERE id = $1`,
        [jobId, scheduledAt]
      );

      this.logger.debug('Job scheduled for retry', { jobId, delaySeconds });
      return Result.ok(undefined);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async deadLetter(jobId: string, reason: string, context: QueueClientContext = {}): Promise<Result<void, Error>> {
    return this.withClient(context.client, async (client) => {
      await client.query(
        `UPDATE queue_jobs 
         SET status = 'dead_letter', 
             failed_at = NOW(),
             error_message = $2
         WHERE id = $1`,
        [jobId, reason]
      );

      this.logger.warn('Job moved to dead-letter queue', { jobId, reason });
      return Result.ok(undefined);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async getStats(queue: string, context: QueueClientContext = {}): Promise<Result<QueueStats, Error>> {
    return this.withClient(context.client, async (client) => {
      const result = await client.query<{
        status: string;
        count: string;
      }>(
        `SELECT status, COUNT(*) as count
         FROM queue_jobs
         WHERE queue = $1
         GROUP BY status`,
        [queue]
      );

      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);

      const todayResult = await client.query<{
        completed: string;
        failed: string;
      }>(
        `SELECT 
           COUNT(*) FILTER (WHERE status = 'completed' AND completed_at >= $2) as completed,
           COUNT(*) FILTER (WHERE status = 'dead_letter' AND failed_at >= $2) as failed
         FROM queue_jobs
         WHERE queue = $1`,
        [queue, todayStart]
      );

      const stats: QueueStats = {
        queue,
        pending: 0,
        processing: 0,
        deadLetter: 0,
        completedToday: 0,
        failedToday: 0,
      };

      for (const row of result.rows) {
        switch (row.status) {
          case 'pending':
            stats.pending = parseInt(row.count, 10);
            break;
          case 'processing':
            stats.processing = parseInt(row.count, 10);
            break;
          case 'dead_letter':
            stats.deadLetter = parseInt(row.count, 10);
            break;
        }
      }

      if (todayResult.rows[0]) {
        stats.completedToday = parseInt(todayResult.rows[0].completed, 10);
        stats.failedToday = parseInt(todayResult.rows[0].failed, 10);
      }

      return Result.ok(stats);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }

  async purge(queue: string, context: QueueClientContext = {}): Promise<Result<number, Error>> {
    return this.withClient(context.client, async (client) => {
      const result = await client.query(
        `DELETE FROM queue_jobs WHERE queue = $1 AND status IN ('pending', 'dead_letter')`,
        [queue]
      );

      this.logger.info('Queue purged', { queue, deleted: result.rowCount });
      return Result.ok(result.rowCount ?? 0);
    }).catch((error) =>
      Result.err(error instanceof Error ? error : new Error(String(error)))
    );
  }
}

export class QueueSession {
  constructor(
    private readonly provider: PostgresQueueProvider,
    private readonly client: PoolClient
  ) {}

  async enqueue<T>(queue: string, payload: T, options: EnqueueOptions = {}): Promise<Result<string, Error>> {
    return this.provider.enqueue(queue, payload, options, { client: this.client });
  }

  async dequeue<T>(queue: string, options: DequeueOptions = {}): Promise<Result<QueueJob<T>[], Error>> {
    return this.provider.dequeue(queue, options, { client: this.client });
  }

  async complete(jobId: string): Promise<Result<void, Error>> {
    return this.provider.complete(jobId, { client: this.client });
  }

  async fail(jobId: string, error: Error): Promise<Result<void, Error>> {
    return this.provider.fail(jobId, error, { client: this.client });
  }

  async retry(jobId: string, delaySeconds = 0, options: { resetAttempt?: boolean } = {}): Promise<Result<void, Error>> {
    return this.provider.retry(jobId, delaySeconds, options, { client: this.client });
  }

  async deadLetter(jobId: string, reason: string): Promise<Result<void, Error>> {
    return this.provider.deadLetter(jobId, reason, { client: this.client });
  }

  async getStats(queue: string): Promise<Result<QueueStats, Error>> {
    return this.provider.getStats(queue, { client: this.client });
  }

  async purge(queue: string): Promise<Result<number, Error>> {
    return this.provider.purge(queue, { client: this.client });
  }

  async close(): Promise<void> {
    this.client.release();
  }
}

/**
 * Fair scheduler to prevent tenant starvation
 * Implements weighted fair queuing
 */
export class FairQueueScheduler {
  private readonly queue: QueueProvider;
  private readonly maxTenantShare: number;
  private readonly tenantCounts: Map<string, number> = new Map();
  private readonly windowMs: number;
  // FIX-500-371: Cap tenantCounts to prevent unbounded growth between resets
  private static readonly MAX_TENANT_ENTRIES = 10_000;
  private lastReset: number = Date.now();

  constructor(
    queue: QueueProvider,
    options: {
      maxTenantShare?: number; // Max percentage of capacity per tenant (0-1)
      windowMs?: number; // Window for counting tenant jobs
    } = {}
  ) {
    this.queue = queue;
    this.maxTenantShare = options.maxTenantShare ?? 0.3; // 30% max
    this.windowMs = options.windowMs ?? 60000; // 1 minute window
  }

  async dequeue<T>(
    queueName: string,
    maxJobs: number
  ): Promise<Result<QueueJob<T>[], Error>> {
    // Reset counts if window expired or tenant count exceeds cap
    if (Date.now() - this.lastReset > this.windowMs || this.tenantCounts.size > FairQueueScheduler.MAX_TENANT_ENTRIES) {
      this.tenantCounts.clear();
      this.lastReset = Date.now();
    }

    const result = await this.queue.dequeue<T>(queueName, { maxJobs });
    if (!result.ok) return result;

    // Filter jobs based on fair share
    const fairJobs: QueueJob<T>[] = [];
    const maxPerTenant = Math.ceil(maxJobs * this.maxTenantShare);

    for (const job of result.value) {
      const tenantId = job.tenantId ?? '__default__';
      const currentCount = this.tenantCounts.get(tenantId) ?? 0;

      if (currentCount < maxPerTenant) {
        fairJobs.push(job);
        this.tenantCounts.set(tenantId, currentCount + 1);
      } else {
        // Return job to queue with small delay (priority boost for fairness)
        const delaySeconds = Math.max(1, Math.ceil(this.windowMs / 1000));
        await this.queue.retry(job.id, delaySeconds, { resetAttempt: true });
      }
    }

    return Result.ok(fairJobs);
  }
}

// SQL for creating the queue tables
export const QUEUE_SCHEMA = `
CREATE TYPE queue_status AS ENUM ('pending', 'processing', 'completed', 'dead_letter');

CREATE TABLE IF NOT EXISTS queue_jobs (
  id UUID PRIMARY KEY,
  queue VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  visibility_timeout INTEGER NOT NULL DEFAULT 300,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  locked_until TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failed_at TIMESTAMPTZ,
  error_message TEXT,
  tenant_id VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}',
  status queue_status NOT NULL DEFAULT 'pending'
);

CREATE INDEX idx_queue_jobs_dequeue ON queue_jobs (queue, scheduled_at, priority DESC)
  WHERE status = 'pending';
CREATE INDEX idx_queue_jobs_tenant ON queue_jobs (tenant_id, queue)
  WHERE status = 'pending';
CREATE INDEX idx_queue_jobs_locked ON queue_jobs (locked_until)
  WHERE locked_until IS NOT NULL;
`;
