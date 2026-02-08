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
import type { Pool } from 'pg';

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
  retry(jobId: string, delaySeconds?: number): Promise<Result<void, Error>>;
  deadLetter(jobId: string, reason: string): Promise<Result<void, Error>>;
  getStats(queue: string): Promise<Result<QueueStats, Error>>;
  purge(queue: string): Promise<Result<number, Error>>;
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

  async enqueue<T>(
    queue: string,
    payload: T,
    options: EnqueueOptions = {}
  ): Promise<Result<string, Error>> {
    const client = await this.pool.connect();
    
    try {
      const id = crypto.randomUUID();
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

      this.logger.debug('Job enqueued', { jobId: id, queue });
      return Result.ok(id);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async dequeue<T>(
    queue: string,
    options: DequeueOptions = {}
  ): Promise<Result<QueueJob<T>[], Error>> {
    const client = await this.pool.connect();
    
    try {
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
         SET locked_until = $3, attempts = attempts + 1
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
          // Skip corrupt jobs — log and let them expire via visibility timeout
          this.logger.error('Failed to parse job payload/metadata', {
            jobId: row.id,
            queue,
            error: parseError instanceof Error ? parseError.message : String(parseError),
          });
        }
      }

      if (jobs.length > 0) {
        this.logger.debug('Jobs dequeued', { queue, count: jobs.length });
      }

      return Result.ok(jobs);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async complete(jobId: string): Promise<Result<void, Error>> {
    const client = await this.pool.connect();
    
    try {
      await client.query(
        `UPDATE queue_jobs 
         SET status = 'completed', completed_at = NOW()
         WHERE id = $1`,
        [jobId]
      );

      this.logger.debug('Job completed', { jobId });
      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async fail(jobId: string, error: Error): Promise<Result<void, Error>> {
    const client = await this.pool.connect();
    
    try {
      // Check if should retry or dead-letter
      const result = await client.query<{
        attempts: number;
        max_attempts: number;
        visibility_timeout: number;
      }>(
        'SELECT attempts, max_attempts, visibility_timeout FROM queue_jobs WHERE id = $1',
        [jobId]
      );

      const job = result.rows[0];
      if (!job) {
        return Result.err(new Error(`Job not found: ${jobId}`));
      }

      if (job.attempts >= job.max_attempts) {
        // Move to dead-letter
        return this.deadLetter(jobId, error.message);
      }

      // Retry with exponential backoff
      const delaySeconds = Math.min(
        job.visibility_timeout * Math.pow(2, job.attempts - 1),
        3600 // Max 1 hour
      );
      
      return this.retry(jobId, delaySeconds);
    } catch (err) {
      return Result.err(err instanceof Error ? err : new Error(String(err)));
    } finally {
      client.release();
    }
  }

  async retry(jobId: string, delaySeconds = 0): Promise<Result<void, Error>> {
    const client = await this.pool.connect();
    
    try {
      const scheduledAt = new Date(Date.now() + delaySeconds * 1000);
      
      await client.query(
        `UPDATE queue_jobs 
         SET locked_until = NULL, scheduled_at = $2
         WHERE id = $1`,
        [jobId, scheduledAt]
      );

      this.logger.debug('Job scheduled for retry', { jobId, delaySeconds });
      return Result.ok(undefined);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async deadLetter(jobId: string, reason: string): Promise<Result<void, Error>> {
    const client = await this.pool.connect();
    
    try {
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
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async getStats(queue: string): Promise<Result<QueueStats, Error>> {
    const client = await this.pool.connect();
    
    try {
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
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
  }

  async purge(queue: string): Promise<Result<number, Error>> {
    const client = await this.pool.connect();
    
    try {
      const result = await client.query(
        `DELETE FROM queue_jobs WHERE queue = $1 AND status IN ('pending', 'dead_letter')`,
        [queue]
      );

      this.logger.info('Queue purged', { queue, deleted: result.rowCount });
      return Result.ok(result.rowCount ?? 0);
    } catch (error) {
      return Result.err(error instanceof Error ? error : new Error(String(error)));
    } finally {
      client.release();
    }
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
        await this.queue.retry(job.id, 1);
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
