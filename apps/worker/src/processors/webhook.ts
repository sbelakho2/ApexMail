/**
 * Webhook Processor - Delivers webhook events to customer endpoints
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { createHmac } from 'crypto';

interface WebhookProcessorConfig {
  db: Pool;
  redis: Redis;
  config: {
    name: string;
    concurrency: number;
    pollInterval: number;
    maxRetries: number;
    retryDelay: number;
  };
  logger: Logger;
}

interface WebhookJob {
  id: string;
  webhookId: string;
  tenantId: string;
  eventType: string;
  payload: Record<string, unknown>;
  url: string;
  secret: string;
  headers?: Record<string, string>;
  attempt: number;
  maxRetries: number;
  retryDelay: number;
  backoffMultiplier: number;
  createdAt: Date;
}

interface WebhookDeliveryResult {
  success: boolean;
  statusCode?: number;
  responseTime: number;
  error?: string;
  responseBody?: string;
}

export class WebhookProcessor {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly config: WebhookProcessorConfig['config'];
  private readonly logger: Logger;
  
  private isRunning = false;
  private activeJobs = 0;

  constructor(options: WebhookProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.logger = options.logger;
  }

  async start(): Promise<void> {
    this.logger.info('Starting webhook processor', {
      concurrency: this.config.concurrency,
      pollInterval: this.config.pollInterval,
    });

    this.isRunning = true;
    this.poll();
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping webhook processor');
    this.isRunning = false;

    // Wait for active jobs
    const maxWait = 30000;
    const startTime = Date.now();
    
    while (this.activeJobs > 0 && Date.now() - startTime < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (this.activeJobs > 0) {
      this.logger.warn('Forcing stop with active jobs', { activeJobs: this.activeJobs });
    }

    this.logger.info('Webhook processor stopped');
  }

  private async poll(): Promise<void> {
    while (this.isRunning) {
      try {
        const availableSlots = this.config.concurrency - this.activeJobs;
        if (availableSlots <= 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
          continue;
        }

        const jobs = await this.fetchJobs(availableSlots);
        
        if (jobs.length === 0) {
          await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          continue;
        }

        await Promise.all(jobs.map(job => this.processJob(job)));
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  private async fetchJobs(limit: number): Promise<WebhookJob[]> {
    const result = await this.db.query<WebhookJob>(`
      SELECT 
        wq.id, wq.webhook_id as "webhookId", wq.tenant_id as "tenantId",
        wq.event_type as "eventType", wq.payload, wq.attempt, wq.created_at as "createdAt",
        w.url, w.secret, w.headers,
        (w.retry_policy->>'maxRetries')::int as "maxRetries",
        (w.retry_policy->>'retryDelay')::int as "retryDelay",
        (w.retry_policy->>'backoffMultiplier')::float as "backoffMultiplier"
      FROM webhook_queue wq
      JOIN webhooks w ON w.id = wq.webhook_id
      WHERE wq.status = 'pending'
        AND (wq.scheduled_at IS NULL OR wq.scheduled_at <= NOW())
        AND (wq.locked_until IS NULL OR wq.locked_until < NOW())
        AND w.enabled = true
      ORDER BY wq.created_at ASC
      LIMIT $1
      FOR UPDATE OF wq SKIP LOCKED
    `, [limit]);

    if (result.rows.length === 0) {
      return [];
    }

    // Lock jobs
    const ids = result.rows.map(r => r.id);
    const lockUntil = new Date(Date.now() + 60000); // 1 minute lock

    await this.db.query(`
      UPDATE webhook_queue
      SET status = 'processing', locked_until = $1, updated_at = NOW()
      WHERE id = ANY($2)
    `, [lockUntil, ids]);

    return result.rows;
  }

  private async processJob(job: WebhookJob): Promise<void> {
    this.activeJobs++;
    const startTime = Date.now();

    try {
      this.logger.debug('Processing webhook job', {
        jobId: job.id,
        webhookId: job.webhookId,
        eventType: job.eventType,
        attempt: job.attempt,
      });

      const result = await this.deliverWebhook(job);

      if (result.success) {
        await this.handleSuccess(job, result);
      } else {
        await this.handleFailure(job, result);
      }

    } catch (error) {
      await this.handleError(job, error as Error);
    } finally {
      this.activeJobs--;
      
      const duration = Date.now() - startTime;
      this.logger.debug('Webhook job completed', {
        jobId: job.id,
        duration,
        activeJobs: this.activeJobs,
      });
    }
  }

  private async deliverWebhook(job: WebhookJob): Promise<WebhookDeliveryResult> {
    const timestamp = Date.now();
    const deliveryId = generateId('dlv');
    
    // Sign payload
    const signature = this.signPayload(job.secret, timestamp, job.payload);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-ApexMail-Webhook-Id': job.webhookId,
      'X-ApexMail-Signature': signature,
      'X-ApexMail-Timestamp': timestamp.toString(),
      'X-ApexMail-Event': job.eventType,
      'X-ApexMail-Delivery-Id': deliveryId,
      'User-Agent': 'ApexMail-Webhook/1.0',
      ...job.headers,
    };

    const startTime = Date.now();

    try {
      const response = await fetch(job.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(job.payload),
        signal: AbortSignal.timeout(30000), // 30 second timeout
      });

      const responseTime = Date.now() - startTime;
      let responseBody: string | undefined;

      try {
        responseBody = await response.text();
        // Truncate response body
        if (responseBody.length > 1000) {
          responseBody = responseBody.substring(0, 1000) + '...';
        }
      } catch {
        // Ignore response body read errors
      }

      if (response.ok) {
        return {
          success: true,
          statusCode: response.status,
          responseTime,
          responseBody,
        };
      }

      // Check if retryable status code
      const isRetryable = this.isRetryableStatusCode(response.status);
      
      return {
        success: false,
        statusCode: response.status,
        responseTime,
        error: `HTTP ${response.status}: ${response.statusText}`,
        responseBody,
      };

    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        success: false,
        responseTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private signPayload(secret: string, timestamp: number, payload: Record<string, unknown>): string {
    const message = `${timestamp}.${JSON.stringify(payload)}`;
    return 'sha256=' + createHmac('sha256', secret).update(message).digest('hex');
  }

  private isRetryableStatusCode(statusCode: number): boolean {
    // Retry on server errors and some client errors
    return statusCode >= 500 || statusCode === 408 || statusCode === 429;
  }

  private async handleSuccess(job: WebhookJob, result: WebhookDeliveryResult): Promise<void> {
    this.logger.info('Webhook delivered successfully', {
      jobId: job.id,
      webhookId: job.webhookId,
      statusCode: result.statusCode,
      responseTime: result.responseTime,
    });

    // Record delivery
    await this.db.query(`
      INSERT INTO webhook_deliveries (
        id, webhook_id, tenant_id, event_type, status, status_code,
        response_time, attempt, delivered_at
      ) VALUES ($1, $2, $3, $4, 'success', $5, $6, $7, NOW())
    `, [
      generateId('wdl'),
      job.webhookId,
      job.tenantId,
      job.eventType,
      result.statusCode,
      result.responseTime,
      job.attempt,
    ]);

    // Update webhook stats
    await this.db.query(`
      UPDATE webhooks
      SET 
        total_deliveries = total_deliveries + 1,
        successful_deliveries = successful_deliveries + 1,
        last_delivery_at = NOW(),
        last_success_at = NOW(),
        updated_at = NOW()
      WHERE id = $1
    `, [job.webhookId]);

    // Remove from queue
    await this.db.query('DELETE FROM webhook_queue WHERE id = $1', [job.id]);
  }

  private async handleFailure(job: WebhookJob, result: WebhookDeliveryResult): Promise<void> {
    this.logger.warn('Webhook delivery failed', {
      jobId: job.id,
      webhookId: job.webhookId,
      statusCode: result.statusCode,
      error: result.error,
      attempt: job.attempt,
    });

    const isRetryable = result.statusCode 
      ? this.isRetryableStatusCode(result.statusCode)
      : true; // Network errors are retryable

    const canRetry = isRetryable && job.attempt < job.maxRetries;

    if (canRetry) {
      await this.retryJob(job, result.error ?? 'Unknown error');
    } else {
      await this.failJob(job, result);
    }
  }

  private async handleError(job: WebhookJob, error: Error): Promise<void> {
    this.logger.error('Webhook processing error', {
      jobId: job.id,
      webhookId: job.webhookId,
      error: error.message,
    });

    if (job.attempt < job.maxRetries) {
      await this.retryJob(job, error.message);
    } else {
      await this.failJob(job, { success: false, responseTime: 0, error: error.message });
    }
  }

  private async retryJob(job: WebhookJob, error: string): Promise<void> {
    const nextAttempt = job.attempt + 1;
    const delay = job.retryDelay * Math.pow(job.backoffMultiplier, job.attempt - 1);
    const scheduledAt = new Date(Date.now() + delay);

    await this.db.query(`
      UPDATE webhook_queue
      SET 
        status = 'pending',
        attempt = $1,
        scheduled_at = $2,
        last_error = $3,
        locked_until = NULL,
        updated_at = NOW()
      WHERE id = $4
    `, [nextAttempt, scheduledAt, error, job.id]);

    this.logger.debug('Webhook job scheduled for retry', {
      jobId: job.id,
      nextAttempt,
      scheduledAt,
    });
  }

  private async failJob(job: WebhookJob, result: WebhookDeliveryResult): Promise<void> {
    this.logger.error('Webhook delivery permanently failed', {
      jobId: job.id,
      webhookId: job.webhookId,
      attempts: job.attempt,
      error: result.error,
    });

    // Record failed delivery
    await this.db.query(`
      INSERT INTO webhook_deliveries (
        id, webhook_id, tenant_id, event_type, status, status_code,
        response_time, error_message, attempt, delivered_at
      ) VALUES ($1, $2, $3, $4, 'failed', $5, $6, $7, $8, NOW())
    `, [
      generateId('wdl'),
      job.webhookId,
      job.tenantId,
      job.eventType,
      result.statusCode,
      result.responseTime,
      result.error,
      job.attempt,
    ]);

    // Update webhook stats
    await this.db.query(`
      UPDATE webhooks
      SET 
        total_deliveries = total_deliveries + 1,
        failed_deliveries = failed_deliveries + 1,
        last_delivery_at = NOW(),
        last_failure_at = NOW(),
        last_error = $1,
        updated_at = NOW()
      WHERE id = $2
    `, [result.error, job.webhookId]);

    // Move to dead letter queue
    await this.db.query(`
      INSERT INTO webhook_dlq (id, original_job, error_message, failed_at)
      VALUES ($1, $2, $3, NOW())
    `, [generateId('wdq'), JSON.stringify(job), result.error]);

    // Remove from queue
    await this.db.query('DELETE FROM webhook_queue WHERE id = $1', [job.id]);

    // Check if webhook should be disabled
    await this.checkWebhookHealth(job.webhookId);
  }

  private async checkWebhookHealth(webhookId: string): Promise<void> {
    // Get recent delivery stats
    const result = await this.db.query<{
      total: string;
      failures: string;
      recent_failures: string;
    }>(`
      SELECT 
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'failed') as failures,
        COUNT(*) FILTER (WHERE status = 'failed' AND delivered_at > NOW() - INTERVAL '1 hour') as recent_failures
      FROM webhook_deliveries
      WHERE webhook_id = $1 AND delivered_at > NOW() - INTERVAL '24 hours'
    `, [webhookId]);

    if (result.rows.length === 0) return;

    const stats = result.rows[0];
    const total = parseInt(stats.total, 10);
    const failures = parseInt(stats.failures, 10);
    const recentFailures = parseInt(stats.recent_failures, 10);

    // Disable webhook if:
    // - More than 10 consecutive failures in the last hour, OR
    // - More than 50% failure rate with at least 20 attempts
    const shouldDisable = recentFailures >= 10 || (total >= 20 && failures / total > 0.5);

    if (shouldDisable) {
      await this.db.query(`
        UPDATE webhooks
        SET enabled = false, disabled_reason = 'auto_disabled_high_failure_rate', updated_at = NOW()
        WHERE id = $1 AND enabled = true
      `, [webhookId]);

      this.logger.warn('Webhook auto-disabled due to high failure rate', {
        webhookId,
        total,
        failures,
        recentFailures,
      });
    }
  }

  /**
   * Queue a webhook event for delivery
   */
  async queueWebhookEvent(
    webhookId: string,
    tenantId: string,
    eventType: string,
    payload: Record<string, unknown>
  ): Promise<string> {
    const jobId = generateId('whj');

    await this.db.query(`
      INSERT INTO webhook_queue (
        id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
      ) VALUES ($1, $2, $3, $4, $5, 'pending', 1, NOW())
    `, [jobId, webhookId, tenantId, eventType, JSON.stringify(payload)]);

    return jobId;
  }
}

/**
 * Helper function to queue webhook events from other parts of the system
 */
export async function dispatchWebhookEvent(
  db: Pool,
  tenantId: string,
  eventType: string,
  data: Record<string, unknown>
): Promise<void> {
  // Find all enabled webhooks for this tenant that subscribe to this event
  const result = await db.query<{ id: string }>(`
    SELECT id
    FROM webhooks
    WHERE tenant_id = $1
      AND enabled = true
      AND (events @> $2::jsonb OR events @> '"*"'::jsonb)
  `, [tenantId, JSON.stringify([eventType])]);

  if (result.rows.length === 0) return;

  const payload = {
    id: generateId('evt'),
    type: eventType,
    tenantId,
    timestamp: new Date().toISOString(),
    data,
  };

  // Queue events for each webhook
  const values = result.rows.map((row, index) => {
    const offset = index * 6;
    return `($${offset + 1}, $${offset + 2}, $${offset + 3}, $${offset + 4}, $${offset + 5}, 'pending', 1, NOW())`;
  }).join(', ');

  const params: (string | Record<string, unknown>)[] = [];
  for (const row of result.rows) {
    params.push(generateId('whj'), row.id, tenantId, eventType, JSON.stringify(payload));
  }

  if (params.length > 0) {
    await db.query(`
      INSERT INTO webhook_queue (
        id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at
      ) VALUES ${values}
    `, params);
  }
}
