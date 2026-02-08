/**
 * Webhook Processor - Delivers webhook events to customer endpoints
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { hmacSign } from '@apexmail/lib/crypto';
import { CircuitBreakerFactory } from '../circuit-breaker.js';
import type { QueueNotifier } from '../queue-notifier.js';
import * as dns from 'dns/promises';
import * as net from 'net';

interface WebhookProcessorConfig {
  db: Pool;
  redis: Redis;
  notifier?: QueueNotifier;
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
  /** F-234: Parsed Retry-After value from the target server (in milliseconds). */
  retryAfterMs?: number;
}

/**
 * C-114: Maximum concurrent webhook deliveries per tenant.
 * Prevents a single tenant from monopolizing all worker slots.
 */
const MAX_CONCURRENT_PER_TENANT = 5;

/**
 * C-119: Maximum webhook payload size in bytes (1 MB).
 * Prevents arbitrarily large payloads from consuming excessive
 * bandwidth and memory during delivery.
 */
const MAX_WEBHOOK_PAYLOAD_BYTES = 1 * 1024 * 1024; // 1 MB

export class WebhookProcessor {
  private readonly db: Pool;
  private readonly redis: Redis;
  private readonly config: WebhookProcessorConfig['config'];
  private readonly logger: Logger;
  private readonly circuitBreakers: CircuitBreakerFactory;
  private readonly notifier: QueueNotifier | undefined;
  /**
   * FIX-500-082: Reuse a single dns.Resolver instance instead of
   * creating implicit resolvers via dns.resolve4/dns.resolve6 per call.
   */
  private readonly dnsResolver: dns.Resolver;
  /**
   * FIX-500-083: DNS result cache with 60-second TTL to avoid
   * re-resolving the same hostname on every webhook delivery.
   */
  private readonly dnsCache = new Map<string, { ips: string[]; expiresAt: number }>();
  private static readonly DNS_CACHE_TTL_MS = 60_000;
  
  private isRunning = false;
  private activeJobs = 0;
  /** C-114: Track active jobs per tenant to enforce per-tenant concurrency. */
  private readonly tenantActiveJobs = new Map<string, number>();
  /**
   * FIX-500-081: Batch completion buffer — success completions are queued
   * here and flushed in a single multi-row transaction after each poll batch.
   */
  private readonly pendingSuccesses: Array<{ job: WebhookJob; result: WebhookDeliveryResult }> = [];

  constructor(options: WebhookProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.logger = options.logger;
    this.notifier = options.notifier;
    
    // FIX-500-082: Reuse a single dns.Resolver instance
    this.dnsResolver = new dns.Resolver();
    
    // Initialize circuit breaker factory for per-endpoint circuit breakers
    this.circuitBreakers = new CircuitBreakerFactory(options.redis, {
      failureThreshold: 5,
      resetTimeout: 30000,  // 30 seconds
      successThreshold: 2,
      rollingWindowMs: 60000, // 1 minute
    });
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
          // LISTEN/NOTIFY wakeup: sleep until notified or fallback timeout
          if (this.notifier) {
            await this.notifier.waitForNotification('queue_webhook_queue', 30_000);
          } else {
            await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          }
          continue;
        }

        // Use allSettled to prevent single failure from failing entire batch
        const results = await Promise.allSettled(jobs.map(job => this.processJob(job)));
        
        // Log any unexpected rejections (processJob should handle its own errors)
        for (let i = 0; i < results.length; i++) {
          const result = results[i];
          if (result && result.status === 'rejected') {
            this.logger.error('Unexpected webhook job processing error', {
              jobId: jobs[i]?.id,
              error: result.reason,
            });
          }
        }

        // FIX-500-081: Flush batched success completions in one transaction
        await this.flushPendingSuccesses();
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  private async fetchJobs(limit: number): Promise<WebhookJob[]> {
    const lockUntil = new Date(Date.now() + 60000); // 1 minute lock
    
    // Use CTE with UPDATE...RETURNING for atomic claim
    // This prevents race conditions between SELECT and UPDATE
    const result = await this.db.query<WebhookJob & { id: string }>(`
      WITH claimed_jobs AS (
        UPDATE webhook_queue wq
        SET status = 'processing', locked_until = $1, updated_at = NOW()
        WHERE wq.id IN (
          SELECT wq2.id
          FROM webhook_queue wq2
          JOIN webhooks w ON w.id = wq2.webhook_id
          WHERE wq2.status = 'pending'
            AND (wq2.scheduled_at IS NULL OR wq2.scheduled_at <= NOW())
            AND (wq2.locked_until IS NULL OR wq2.locked_until < NOW())
            AND w.enabled = true
          ORDER BY wq2.created_at ASC
          LIMIT $2
          FOR UPDATE OF wq2 SKIP LOCKED
        )
        RETURNING wq.id, wq.webhook_id, wq.tenant_id, wq.event_type, 
                  wq.payload, wq.attempt, wq.created_at
      )
      SELECT 
        cj.id, cj.webhook_id as "webhookId", cj.tenant_id as "tenantId",
        cj.event_type as "eventType", cj.payload, cj.attempt, cj.created_at as "createdAt",
        w.url, w.secret, w.headers,
        (w.retry_policy->>'maxRetries')::int as "maxRetries",
        (w.retry_policy->>'retryDelay')::int as "retryDelay",
        (w.retry_policy->>'backoffMultiplier')::float as "backoffMultiplier"
      FROM claimed_jobs cj
      JOIN webhooks w ON w.id = cj.webhook_id
    `, [lockUntil, limit]);

    return result.rows;
  }

  private async processJob(job: WebhookJob): Promise<void> {
    // C-114: Enforce per-tenant concurrency limit
    const tenantCurrent = this.tenantActiveJobs.get(job.tenantId) ?? 0;
    if (tenantCurrent >= MAX_CONCURRENT_PER_TENANT) {
      this.logger.warn('C-114: Per-tenant webhook concurrency limit reached, rescheduling', {
        tenantId: job.tenantId,
        tenantActiveJobs: tenantCurrent,
        limit: MAX_CONCURRENT_PER_TENANT,
        jobId: job.id,
      });
      // FIX-500-101: Set scheduled_at 5s in the future to avoid hot-loop
      // re-fetch on the next 100ms poll cycle.
      await this.db.query(
        `UPDATE webhook_queue SET status = 'pending', scheduled_at = NOW() + INTERVAL '5 seconds', locked_until = NULL, updated_at = NOW() WHERE id = $1`,
        [job.id],
      );
      return;
    }

    this.activeJobs++;
    this.tenantActiveJobs.set(job.tenantId, tenantCurrent + 1);
    const startTime = Date.now();

    try {
      this.logger.debug('Processing webhook job', {
        jobId: job.id,
        webhookId: job.webhookId,
        eventType: job.eventType,
        attempt: job.attempt,
      });

      /**
       * C-086: Webhook delivery deduplication.
       *
       * If the process crashes after a successful HTTP delivery but before
       * the transactional completion (INSERT delivery + DELETE from queue),
       * the job stays in the queue and would be re-delivered on next poll.
       *
       * We set a Redis key BEFORE delivery and check it here. If the key
       * exists from a previous attempt, skip re-delivery and just clean up.
       * The key has a 24h TTL to prevent unbounded growth.
       */
      const dedupKey = `webhook:dedup:${job.id}:${job.attempt}`;
      const previouslyDelivered = await this.redis.get(dedupKey);
      if (previouslyDelivered) {
        this.logger.warn('Webhook already delivered (dedup), cleaning up', {
          jobId: job.id,
          webhookId: job.webhookId,
          attempt: job.attempt,
        });
        // Remove the orphaned queue entry
        await this.db.query('DELETE FROM webhook_queue WHERE id = $1', [job.id]);
        return;
      }

      // Get circuit breaker for this webhook endpoint (keyed by webhook ID)
      const circuitBreaker = this.circuitBreakers.get(`webhook:${job.webhookId}`);

      // Check if circuit is open
      const canExecute = await circuitBreaker.canExecute();
      if (!canExecute) {
        this.logger.warn('Circuit breaker open for webhook', {
          webhookId: job.webhookId,
          jobId: job.id,
        });
        
        // FIX-500-005: Don't increment attempt count when CB is open — the endpoint
        // was never contacted, so consuming a retry is unfair. Just reschedule with
        // a delay so we re-check the CB state later.
        const cbRetryDelay = Math.min(30000, job.retryDelay * Math.pow(job.backoffMultiplier, job.attempt - 1));
        const scheduledAt = new Date(Date.now() + cbRetryDelay);
        await this.db.query(
          `UPDATE webhook_queue SET status = 'pending', scheduled_at = $1, locked_until = NULL, last_error = 'Circuit breaker open — waiting for recovery', updated_at = NOW() WHERE id = $2`,
          [scheduledAt, job.id]
        );
        return;
      }

      // C-119: Enforce payload size limit before delivery.
      // Truncate large fields (e.g. full HTML body) to prevent oversized payloads.
      const rawPayload = JSON.stringify(job.payload);
      if (rawPayload.length > MAX_WEBHOOK_PAYLOAD_BYTES) {
        this.logger.warn('C-119: Webhook payload exceeds size limit, truncating large fields', {
          jobId: job.id,
          webhookId: job.webhookId,
          originalSize: rawPayload.length,
          limit: MAX_WEBHOOK_PAYLOAD_BYTES,
        });
        job.payload = this.truncatePayload(job.payload, MAX_WEBHOOK_PAYLOAD_BYTES);
      }

      /**
       * C-128: Cache the serialized payload to avoid redundant JSON.stringify calls.
       * The same serialized form is used for:
       *   1. HMAC signature computation (signPayload)
       *   2. HTTP request body (fetch)
       * Previously, JSON.stringify was called separately in signPayload() and
       * in the fetch body, doubling serialization cost for every delivery.
       */
      const serializedPayload = JSON.stringify(job.payload);

      // Mark as in-flight before delivery (24h TTL)
      await this.redis.set(dedupKey, '1', 'EX', 86400);

      const result = await this.deliverWebhook(job, serializedPayload);

      // Update circuit breaker state based on result
      if (result.success) {
        await circuitBreaker.recordSuccess();
        await this.handleSuccess(job, result);
      } else {
        await circuitBreaker.recordFailure();
        // Remove dedup key on failure so retries aren't blocked
        await this.redis.del(dedupKey).catch(() => {});
        await this.handleFailure(job, result);
      }

    } catch (error) {
      // Record failure in circuit breaker for unexpected errors
      const circuitBreaker = this.circuitBreakers.get(`webhook:${job.webhookId}`);
      await circuitBreaker.recordFailure();
      // Remove dedup key on error so retries aren't blocked
      await this.redis.del(`webhook:dedup:${job.id}:${job.attempt}`).catch(() => {});
      await this.handleError(job, error as Error);
    } finally {
      this.activeJobs--;
      // C-114: Decrement per-tenant counter
      const tenantCount = (this.tenantActiveJobs.get(job.tenantId) ?? 1) - 1;
      if (tenantCount <= 0) {
        this.tenantActiveJobs.delete(job.tenantId);
      } else {
        this.tenantActiveJobs.set(job.tenantId, tenantCount);
      }
      
      const duration = Date.now() - startTime;
      this.logger.debug('Webhook job completed', {
        jobId: job.id,
        duration,
        activeJobs: this.activeJobs,
        tenantActiveJobs: this.tenantActiveJobs.get(job.tenantId) ?? 0,
      });
    }
  }

  /**
   * C-119: Truncate oversized webhook payloads by removing or shortening
   * large string fields (e.g. html, text, content) to stay within the
   * size limit. Preserves structure and metadata.
   */
  private truncatePayload(
    payload: Record<string, unknown>,
    maxBytes: number,
  ): Record<string, unknown> {
    const TRUNCATION_NOTICE = '[truncated — payload exceeded size limit]';
    // Fields commonly containing large content that can be safely truncated
    const largeFieldKeys = new Set(['html', 'htmlBody', 'textBody', 'text', 'content', 'body', 'raw_message', 'rawMessage']);

    const truncateObj = (obj: Record<string, unknown>): Record<string, unknown> => {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && largeFieldKeys.has(key) && value.length > 1024) {
          result[key] = value.substring(0, 512) + TRUNCATION_NOTICE;
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          result[key] = truncateObj(value as Record<string, unknown>);
        } else {
          result[key] = value;
        }
      }
      return result;
    };

    let truncated = truncateObj(payload);

    // If still over limit after field truncation, aggressively truncate any large string
    let serialized = JSON.stringify(truncated);
    if (serialized.length > maxBytes) {
      const aggressiveTruncate = (obj: Record<string, unknown>): Record<string, unknown> => {
        const res: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'string' && value.length > 256) {
            res[key] = value.substring(0, 256) + TRUNCATION_NOTICE;
          } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            res[key] = aggressiveTruncate(value as Record<string, unknown>);
          } else {
            res[key] = value;
          }
        }
        return res;
      };
      truncated = aggressiveTruncate(truncated);
    }

    return truncated;
  }

  /**
   * C-128: Accepts an optional pre-serialized payload to avoid redundant
   * JSON.stringify calls. When provided, the same string is used for both
   * HMAC signature computation and the HTTP request body.
   */
  private async deliverWebhook(job: WebhookJob, cachedBody?: string): Promise<WebhookDeliveryResult> {
    // SECURITY FIX (FIX-032): Re-validate URL at delivery time to prevent DNS rebinding
    // DNS may have changed since registration to point to internal/private IPs
    try {
      await this.validateDeliveryUrl(job.url);
    } catch (error) {
      return {
        success: false,
        responseTime: 0,
        error: `SSRF protection: ${error instanceof Error ? error.message : 'URL validation failed'}`,
      };
    }

    const timestamp = Date.now();
    const deliveryId = generateId('dlv');

    // C-128: Use pre-serialized payload if available, otherwise serialize once here
    const body = cachedBody ?? JSON.stringify(job.payload);
    
    // Sign payload using the same serialized body
    const signature = this.signPayloadRaw(job.secret, timestamp, body);

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
        body,
        signal: AbortSignal.timeout(30000), // 30 second timeout
      });

      const responseTime = Date.now() - startTime;
      let responseBody: string | undefined;

      try {
        /**
         * FIX-500-084: Stream response body with byte limit instead of
         * buffering the entire response via response.text(). We read up
         * to 1 KB and discard the rest.
         */
        const MAX_RESPONSE_BYTES = 1024;
        const reader = response.body?.getReader();
        if (reader) {
          const chunks: Uint8Array[] = [];
          let totalBytes = 0;
          let truncated = false;

          while (totalBytes < MAX_RESPONSE_BYTES) {
            const { done, value } = await reader.read();
            if (done || !value) break;
            const remaining = MAX_RESPONSE_BYTES - totalBytes;
            if (value.length > remaining) {
              chunks.push(value.subarray(0, remaining));
              totalBytes += remaining;
              truncated = true;
              break;
            }
            chunks.push(value);
            totalBytes += value.length;
          }
          // Cancel the rest of the stream to free resources
          reader.cancel().catch(() => {});

          const decoder = new TextDecoder();
          responseBody = chunks.map(c => decoder.decode(c, { stream: true })).join('');
          if (truncated) {
            responseBody += '...';
          }
        }
      } catch (bodyErr) {
        // FIX-500-436: Log response body read errors for debugging.
        // Don't fail the delivery, but record the issue for diagnostics.
        this.logger.warn('FIX-500-436: Failed to read webhook response body', {
          statusCode: response.status,
          error: bodyErr instanceof Error ? bodyErr.message : String(bodyErr),
        });
      }

      if (response.ok) {
        return {
          success: true,
          statusCode: response.status,
          responseTime,
          responseBody,
        };
      }

      // F-234: Parse Retry-After header when present (429 or 503 responses).
      // The header value can be seconds (integer) or an HTTP-date string.
      let retryAfterMs: number | undefined;
      const retryAfterHeader = response.headers.get('retry-after');
      if (retryAfterHeader && (response.status === 429 || response.status === 503)) {
        const parsed = parseInt(retryAfterHeader, 10);
        if (!isNaN(parsed) && parsed > 0) {
          // Value is in seconds — cap at 1 hour to prevent abuse
          retryAfterMs = Math.min(parsed, 3600) * 1000;
        } else {
          // Try parsing as HTTP-date (RFC 7231)
          const date = new Date(retryAfterHeader);
          if (!isNaN(date.getTime())) {
            const delayMs = date.getTime() - Date.now();
            if (delayMs > 0) {
              retryAfterMs = Math.min(delayMs, 3600_000); // cap at 1 hour
            }
          }
        }
        this.logger.info('F-234: Retry-After header received from webhook endpoint', {
          url: job.url,
          webhookId: job.webhookId,
          statusCode: response.status,
          retryAfterHeader,
          retryAfterMs,
        });
      }

      return {
        success: false,
        statusCode: response.status,
        responseTime,
        error: `HTTP ${response.status}: ${response.statusText}`,
        responseBody,
        retryAfterMs,
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

  /**
   * C-128: Unified signing method that accepts either a pre-serialized
   * payload string or a Record object. When a string is provided, it
   * avoids the redundant JSON.stringify call.
   */
  private signPayload(secret: string, timestamp: number, payload: Record<string, unknown> | string): string {
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const message = `${timestamp}.${body}`;
    return 'sha256=' + hmacSign(secret, message, 'sha256');
  }

  /**
   * C-128: Alias that makes the pre-serialized intent explicit in calling code.
   */
  private signPayloadRaw(secret: string, timestamp: number, serializedPayload: string): string {
    return this.signPayload(secret, timestamp, serializedPayload);
  }

  private isRetryableStatusCode(statusCode: number): boolean {
    // Retry on server errors and some client errors
    return statusCode >= 500 || statusCode === 408 || statusCode === 429;
  }

  /**
   * SECURITY (FIX-032): Validate URL at delivery time to prevent DNS rebinding.
   * FIX-500-082: Uses reusable Resolver instance.
   * FIX-500-083: Caches DNS results for 60 seconds.
   */
  private async validateDeliveryUrl(urlString: string): Promise<void> {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // FIX-500-437: Allow extending blocked hosts via env var for different
    // deployment environments (AWS 169.254.169.254, custom internal DNS, etc.)
    const defaultBlocked = [
      'localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]',
      'metadata.google.internal', 'instance-data',
      'kubernetes.default', 'kubernetes.default.svc',
    ];
    const extraBlocked = process.env.WEBHOOK_BLOCKED_HOSTS?.split(',').map(h => h.trim()).filter(Boolean) ?? [];
    const blocked = [...defaultBlocked, ...extraBlocked];
    if (blocked.some(h => hostname.toLowerCase() === h || hostname.toLowerCase().endsWith('.' + h))) {
      throw new Error('URL points to internal/localhost address');
    }

    // If hostname is an IP, check directly
    if (net.isIP(hostname)) {
      if (isPrivateIP(hostname)) {
        throw new Error(`URL resolves to private IP: ${hostname}`);
      }
      return;
    }

    // FIX-500-083: Check DNS cache first
    // FIX-500-442: Implement LRU eviction by deleting and re-inserting on hit,
    // so the Map iteration order reflects access order (most recent at end).
    const cached = this.dnsCache.get(hostname);
    let allAddresses: string[];

    if (cached && cached.expiresAt > Date.now()) {
      // LRU: move to end of Map iteration order
      this.dnsCache.delete(hostname);
      this.dnsCache.set(hostname, cached);
      allAddresses = cached.ips;
    } else {
      // FIX-500-082: Use the shared resolver instance
      const addresses4 = await this.dnsResolver.resolve4(hostname).catch(() => [] as string[]);
      const addresses6 = await this.dnsResolver.resolve6(hostname).catch(() => [] as string[]);
      allAddresses = [...addresses4, ...addresses6];

      // Cache the result
      // FIX-500-442: Cap DNS cache size; evict oldest (LRU) entry
      if (this.dnsCache.size >= 500) {
        const firstKey = this.dnsCache.keys().next().value;
        if (firstKey !== undefined) this.dnsCache.delete(firstKey);
      }
      this.dnsCache.set(hostname, {
        ips: allAddresses,
        expiresAt: Date.now() + WebhookProcessor.DNS_CACHE_TTL_MS,
      });
    }

    if (allAddresses.length === 0) {
      throw new Error('URL hostname could not be resolved');
    }

    for (const ip of allAddresses) {
      if (isPrivateIP(ip)) {
        throw new Error(`URL resolves to private IP: ${ip}`);
      }
    }
  }

  /**
   * FIX-500-081: Queue success for batch flush instead of per-job transaction.
   */
  private async handleSuccess(job: WebhookJob, result: WebhookDeliveryResult): Promise<void> {
    this.logger.info('Webhook delivered successfully', {
      jobId: job.id,
      webhookId: job.webhookId,
      statusCode: result.statusCode,
      responseTime: result.responseTime,
    });

    this.pendingSuccesses.push({ job, result });
  }

  /**
   * FIX-500-081: Flush all pending success completions in a single
   * multi-row transaction. Falls back to individual handling on error.
   * FIX-500-450: Uses unnest arrays instead of manual $N param numbering
   * for cleaner, less error-prone batched INSERTs.
   */
  private async flushPendingSuccesses(): Promise<void> {
    if (this.pendingSuccesses.length === 0) return;

    const batch = this.pendingSuccesses.splice(0);
    const client = await this.db.connect();

    try {
      await client.query('BEGIN');

      // FIX-500-450: Batch INSERT delivery records using unnest arrays
      if (batch.length > 0) {
        const ids: string[] = [];
        const webhookIds: string[] = [];
        const tenantIds: string[] = [];
        const eventTypes: string[] = [];
        const statusCodes: number[] = [];
        const responseTimes: number[] = [];
        const attempts: number[] = [];

        for (const { job, result } of batch) {
          ids.push(generateId('wdl'));
          webhookIds.push(job.webhookId);
          tenantIds.push(job.tenantId);
          eventTypes.push(job.eventType);
          statusCodes.push(result.statusCode ?? 0);
          responseTimes.push(result.responseTime ?? 0);
          attempts.push(job.attempt);
        }

        await client.query(`
          INSERT INTO webhook_deliveries (
            id, webhook_id, tenant_id, event_type, status, status_code,
            response_time, attempt, delivered_at
          )
          SELECT
            unnest($1::text[]),
            unnest($2::text[]),
            unnest($3::text[]),
            unnest($4::text[]),
            'success',
            unnest($5::int[]),
            unnest($6::int[]),
            unnest($7::int[]),
            NOW()
        `, [ids, webhookIds, tenantIds, eventTypes, statusCodes, responseTimes, attempts]);
      }

      // Batch UPDATE webhook stats via unnest
      const webhookIds = batch.map(b => b.job.webhookId);
      await client.query(`
        UPDATE webhooks
        SET
          total_deliveries = total_deliveries + 1,
          successful_deliveries = successful_deliveries + 1,
          last_delivery_at = NOW(),
          last_success_at = NOW(),
          updated_at = NOW()
        WHERE id = ANY($1::text[])
      `, [webhookIds]);

      // Batch DELETE from queue
      const jobIds = batch.map(b => b.job.id);
      await client.query(
        'DELETE FROM webhook_queue WHERE id = ANY($1::text[])',
        [jobIds]
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      this.logger.error('FIX-500-081: Batch flush failed, falling back to individual', {
        error: error instanceof Error ? error.message : String(error),
        count: batch.length,
      });
      // Fall back to individual handling
      for (const { job, result } of batch) {
        try {
          await this.handleSuccessIndividual(job, result);
        } catch (individualErr) {
          this.logger.error('Individual webhook success handling also failed', {
            jobId: job.id,
            error: individualErr instanceof Error ? individualErr.message : String(individualErr),
          });
        }
      }
    } finally {
      client.release();
    }
  }

  /**
   * FIX-500-081: Fallback per-job success handler when batch flush fails.
   */
  private async handleSuccessIndividual(job: WebhookJob, result: WebhookDeliveryResult): Promise<void> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      await client.query(`
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

      await client.query(`
        UPDATE webhooks
        SET
          total_deliveries = total_deliveries + 1,
          successful_deliveries = successful_deliveries + 1,
          last_delivery_at = NOW(),
          last_success_at = NOW(),
          updated_at = NOW()
        WHERE id = $1
      `, [job.webhookId]);

      await client.query('DELETE FROM webhook_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
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
      await this.retryJob(job, result.error ?? 'Unknown error', result.retryAfterMs);
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

  /**
   * F-234: retryAfterMs — when the target server sends a Retry-After header,
   * we honour it instead of using our own exponential backoff, capped at 1 hour.
   *
   * FIX-500-170: Record each failed delivery attempt before rescheduling.
   * Previously retryJob only UPDATE'd the queue — no record of the attempt was
   * stored in webhook_deliveries, making it impossible to debug partial failures.
   */
  private async retryJob(job: WebhookJob, error: string, retryAfterMs?: number): Promise<void> {
    const nextAttempt = job.attempt + 1;
    // FIX-500-102: Increased from 60s to 300s to survive longer outages
    const MAX_RETRY_DELAY = 300_000; // 300 seconds cap (for computed backoff)
    const computedDelay = Math.min(job.retryDelay * Math.pow(job.backoffMultiplier, job.attempt - 1), MAX_RETRY_DELAY);
    // F-234: Prefer server-requested delay over computed backoff
    const delay = retryAfterMs ?? computedDelay;
    const scheduledAt = new Date(Date.now() + delay);

    // FIX-500-170: Record the failed delivery attempt
    await this.db.query(`
      INSERT INTO webhook_deliveries (
        id, webhook_id, tenant_id, event_type, status,
        error_message, attempt, delivered_at
      ) VALUES ($1, $2, $3, $4, 'failed', $5, $6, NOW())
    `, [
      generateId('wdl'),
      job.webhookId,
      job.tenantId,
      job.eventType,
      error,
      job.attempt,
    ]);

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

    /**
     * PERF-003: Transactional completion — all-or-nothing.
     *
     * Previously these were 4 independent queries. If the process crashed
     * after DELETE but before INSERT INTO webhook_dlq, the job was gone
     * with no record. Now all four run atomically.
     */
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Record failed delivery
      await client.query(`
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
      await client.query(`
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
      await client.query(`
        INSERT INTO webhook_dlq (id, original_job, error_message, failed_at)
        VALUES ($1, $2, $3, NOW())
      `, [generateId('wdq'), JSON.stringify(job), result.error]);

      // Remove from queue
      await client.query('DELETE FROM webhook_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    // Check if webhook should be disabled (outside transaction — best-effort)
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
    if (!stats) return; // TypeScript guard for array access
    
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
  // C-099: Suppress duplicate webhook events.
  // If the same (tenant, event type, message ID) combination is already
  // queued and still pending, skip insertion to prevent duplicate deliveries.
  // This guards against callers that may fire the same event more than once
  // (e.g. retries, concurrent handlers processing the same message).
  const messageId = (data.messageId as string) || '';
  if (messageId) {
    const existing = await db.query(
      `SELECT 1 FROM webhook_queue
       WHERE tenant_id = $1
         AND event_type = $2
         AND payload->>'type' = $2
         AND payload->'data'->>'messageId' = $3
         AND status IN ('pending', 'processing')
       LIMIT 1`,
      [tenantId, eventType, messageId]
    );
    if (existing.rows.length > 0) {
      return; // C-099: duplicate event suppressed
    }
  }

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
  const values = result.rows.map((_row: { id: string }, index: number) => {
    const offset = index * 5;  // Fixed: we have 5 placeholders per row
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

/**
 * SECURITY (FIX-032): Check if an IP address is internal/private.
 * Prevents SSRF via DNS rebinding at webhook delivery time.
 */
function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === undefined || b === undefined) return false;
    if (a === 127) return true;                           // Loopback
    if (a === 10) return true;                            // Class A private
    if (a === 172 && b >= 16 && b <= 31) return true;     // Class B private
    if (a === 192 && b === 168) return true;              // Class C private
    if (a === 169 && b === 254) return true;              // Link-local / metadata
    if (a >= 224 && a <= 239) return true;                // Multicast
    if (a === 0 || a === 255) return true;                // Reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const n = ip.toLowerCase();
    if (n === '::1' || n === '::') return true;
    if (n.startsWith('fe80:') || n.startsWith('fc') || n.startsWith('fd')) return true;
    if (n.startsWith('ff')) return true;
    if (n.startsWith('::ffff:')) {
      const v4 = n.slice(7);
      if (net.isIPv4(v4)) return isPrivateIP(v4);
    }
    return false;
  }
  return true; // Unknown format — deny by default
}
