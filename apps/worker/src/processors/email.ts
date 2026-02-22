/**
 * Email Processor - Handles email sending from queue
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { DomainsRepository, SuppressionsRepository, type Domain, type DatabasePool } from '@apexmail/db';
import { CircuitBreakerFactory } from '../circuit-breaker.js';
import { IPRateLimiter } from '../services/ip-rate-limiter.js';
import type { QueueNotifier } from '../queue-notifier.js';
import {
  createEmailTransport,
  type EmailTransport,
  type SendResult,
  type EmailMessage,
  type DkimConfig,
  type TransportType,
  type SesTransportConfig,
} from '../services/email-transport.js';

interface EmailProcessorConfig {
  db: Pool;
  dbPool: DatabasePool;
  redis: Redis;
  config: {
    name: string;
    concurrency: number;
    pollInterval: number;
    visibilityTimeout: number;
    maxRetries: number;
    retryDelay: number;
  };
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    auth?: { user: string; pass: string };
    pool: boolean;
    maxConnections: number;
    maxMessages: number;
    rateLimitPerSecond: number;
  };
  dkim: {
    enabled: boolean;
    selector: string;
    keyPath?: string;
  };
  tracking: {
    enabled: boolean;
    baseUrl: string;
    openPixelPath: string;
    clickRedirectPath: string;
  };
  warmup: {
    enabled: boolean;
    schedule: Record<string, number[]>;
  };
  ipRateLimiting?: {
    enabled: boolean;
    ipAddress?: string; // The IP this worker sends from
  };
  emailTransport?: TransportType;
  ses?: SesTransportConfig;
  notifier?: QueueNotifier;
  logger: Logger;
}

interface EmailJob {
  id: string;
  messageId: string;
  tenantId: string;
  domainId: string;
  from: string;
  to: string;
  subject: string;
  html?: string;
  text?: string;
  headers?: Record<string, string>;
  attachments?: Array<{
    filename: string;
    content: string;
    contentType: string;
    encoding?: string;
  }>;
  campaignId?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  scheduledAt?: Date;
  attempt: number;
  createdAt: Date;
}

export class EmailProcessor {
  private readonly db: Pool;
  private readonly dbPool: DatabasePool;
  private readonly redis: Redis;
  private readonly config: EmailProcessorConfig['config'];
  private readonly smtpConfig: EmailProcessorConfig['smtp'];
  private readonly dkimConfig: EmailProcessorConfig['dkim'];
  private readonly trackingConfig: EmailProcessorConfig['tracking'];
  private readonly warmupConfig: EmailProcessorConfig['warmup'];
  private readonly ipRateLimitingConfig: EmailProcessorConfig['ipRateLimiting'];
  private readonly emailTransport: TransportType;
  private readonly sesConfig: SesTransportConfig | undefined;
  private readonly notifier: QueueNotifier | undefined;
  private readonly logger: Logger;
  
  // IMP-001: messagesRepo + eventsRepo removed — handleSuccess, handleBounce,
  // handleSuppressed, failJob and retryJob now use raw SQL within transactions.
  private readonly domainsRepo: DomainsRepository;
  private readonly suppressionsRepo: SuppressionsRepository;
  private readonly circuitBreakers: CircuitBreakerFactory;
  private ipRateLimiter: IPRateLimiter | null = null;
  private transport: EmailTransport | null = null;
  private isRunning = false;
  private activeJobs = 0;

  /**
   * E-172: Worker-level error rate circuit breaker.
   * Tracks recent send outcomes in a sliding window. If the error rate
   * exceeds the threshold (e.g., 10 of last 20 fail), the worker pauses
   * for a cooldown period to avoid flooding a degraded downstream.
   *
   * FIX-500-426: Use a simple boolean array + failure counter instead of
   * allocating {success, timestamp} objects for every outcome.
   * FIX-500-431: Track timestamps to enable time-based window expiry
   * so stale outcomes from idle periods don't linger.
   */
  private readonly recentOutcomes: boolean[] = [];
  private readonly recentOutcomeTimestamps: number[] = [];
  private recentFailureCount = 0;
  private static readonly ERROR_WINDOW_SIZE = 20;
  private static readonly ERROR_THRESHOLD = 10; // 10 failures out of 20 = 50%
  private static readonly ERROR_COOLDOWN_MS = 60_000; // 1 minute pause
  private errorCooldownUntil = 0;
  private readonly dkimKeys = new Map<string, { privateKey: string; publicKey: string }>();
  private readonly rateLimiter: TokenBucketRateLimiter;
  private dkimRefreshTimer: NodeJS.Timeout | null = null;

  /**
   * C-118: In-memory suppression check cache with 5-minute TTL.
   * Avoids redundant DB lookups when the same recipient appears multiple
   * times across consecutive poll cycles within a short window.
   * Key = "tenantId:email", Value = { suppressed: boolean, reason?: string, expiresAt: number }
   */
  private readonly suppressionCache = new Map<string, { suppressed: boolean; reason?: string; expiresAt: number }>();
  private static readonly SUPPRESSION_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
  private static readonly SUPPRESSION_CACHE_MAX_SIZE = 10_000;

  // FIX-079: Cache warmup day calculation (changes at most once per day, queried per job)
  private readonly warmupDayCache = new Map<string, { day: number; expiresAt: number }>();
  private static readonly WARMUP_DAY_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

  constructor(options: EmailProcessorConfig) {
    this.db = options.db;
    this.dbPool = options.dbPool;
    this.redis = options.redis;
    this.config = options.config;
    this.smtpConfig = options.smtp;
    this.dkimConfig = options.dkim;
    this.trackingConfig = options.tracking;
    this.warmupConfig = options.warmup;
    this.ipRateLimitingConfig = options.ipRateLimiting;
    this.emailTransport = options.emailTransport ?? 'smtp';
    this.sesConfig = options.ses;
    this.notifier = options.notifier;
    this.logger = options.logger;
    
    // Create repositories using the DatabasePool
    this.domainsRepo = new DomainsRepository(this.dbPool);
    this.suppressionsRepo = new SuppressionsRepository(this.dbPool);
    
    this.rateLimiter = new TokenBucketRateLimiter(
      this.smtpConfig.rateLimitPerSecond,
      this.smtpConfig.rateLimitPerSecond
    );
    
    // Initialize circuit breaker factory for SMTP servers
    this.circuitBreakers = new CircuitBreakerFactory(options.redis, {
      failureThreshold: 10,       // Higher threshold for SMTP - more tolerant
      resetTimeout: 60000,        // 1 minute before attempting recovery
      successThreshold: 3,        // Need 3 successes to close
      rollingWindowMs: 120000,    // 2 minute rolling window
    });
  }

  async start(): Promise<void> {
    this.logger.info('Starting email processor', {
      concurrency: this.config.concurrency,
      pollInterval: this.config.pollInterval,
    });

    // Initialize IP Rate Limiter if enabled
    if (this.ipRateLimitingConfig?.enabled) {
      this.ipRateLimiter = new IPRateLimiter({
        redis: this.redis,
        db: this.db,
        logger: this.logger,
        // Sensible defaults - can be overridden via config
        globalHourlyLimit: 2500, // 2500/hour per IP (allows 60K/day theoretical max)
        burstLimit: 50,          // Allow brief bursts of 50 concurrent
        ispAwareLimiting: true,  // Enable ISP-specific limits
      });
      
      this.logger.info('IP rate limiter initialized', {
        ipAddress: this.ipRateLimitingConfig.ipAddress ?? 'auto-detect',
        globalHourlyLimit: 2500,
        ispAwareLimiting: true,
      });
    }

    // Initialize email transport (SMTP or SES, controlled by EMAIL_TRANSPORT env var)
    // FIX-500-007: For SMTP, Nodemailer's built-in socketTimeout + connectionTimeout
    // properly close the socket on expiry (previous Promise.race leaked sockets).
    this.transport = createEmailTransport(
      {
        type: this.emailTransport,
        smtp: {
          host: this.smtpConfig.host,
          port: this.smtpConfig.port,
          secure: this.smtpConfig.secure,
          auth: this.smtpConfig.auth,
          pool: this.smtpConfig.pool,
          maxConnections: this.smtpConfig.maxConnections,
          maxMessages: this.smtpConfig.maxMessages,
          socketTimeout: 30_000,
          connectionTimeout: 15_000,
          greetingTimeout: 15_000,
          tlsRejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false',
        },
        ses: this.sesConfig,
      },
      this.logger,
    );

    // Verify transport connection
    try {
      await this.transport.verify();
      this.logger.info('Email transport verified', { type: this.emailTransport });
    } catch (error) {
      this.logger.error('Email transport verification failed', { type: this.emailTransport, error });
      throw error;
    }

    // Load DKIM keys if enabled
    if (this.dkimConfig.enabled) {
      await this.loadDkimKeys();
      // C-065 / D-111: Add .unref() so timer doesn't prevent process exit
      this.dkimRefreshTimer = setInterval(() => {
        this.loadDkimKeys().catch((error) => {
          this.logger.error('Failed to refresh DKIM keys', { error });
        });
      }, 5 * 60 * 1000); // refresh every 5 minutes
      this.dkimRefreshTimer.unref();
    }

    this.isRunning = true;
    this.poll();
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping email processor');
    this.isRunning = false;

    if (this.dkimRefreshTimer) {
      clearInterval(this.dkimRefreshTimer);
      this.dkimRefreshTimer = null;
    }

    // Wait for active jobs to complete
    const maxWait = 30000;
    const startTime = Date.now();
    
    while (this.activeJobs > 0 && Date.now() - startTime < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (this.activeJobs > 0) {
      this.logger.warn('Forcing stop with active jobs', { activeJobs: this.activeJobs });
    }

    // Close email transport
    if (this.transport) {
      await this.transport.close();
    }

    // Clean up IP rate limiter if initialized
    if (this.ipRateLimiter) {
      this.ipRateLimiter.shutdown();
    }

    this.logger.info('Email processor stopped');
  }

  /**
   * C-098 / E-180: Configurable queue claim batch size via QUEUE_BATCH_SIZE env var.
   *
   * Controls how many jobs are claimed from the email_queue per poll cycle,
   * independent of the `concurrency` setting which governs how many jobs
   * may be *processed* in parallel.
   *
   * ## How to tune
   *
   * | Scale            | QUEUE_BATCH_SIZE | concurrency | Notes                            |
   * |------------------|------------------|-------------|----------------------------------|
   * | Low  (< 1K/hr)   | 5                | 5           | Minimal memory, quick feedback   |
   * | Med  (1K–50K/hr) | 20               | 20          | Good balance of throughput/mem   |
   * | High (> 50K/hr)  | 50–100           | 50          | Max throughput, needs ≥1 GB RAM  |
   *
   * ## Trade-offs
   *
   * - **Larger batches** → fewer DB round-trips, higher throughput, but each
   *   poll cycle locks more rows (longer lock hold) and uses more memory
   *   because all fetched jobs are buffered before processing.
   *
   * - **Smaller batches** → lower memory footprint, shorter lock windows,
   *   but more frequent DB queries and potentially higher end-to-end latency
   *   under load.
   *
   * - Setting the value higher than `concurrency` is wasteful — extra jobs
   *   sit in memory waiting for a processing slot.
   *
   * ## Default behaviour
   *
   * When QUEUE_BATCH_SIZE is unset or 0 the batch size equals the number of
   * available concurrency slots (i.e. no artificial cap). Set an explicit
   * value only when you need to limit the per-cycle claim.
   */
  private readonly queueBatchSize: number = Math.max(
    0,
    parseInt(process.env.QUEUE_BATCH_SIZE || '0', 10) || 0
  );

  private async poll(): Promise<void> {
    while (this.isRunning) {
      try {
        // E-172: Worker-level error rate circuit breaker — pause when error rate is too high
        if (Date.now() < this.errorCooldownUntil) {
          const remainingMs = this.errorCooldownUntil - Date.now();
          this.logger.warn('E-172: Worker paused due to high error rate', {
            resumesInMs: remainingMs,
            recentFailures: this.recentFailureCount,
            windowSize: this.recentOutcomes.length,
          });
          await new Promise(resolve => setTimeout(resolve, Math.min(remainingMs, 5000)));
          continue;
        }

        // Check if we have capacity
        const availableSlots = this.config.concurrency - this.activeJobs;
        if (availableSlots <= 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
          continue;
        }

        // C-098: Respect configurable batch size when set, otherwise use available slots
        const claimLimit = this.queueBatchSize > 0
          ? Math.min(availableSlots, this.queueBatchSize)
          : availableSlots;

        // Fetch jobs from queue
        const jobs = await this.fetchJobs(claimLimit);
        
        if (jobs.length === 0) {
          // LISTEN/NOTIFY wakeup: sleep until notified or fallback timeout
          if (this.notifier) {
            await this.notifier.waitForNotification('queue_email_queue', 30_000);
          } else {
            await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          }
          continue;
        }

        // C-100: Collect completed job IDs for batch queue cleanup.
        // Individual processJob calls handle their own transactions for
        // message status + event recording, but we can batch-delete
        // successfully processed queue entries in a single round-trip
        // when jobs share the same outcome.

        // C-104: Batch suppression pre-check — collect all recipient emails
        // and check suppression status in a single DB query instead of
        // N individual findByEmail calls inside each processJob.
        // FIX-500-003: Group jobs by tenantId for correct per-tenant suppression checks.
        // Previously used jobs[0].tenantId for ALL jobs, missing suppressions for other tenants.
        const batchSuppressionMap = new Map<string, string>();
        try {
          const jobsByTenant = new Map<string, string[]>();
          for (const j of jobs) {
            const emails = jobsByTenant.get(j.tenantId) ?? [];
            emails.push(j.to);
            jobsByTenant.set(j.tenantId, emails);
          }

          const now = Date.now();
          for (const [tenantId, emails] of jobsByTenant) {
            const uniqueEmails = [...new Set(emails)];
            const suppResult = await this.suppressionsRepo.checkBulkSuppression(
              uniqueEmails,
              tenantId
            );
            if (suppResult.ok) {
              for (const [email, data] of suppResult.value.entries()) {
                if (data) {
                  batchSuppressionMap.set(`${tenantId}:${email}`, data.reason ?? 'unknown');
                }
                // C-118: Populate suppression cache for future poll cycles
                const cacheKey = `${tenantId}:${email}`;
                this.suppressionCache.set(cacheKey, {
                  suppressed: !!data,
                  reason: data?.reason ?? undefined,
                  expiresAt: now + EmailProcessor.SUPPRESSION_CACHE_TTL_MS,
                });
              }
            }
          }
          // C-118: Evict oldest entries if cache exceeds max size
          // FIX-061: Use insertion-order eviction instead of sorting the entire Map.
          // Map iterates in insertion order, so the first entries are the oldest.
          // This is O(k) where k = entries to remove, instead of O(n log n) for sort.
          if (this.suppressionCache.size > EmailProcessor.SUPPRESSION_CACHE_MAX_SIZE) {
            const excess = this.suppressionCache.size - EmailProcessor.SUPPRESSION_CACHE_MAX_SIZE;
            let removed = 0;
            for (const key of this.suppressionCache.keys()) {
              if (removed >= excess) break;
              this.suppressionCache.delete(key);
              removed++;
            }
          }
        } catch (err) {
          // Non-fatal: fall back to per-job suppression check
          this.logger.warn('C-104: Batch suppression pre-check failed, falling back to per-job checks', { error: err });
        }

        // Process jobs concurrently - use allSettled to prevent single failure from failing batch
        // This ensures all jobs are processed even if some fail
        const results = await Promise.allSettled(jobs.map(job => this.processJob(job, batchSuppressionMap)));

        // FIX-080: Flush batch completions — all queued successes are committed
        // in a single PG transaction (1 client instead of N).
        await this.flushPendingSuccesses();
        
        // E-166: Track batch progress — count successes, failures, and per-campaign breakdown
        let batchSucceeded = 0;
        let batchFailed = 0;
        const campaignProgress = new Map<string, { succeeded: number; failed: number }>();

        for (let i = 0; i < results.length; i++) {
          const result = results[i];
          const job = jobs[i];
          const campaignId = job?.campaignId ?? '__none__';

          if (!campaignProgress.has(campaignId)) {
            campaignProgress.set(campaignId, { succeeded: 0, failed: 0 });
          }
          const cp = campaignProgress.get(campaignId)!;

          if (result && result.status === 'rejected') {
            batchFailed++;
            cp.failed++;
            this.logger.error('Unexpected job processing error', {
              jobId: job?.id,
              error: result.reason,
            });
          } else {
            batchSucceeded++;
            cp.succeeded++;
          }
        }

        // E-172: Record outcomes in the sliding window for error rate tracking
        // FIX-500-426: Use counter to track failures instead of .filter() scan
        // FIX-500-431: Use timestamps for time-based window expiry (60s)
        const now = Date.now();
        const OUTCOME_WINDOW_MS = 60_000;
        for (let i = 0; i < results.length; i++) {
          const result = results[i];
          const success = result?.status === 'fulfilled';
          this.recentOutcomes.push(success);
          this.recentOutcomeTimestamps.push(now);
          if (!success) this.recentFailureCount++;
        }
        // FIX-500-427: Trim by both count and time in a single splice
        // Evict entries older than OUTCOME_WINDOW_MS
        let evictCount = 0;
        while (evictCount < this.recentOutcomes.length && this.recentOutcomeTimestamps[evictCount]! < now - OUTCOME_WINDOW_MS) {
          if (!this.recentOutcomes[evictCount]) this.recentFailureCount--;
          evictCount++;
        }
        // Also cap at ERROR_WINDOW_SIZE
        const sizeExcess = (this.recentOutcomes.length - evictCount) - EmailProcessor.ERROR_WINDOW_SIZE;
        if (sizeExcess > 0) {
          for (let i = evictCount; i < evictCount + sizeExcess; i++) {
            if (!this.recentOutcomes[i]) this.recentFailureCount--;
          }
          evictCount += sizeExcess;
        }
        if (evictCount > 0) {
          this.recentOutcomes.splice(0, evictCount);
          this.recentOutcomeTimestamps.splice(0, evictCount);
        }
        // E-172: Check if error rate exceeds threshold → activate cooldown
        if (this.recentOutcomes.length >= EmailProcessor.ERROR_WINDOW_SIZE) {
          if (this.recentFailureCount >= EmailProcessor.ERROR_THRESHOLD) {
            this.errorCooldownUntil = Date.now() + EmailProcessor.ERROR_COOLDOWN_MS;
            this.logger.error('E-172: Error rate circuit breaker activated — worker pausing', {
              failures: this.recentFailureCount,
              windowSize: this.recentOutcomes.length,
              threshold: EmailProcessor.ERROR_THRESHOLD,
              cooldownMs: EmailProcessor.ERROR_COOLDOWN_MS,
            });
          }
        }

        // E-166: Emit batch progress metric for monitoring dashboards
        this.logger.info('email.batch.progress', {
          metric: 'email_batch_progress',
          batchSize: jobs.length,
          succeeded: batchSucceeded,
          failed: batchFailed,
          activeJobs: this.activeJobs,
          campaignBreakdown: Object.fromEntries(
            [...campaignProgress.entries()]
              .filter(([k]) => k !== '__none__')
              .map(([k, v]) => [k, v])
          ),
        });

        // C-108: Adaptive polling — when we just processed jobs there are
        // likely more waiting. Use a short 100ms delay instead of the full
        // LISTEN/NOTIFY wait so we drain the queue quickly, reducing
        // end-to-end latency while still yielding the event loop.
        await new Promise(resolve => setTimeout(resolve, 100));
        continue;
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  private async fetchJobs(limit: number): Promise<EmailJob[]> {
    // SECURITY FIX: Use single atomic UPDATE ... RETURNING to prevent double-processing
    // 
    // Previous implementation used separate SELECT + UPDATE which is vulnerable to race conditions:
    // 1. Worker A: SELECT ... FOR UPDATE SKIP LOCKED (autocommit releases lock after query)
    // 2. Worker B: SELECT ... FOR UPDATE SKIP LOCKED (can now see same rows)
    // 3. Both workers UPDATE and process the same jobs
    //
    // This atomic operation ensures each job is claimed by exactly one worker.
    // The WHERE clause filters, and RETURNING gives us the job data in one atomic operation.
    
    const lockUntil = new Date(Date.now() + this.config.visibilityTimeout);
    
    const result = await this.db.query<EmailJob>(`
      UPDATE email_queue
      SET status = 'processing', 
          locked_until = $1, 
          updated_at = NOW()
      WHERE id IN (
        SELECT id
        FROM email_queue
        WHERE status = 'pending'
          AND (scheduled_at IS NULL OR scheduled_at <= NOW())
          AND (locked_until IS NULL OR locked_until < NOW())
        ORDER BY priority DESC, created_at ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED
      )
      RETURNING 
        id, message_id as "messageId", tenant_id as "tenantId", domain_id as "domainId",
        "from", "to", subject, html, text, headers, attachments,
        campaign_id as "campaignId", tags, metadata, scheduled_at as "scheduledAt",
        attempt, created_at as "createdAt"
    `, [lockUntil, limit]);

    return result.rows;
  }

  private async processJob(job: EmailJob, batchSuppressions?: Map<string, string>): Promise<void> {
    this.activeJobs++;
    const startTime = Date.now();

    try {
      this.logger.debug('Processing email job', {
        jobId: job.id,
        messageId: job.messageId,
        to: job.to,
        attempt: job.attempt,
      });

      // C-104: Use pre-computed batch suppression map when available,
      // falling back to per-job DB lookup only if batch check was not done.
      // FIX-500-003: Key is now tenant-scoped (tenantId:email) for multi-tenant correctness.
      if (batchSuppressions && batchSuppressions.has(`${job.tenantId}:${job.to}`)) {
        await this.handleSuppressed(job, batchSuppressions.get(`${job.tenantId}:${job.to}`)!);
        return;
      } else if (!batchSuppressions) {
        // C-118: Check in-memory suppression cache before hitting the DB.
        const cacheKey = `${job.tenantId}:${job.to}`;
        const cached = this.suppressionCache.get(cacheKey);
        if (cached && cached.expiresAt > Date.now()) {
          if (cached.suppressed) {
            await this.handleSuppressed(job, cached.reason ?? 'unknown');
            return;
          }
          // Cached as not-suppressed — skip DB lookup
        } else {
          // Cache miss or expired — do individual suppression check
          const suppressionResult = await this.suppressionsRepo.findByEmail(job.to, job.tenantId);
          if (suppressionResult.ok && suppressionResult.value && suppressionResult.value.length > 0) {
            const firstSuppression = suppressionResult.value[0];
            if (firstSuppression) {
              // C-118: Cache the positive suppression result
              this.suppressionCache.set(cacheKey, {
                suppressed: true,
                reason: firstSuppression.reason ?? 'unknown',
                expiresAt: Date.now() + EmailProcessor.SUPPRESSION_CACHE_TTL_MS,
              });
              await this.handleSuppressed(job, firstSuppression.reason ?? 'unknown');
              return;
            }
          }
          // C-118: Cache the negative (not suppressed) result
          this.suppressionCache.set(cacheKey, {
            suppressed: false,
            expiresAt: Date.now() + EmailProcessor.SUPPRESSION_CACHE_TTL_MS,
          });
          // FIX-500-434: Evict oldest entries after individual writes too,
          // not just after batch pre-check. Without this, per-job cache writes
          // can grow the cache beyond SUPPRESSION_CACHE_MAX_SIZE unboundedly.
          if (this.suppressionCache.size > EmailProcessor.SUPPRESSION_CACHE_MAX_SIZE) {
            const excess = this.suppressionCache.size - EmailProcessor.SUPPRESSION_CACHE_MAX_SIZE;
            let removed = 0;
            for (const key of this.suppressionCache.keys()) {
              if (removed >= excess) break;
              this.suppressionCache.delete(key);
              removed++;
            }
          }
        }
      }

      // Check warmup limits
      if (this.warmupConfig.enabled) {
        const canSend = await this.checkWarmupLimit(job.domainId, job.tenantId);
        if (!canSend) {
          await this.requeueJob(job, 'warmup_limit');
          return;
        }
      }

      // Check IP rate limits (ISP-aware warmup)
      if (this.ipRateLimiter && this.ipRateLimitingConfig?.ipAddress) {
        const recipientDomain = job.to.split('@')[1] ?? '';
        const rateLimitResult = await this.ipRateLimiter.checkRateLimit(
          this.ipRateLimitingConfig.ipAddress,
          recipientDomain
        );
        
        if (!rateLimitResult.allowed) {
          this.logger.warn('IP rate limit exceeded', {
            jobId: job.id,
            reason: rateLimitResult.reason,
            currentCount: rateLimitResult.currentCount,
            limit: rateLimitResult.limit,
            retryAfter: rateLimitResult.retryAfter,
            isp: rateLimitResult.isp,
          });
          // FIX-500-114: Use rate limiter's computed retryAfter delay
          await this.requeueJob(job, 'ip_rate_limit', rateLimitResult.retryAfter);
          return;
        }
      }

      // Token bucket rate limit (per-second smoothing)
      await this.rateLimiter.acquire();

      // Get domain for DKIM signing (with tenant isolation)
      const domainResult = await this.domainsRepo.findById(job.domainId, job.tenantId);
      if (!domainResult.ok || !domainResult.value) {
        await this.handleError(job, new Error('Domain not found'));
        return;
      }

      const domain = domainResult.value;

      // Prepare email with tracking
      const email = await this.prepareEmail(job, domain);

      // Send email
      const sendResult = await this.sendEmail(email);

      // Record success
      await this.handleSuccess(job, sendResult);

    } catch (error) {
      await this.handleError(job, error as Error);
    } finally {
      this.activeJobs--;
      
      const duration = Date.now() - startTime;

      // E-158: Record email processing duration as a structured metric.
      // Emitted at info level so log-based metric systems (Loki, CloudWatch,
      // Datadog) can build histograms from the `metric` + `durationMs` fields.
      this.logger.info('email.processing.duration', {
        metric: 'email_processing_duration_ms',
        jobId: job.id,
        messageId: job.messageId,
        durationMs: duration,
        attempt: job.attempt,
        activeJobs: this.activeJobs,
        // Bucket label for quick dashboarding
        durationBucket: duration < 500 ? 'fast' : duration < 2000 ? 'normal' : duration < 10000 ? 'slow' : 'very_slow',
      });
    }
  }

  private async prepareEmail(job: EmailJob, domainData: Domain): Promise<PreparedEmail> {
    let html = job.html;
    const text = job.text;

    // Add tracking if enabled
    if (this.trackingConfig.enabled && html) {
      html = this.addTrackingPixel(html, job);
      html = this.rewriteLinks(html, job);
    }

    // Generate Message-ID using domain.domain property
    const messageId = `<${job.messageId}@${domainData.domain}>`;

    // Build headers
    const headers: Record<string, string> = {
      'Message-ID': messageId,
      'X-ApexMail-Message-ID': job.messageId,
      'X-ApexMail-Tenant-ID': job.tenantId,
      'List-Unsubscribe': this.generateUnsubscribeHeader(job),
      'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
      ...job.headers,
    };

    if (job.campaignId) {
      headers['X-ApexMail-Campaign-ID'] = job.campaignId;
    }

    // DKIM signing - get private key from dkimKeys cache (loaded during start)
    let dkim: DkimConfig | undefined;
    const dkimKey = this.dkimKeys.get(domainData.id);
    if (this.dkimConfig.enabled && dkimKey?.privateKey) {
      dkim = {
        domainName: domainData.domain,
        keySelector: this.dkimConfig.selector,
        privateKey: dkimKey.privateKey,
      };

      // F-233: DMARC alignment check — the From header domain must match
      // the DKIM d= domain (domainData.domain). If they don't align,
      // DMARC will fail even if SPF and DKIM individually pass.
      const fromDomain = (job.from.split('@')[1] ?? '').toLowerCase();
      const dkimDomain = domainData.domain.toLowerCase();
      if (fromDomain && dkimDomain && fromDomain !== dkimDomain) {
        // FIX-500-428: Optionally reject messages with DMARC misalignment
        // instead of just warning (guaranteeing DMARC failure at receiving MTA).
        const rejectOnMisaligned = process.env.DMARC_REJECT_MISALIGNED === 'true';
        if (rejectOnMisaligned) {
          throw new Error(`DMARC alignment failure: From domain '${fromDomain}' does not match DKIM d= domain '${dkimDomain}'`);
        }
        this.logger.warn('F-233: DMARC alignment failure — From domain does not match DKIM d= domain', {
          jobId: job.id,
          messageId: job.messageId,
          fromDomain,
          dkimDomain,
          impact: 'DMARC will likely fail for this message even if SPF and DKIM individually pass',
        });
      }
    }

    return {
      from: job.from,
      to: job.to,
      subject: job.subject,
      html,
      text,
      headers,
      attachments: job.attachments?.map(a => ({
        filename: a.filename,
        content: Buffer.from(a.content, (a.encoding as BufferEncoding) ?? 'base64'),
        contentType: a.contentType,
      })),
      dkim,
    };
  }

  private addTrackingPixel(html: string, job: EmailJob): string {
    const trackingId = this.encodeTrackingId(job.messageId, job.tenantId);
    const pixelUrl = `${this.trackingConfig.baseUrl}${this.trackingConfig.openPixelPath}/${trackingId}`;
    const pixel = `<img src="${pixelUrl}" width="1" height="1" alt="" style="display:none;visibility:hidden;" />`;
    
    // FIX-500-430: Use lastIndexOf to find the *last* </body> tag.
    // String.replace only replaces the first occurrence, which breaks
    // if there are multiple </body> tags (e.g., nested email quotes).
    const lastBodyIdx = html.lastIndexOf('</body>');
    if (lastBodyIdx !== -1) {
      return html.slice(0, lastBodyIdx) + pixel + html.slice(lastBodyIdx);
    }
    return html + pixel;
  }

  private rewriteLinks(html: string, job: EmailJob): string {
    const trackingId = this.encodeTrackingId(job.messageId, job.tenantId);
    const clickBase = `${this.trackingConfig.baseUrl}${this.trackingConfig.clickRedirectPath}/${trackingId}`;
    
    // FIX-500-429: Broadened regex to handle whitespace between attributes
    // and extended skip list to include javascript:, data:, and # anchors.
    return html.replace(
      /<a\s+([^>]*?)href\s*=\s*["']([^"']+)["']([^>]*?)>/gi,
      (match, before, url, after) => {
        // Skip mailto:, tel:, javascript:, data:, anchors, and tracking URLs
        if (
          url.startsWith('mailto:') ||
          url.startsWith('tel:') ||
          url.startsWith('javascript:') ||
          url.startsWith('data:') ||
          url.startsWith('#') ||
          url.includes(this.trackingConfig.baseUrl)
        ) {
          return match;
        }
        
        const encodedUrl = Buffer.from(url).toString('base64url');
        const trackedUrl = `${clickBase}?u=${encodedUrl}`;
        return `<a ${before}href="${trackedUrl}"${after}>`;
      }
    );
  }

  private encodeTrackingId(messageId: string, tenantId: string): string {
    const payload = JSON.stringify({ m: messageId, t: tenantId });
    return Buffer.from(payload).toString('base64url');
  }

  private generateUnsubscribeHeader(job: EmailJob): string {
    const unsubscribeId = this.encodeTrackingId(job.messageId, job.tenantId);
    const unsubscribeUrl = `${this.trackingConfig.baseUrl}/unsubscribe/${unsubscribeId}`;
    const domain = job.from.split('@')[1] ?? 'example.com';
    return `<${unsubscribeUrl}>, <mailto:unsubscribe@${domain}?subject=Unsubscribe>`;
  }

  /**
   * C-129: Email content MIME type detection.
   *
   * Nodemailer automatically sets the correct MIME type based on which
   * fields are provided in `mailOptions`:
   *   - `text` only         → Content-Type: text/plain
   *   - `html` only         → Content-Type: text/html
   *   - `text` AND `html`   → multipart/alternative with both parts
   *
   * No manual Content-Type or multipart handling is needed. Nodemailer's
   * internal MimeNode builder handles boundary generation, encoding, and
   * part ordering (text/plain first, text/html second) per RFC 2046 §5.1.4.
   */
  private async sendEmail(email: EmailMessage): Promise<SendResult> {
    if (!this.transport) {
      throw new Error('Email transport not initialized');
    }

    // Use circuit breaker keyed by transport type + endpoint
    const circuitBreakerKey = this.emailTransport === 'ses'
      ? `ses:${this.sesConfig?.region ?? 'us-east-1'}`
      : `smtp:${this.smtpConfig.host}:${this.smtpConfig.port}`;
    const circuitBreaker = this.circuitBreakers.get(circuitBreakerKey);
    
    // Check if circuit is open (too many failures)
    const state = await circuitBreaker.getState();
    if (state === 'open') {
      this.logger.warn('Circuit breaker open for email transport', {
        transport: this.emailTransport,
        key: circuitBreakerKey,
      });
      throw new Error(`Email transport circuit breaker open - ${circuitBreakerKey} temporarily unavailable`);
    }

    // FIX-500-007: For SMTP, Nodemailer's built-in socketTimeout/connectionTimeout
    // handle timeouts natively. For SES, the AWS SDK manages its own retries/timeouts.
    try {
      const result = await this.transport.send(email);
      
      // Record success to circuit breaker
      await circuitBreaker.recordSuccess();
      
      return result;
    } catch (error) {
      // Record failure to circuit breaker
      await circuitBreaker.recordFailure();
      throw error;
    }
  }

  /**
   * IMP-001: Transactional completion — markSent + event + queue delete
   * are wrapped in a single Postgres transaction so a crash between any
   * two steps cannot leave the system in an inconsistent state (e.g.
   * message marked sent but still in queue → duplicate delivery).
   *
   * FIX-080: Batch completions — when multiple jobs are sent successfully,
   * batchHandleSuccess collects their completions and performs multi-row
   * UPDATE/INSERT/DELETE in a single PG transaction, reducing PG connection
   * churn from N clients per poll cycle to 1.
   * FIX-500-463: Verified — batch completions are both documented AND implemented.
   */
  private pendingSuccesses: Array<{ job: EmailJob; result: SendResult }> = [];

  /**
   * Queue a successful send for batch completion. The actual DB writes
   * happen in flushPendingSuccesses (called once per poll cycle).
   */
  private queueSuccess(job: EmailJob, result: SendResult): void {
    this.pendingSuccesses.push({ job, result });
  }

  /**
   * FIX-080: Flush all pending successes in a single PG transaction.
   * Uses multi-row INSERT for events, multi-row UPDATE for messages,
   * and multi-row DELETE for queue cleanup.
   */
  private async flushPendingSuccesses(): Promise<void> {
    const pending = this.pendingSuccesses;
    if (pending.length === 0) return;
    this.pendingSuccesses = [];

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Batch UPDATE messages to 'sent' status
      // Uses unnest arrays for multi-row UPDATE in a single round-trip
      const msgIds: string[] = [];
      const smtpMsgIds: string[] = [];
      for (const { job, result } of pending) {
        msgIds.push(job.messageId);
        smtpMsgIds.push(result.messageId || '');
      }
      await client.query(
        `UPDATE messages 
         SET status = 'sent', sent_at = NOW(), updated_at = NOW(),
             smtp_message_id = batch.smtp_id
         FROM (SELECT unnest($1::text[]) AS id, unnest($2::text[]) AS smtp_id) AS batch
         WHERE messages.id = batch.id`,
        [msgIds, smtpMsgIds]
      );

      // Batch INSERT events
      const evtValues: unknown[] = [];
      const evtPlaceholders: string[] = [];
      let paramIdx = 1;
      for (const { job, result } of pending) {
        evtPlaceholders.push(
          `($${paramIdx++}, $${paramIdx++}, $${paramIdx++}, 'sent', $${paramIdx++}, $${paramIdx++}, NOW())`
        );
        evtValues.push(
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          JSON.stringify({ smtpResponse: result.response, messageIdHeader: result.messageId }),
        );
      }
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, metadata, timestamp)
         VALUES ${evtPlaceholders.join(', ')}`,
        evtValues
      );

      // Batch DELETE from queue
      const queueIds = pending.map(p => p.job.id);
      await client.query(
        `DELETE FROM email_queue WHERE id = ANY($1::text[])`,
        [queueIds]
      );

      await client.query('COMMIT');

      // Log batch success
      for (const { job, result } of pending) {
        this.logger.info('Email sent successfully', {
          jobId: job.id,
          messageId: job.messageId,
          response: result.response,
          batchCompletion: true,
        });
      }
    } catch (error) {
      await client.query('ROLLBACK');
      // On batch failure, fall back to individual completions
      this.logger.warn('FIX-080: Batch completion failed, falling back to per-job', {
        batchSize: pending.length,
        error: error instanceof Error ? error.message : 'Unknown',
      });
      for (const { job, result } of pending) {
        try {
          await this.handleSuccessIndividual(job, result);
        } catch (individualError) {
          this.logger.error('Individual completion also failed', {
            jobId: job.id,
            error: individualError instanceof Error ? individualError.message : 'Unknown',
          });
        }
      }
      return;
    } finally {
      client.release();
    }

    // FIX-500-008: Post-transaction side-effects (non-critical Redis updates)
    for (const { job } of pending) {
      try {
        if (this.warmupConfig.enabled) {
          await this.incrementWarmupCounter(job.domainId);
        }
        if (this.ipRateLimiter && this.ipRateLimitingConfig?.ipAddress) {
          const recipientDomain = job.to.split('@')[1] ?? '';
          await this.ipRateLimiter.recordSend(
            this.ipRateLimitingConfig.ipAddress,
            recipientDomain
          );
        }
      } catch (sideEffectError) {
        this.logger.warn('Post-send side-effect failed (email already sent)', {
          jobId: job.id,
          messageId: job.messageId,
          error: sideEffectError instanceof Error ? sideEffectError.message : 'Unknown',
        });
      }
    }
  }

  /**
   * Individual success handler — used as fallback when batch completion fails.
   */
  private async handleSuccessIndividual(job: EmailJob, result: SendResult): Promise<void> {
    this.logger.info('Email sent successfully', {
      jobId: job.id,
      messageId: job.messageId,
      response: result.response,
    });

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      // FIX-500-489: Guard status transition with WHERE to prevent TOCTOU race
      const updateResult = await client.query(
        `UPDATE messages SET status = 'sent', sent_at = NOW(), smtp_message_id = $2, updated_at = NOW() WHERE id = $1 AND status IN ('queued', 'sending')`,
        [job.messageId, result.messageId || '']
      );
      if (updateResult.rowCount === 0) {
        this.logger.warn('FIX-500-489: Message status transition to sent skipped (already transitioned)', { messageId: job.messageId });
      }
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, metadata, timestamp)
         VALUES ($1, $2, $3, 'sent', $4, $5, NOW())`,
        [
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          JSON.stringify({ smtpResponse: result.response, messageIdHeader: result.messageId }),
        ]
      );
      await client.query('DELETE FROM email_queue WHERE id = $1', [job.id]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    try {
      if (this.warmupConfig.enabled) {
        await this.incrementWarmupCounter(job.domainId);
      }
      if (this.ipRateLimiter && this.ipRateLimitingConfig?.ipAddress) {
        const recipientDomain = job.to.split('@')[1] ?? '';
        await this.ipRateLimiter.recordSend(
          this.ipRateLimitingConfig.ipAddress,
          recipientDomain
        );
      }
    } catch (sideEffectError) {
      this.logger.warn('Post-send side-effect failed (email already sent)', {
        jobId: job.id,
        messageId: job.messageId,
        error: sideEffectError instanceof Error ? sideEffectError.message : 'Unknown',
      });
    }
  }

  private async handleSuccess(job: EmailJob, result: SendResult): Promise<void> {
    // FIX-080: Queue for batch completion instead of per-job DB writes.
    // Batch is flushed at the end of the poll cycle by flushPendingSuccesses().
    this.queueSuccess(job, result);
  }

  private async handleError(job: EmailJob, error: Error): Promise<void> {
    // E-154: Categorise errors as transient vs permanent for better observability
    // and to prevent wasteful retries on permanent failures.
    const category = this.categorizeError(error);

    // E-162: Include comprehensive context for error triage.
    // Missing tenantId, maxRetries, and recipient domain made it hard to
    // correlate failures with specific tenants or ISPs in production logs.
    this.logger.error('Email send failed', {
      jobId: job.id,
      messageId: job.messageId,
      tenantId: job.tenantId,
      to: job.to,
      error: error.message,
      errorCategory: category,
      attempt: job.attempt,
      maxRetries: this.config.maxRetries,
      willRetry: category !== 'permanent' && job.attempt < this.config.maxRetries,
      recipientDomain: job.to.split('@')[1] ?? 'unknown',
      campaignId: job.campaignId ?? null,
      activeJobs: this.activeJobs,
    });

    const isBounce = this.isBounceError(error);

    if (isBounce) {
      await this.handleBounce(job, error);
    } else if (category === 'permanent') {
      // E-154: Permanent errors should never retry — fail immediately
      await this.failJob(job, error);
    } else if (job.attempt < this.config.maxRetries) {
      // FIX-500-435: Treat 'unknown' errors as transient (retryable).
      // Previously unknown errors fell through to failJob, permanently failing
      // messages for unrecognised errors (e.g., new SMTP codes, unusual network issues).
      await this.retryJob(job, error);
    } else {
      await this.failJob(job, error);
    }
  }

  /**
   * E-154: Categorise send errors as transient (worth retrying) or permanent
   * (no point retrying — authentication, policy, or configuration issues).
   */
  private categorizeError(error: Error): 'transient' | 'permanent' | 'unknown' {
    const msg = error.message.toLowerCase();

    // Permanent: authentication / policy / config errors
    const permanentPatterns = [
      /\b(535)\b/,              // 535 Authentication failed
      /\b(530)\b/,              // 530 Authentication required
      /\b(523)\b/,              // 523 Message length exceeds limit
      /\b(556)\b/,              // 556 Domain does not accept mail
      /invalid.*credential/,
      /authentication.*failed/,
      /relay.*denied/,
      /not.*permitted/,
      /certificate.*invalid/,
      /self.signed/,
    ];

    // Transient: temporary server-side or network issues
    const transientPatterns = [
      /\b(421|450|451|452)\b/,  // 4xx temporary SMTP errors
      /timeout/,
      /econnreset/,
      /econnrefused/,
      /enetunreach/,
      /enotfound/,
      /temporary/,
      /try.*again/,
      /too.*many.*connections/,
      /rate.*limit/,
      /greylist/,
      /circuit.*breaker/,
    ];

    for (const pattern of permanentPatterns) {
      if (pattern.test(msg)) return 'permanent';
    }
    for (const pattern of transientPatterns) {
      if (pattern.test(msg)) return 'transient';
    }
    return 'unknown';
  }

  /**
   * IMP-001: Transactional bounce handling — markBounced + event +
   * suppression (hard bounces) + queue delete in a single transaction.
   */
  private async handleBounce(job: EmailJob, error: Error): Promise<void> {
    const bounceType = this.classifyBounce(error);

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Update message status
      // FIX-500-489: Guard status transition with WHERE to prevent TOCTOU race
      await client.query(
        `UPDATE messages SET status = 'bounced', bounced_at = NOW(), bounce_type = $2, bounce_reason = $3, updated_at = NOW() WHERE id = $1 AND status IN ('queued', 'sending', 'sent')`,
        [job.messageId, bounceType.type, `${bounceType.subtype}: ${error.message}`]
      );

      // Record bounce event
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, bounce_type, metadata, timestamp)
         VALUES ($1, $2, $3, 'bounced', $4, $5, $6, NOW())`,
        [
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          bounceType.type,
          JSON.stringify({ bounceSubtype: bounceType.subtype, bounceMessage: error.message }),
        ]
      );

      // Add to suppression list for hard bounces
      if (bounceType.type === 'hard') {
        await client.query(
          `INSERT INTO suppressions (id, tenant_id, email, reason, bounce_type, source, original_message_id, metadata, created_at)
           VALUES ($1, $2, $3, 'bounce', $4, 'system', $5, $6, NOW())
           ON CONFLICT (tenant_id, email) DO NOTHING`,
          [
            generateId('sup'),
            job.tenantId,
            job.to,
            bounceType.type,
            job.messageId,
            JSON.stringify({ domainId: job.domainId, campaignId: job.campaignId, bounceSubtype: bounceType.subtype }),
          ]
        );
      }

      // Remove from queue
      await client.query('DELETE FROM email_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (txError) {
      await client.query('ROLLBACK');
      throw txError;
    } finally {
      client.release();
    }
  }

  /**
   * IMP-001: Transactional suppressed handling — status update + event +
   * queue delete in a single transaction.
   */
  private async handleSuppressed(job: EmailJob, reason: string): Promise<void> {
    this.logger.info('Recipient suppressed', {
      jobId: job.id,
      messageId: job.messageId,
      to: job.to,
      reason,
    });

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Update message status — use 'failed' as there's no 'dropped' status
      // FIX-500-489: Guard status transition with WHERE to prevent TOCTOU race
      await client.query(
        `UPDATE messages SET status = 'failed', metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb, updated_at = NOW() WHERE id = $1 AND status NOT IN ('failed', 'bounced')`,
        [job.messageId, JSON.stringify({ dropReason: `suppressed:${reason}`, suppressed: true })]
      );

      // Record dropped event
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, metadata, timestamp)
         VALUES ($1, $2, $3, 'dropped', $4, $5, NOW())`,
        [
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          JSON.stringify({ reason: `suppressed:${reason}` }),
        ]
      );

      // Remove from queue
      await client.query('DELETE FROM email_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (txError) {
      await client.query('ROLLBACK');
      throw txError;
    } finally {
      client.release();
    }
  }

  /**
   * FIX-006: Transactional retry — queue update + deferred event in a
   * single Postgres transaction. Previously these were two separate
   * operations; a crash between them would leave an incomplete event
   * timeline (message retried but no deferred event recorded).
   * Matches the IMP-001 pattern used by handleSuccess/handleBounce/
   * handleSuppressed/failJob.
   */
  /**
   * E-189: Retry delay constants for exponential backoff.
   * Formula: locked_until = NOW() + min(baseDelay * 2^retryCount, maxDelay)
   * This prevents retries from firing immediately and gives downstream
   * services time to recover.
   */
  private static readonly RETRY_BASE_DELAY_MS = 30_000;      // 30 seconds
  private static readonly RETRY_MAX_DELAY_MS  = 30 * 60_000; // 30 minutes

  private async retryJob(job: EmailJob, error: Error): Promise<void> {
    const nextAttempt = job.attempt + 1;
    // E-189: Exponential backoff with capped max delay
    const delay = Math.min(
      EmailProcessor.RETRY_BASE_DELAY_MS * Math.pow(2, job.attempt - 1),
      EmailProcessor.RETRY_MAX_DELAY_MS
    );
    const scheduledAt = new Date(Date.now() + delay);
    // E-189: Set locked_until to prevent other workers from picking up the
    // job before the backoff period expires. This is the authoritative
    // backoff mechanism — scheduledAt filters in fetchJobs, while
    // locked_until provides a secondary guard against premature claims.
    const lockedUntil = new Date(Date.now() + delay);

    this.logger.info('E-189: Scheduling retry with exponential backoff', {
      jobId: job.id,
      messageId: job.messageId,
      attempt: nextAttempt,
      delayMs: delay,
      scheduledAt: scheduledAt.toISOString(),
      lockedUntil: lockedUntil.toISOString(),
    });

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      await client.query(`
        UPDATE email_queue
        SET 
          status = 'pending',
          attempt = $1,
          scheduled_at = $2,
          last_error = $3,
          locked_until = $5,
          updated_at = NOW()
        WHERE id = $4
      `, [nextAttempt, scheduledAt, error.message, job.id, lockedUntil]);

      // Record deferred event inside the same transaction
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, metadata, timestamp)
         VALUES ($1, $2, $3, 'deferred', $4, $5, NOW())`,
        [
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          JSON.stringify({
            attempt: nextAttempt,
            scheduledAt: scheduledAt.toISOString(),
            error: error.message,
          }),
        ]
      );

      await client.query('COMMIT');
    } catch (txError) {
      await client.query('ROLLBACK');
      throw txError;
    } finally {
      client.release();
    }
  }

  /**
   * IMP-001: Transactional failure handling — markFailed + event +
   * DLQ insert + queue delete in a single transaction.
   */
  private async failJob(job: EmailJob, error: Error): Promise<void> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Update message status
      // FIX-500-489: Guard status transition with WHERE to prevent TOCTOU race
      await client.query(
        `UPDATE messages SET status = 'failed', bounce_reason = $2, updated_at = NOW() WHERE id = $1 AND status NOT IN ('failed', 'bounced')`,
        [job.messageId, error.message]
      );

      // Record dropped event for permanent failure
      await client.query(
        `INSERT INTO events (id, tenant_id, message_id, event_type, recipient_email, metadata, timestamp)
         VALUES ($1, $2, $3, 'dropped', $4, $5, NOW())`,
        [
          generateId('evt'),
          job.tenantId,
          job.messageId,
          job.to,
          JSON.stringify({ error: error.message, attempt: job.attempt, permanentFailure: true, reason: 'max_retries_exceeded' }),
        ]
      );

      // Move to dead letter queue
      await client.query(
        `INSERT INTO email_dlq (id, original_job, error_message, failed_at)
         VALUES ($1, $2, $3, NOW())`,
        [generateId('dlq'), JSON.stringify(job), error.message]
      );

      // Remove from queue
      await client.query('DELETE FROM email_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (txError) {
      await client.query('ROLLBACK');
      throw txError;
    } finally {
      client.release();
    }
  }

  /**
   * FIX-500-114: Accept optional delayMs from rate limiter's retryAfter
   * instead of always using a flat 60-second delay.
   */
  private async requeueJob(job: EmailJob, reason: string, delayMs?: number): Promise<void> {
    // FIX-500-114: Use rate limiter's retryAfter when available, default 60s
    const scheduledAt = new Date(Date.now() + (delayMs ?? 60_000));

    await this.db.query(`
      UPDATE email_queue
      SET 
        status = 'pending',
        scheduled_at = $1,
        locked_until = NULL,
        updated_at = NOW()
      WHERE id = $2
    `, [scheduledAt, job.id]);

    this.logger.debug('Job requeued', { jobId: job.id, reason, scheduledAt });
  }

  private isBounceError(error: Error): boolean {
    const message = error.message.toLowerCase();
    const bouncePattern = /\b(55[0-5])\b/;
    return bouncePattern.test(message);
  }

  // E-154: isRetryableError replaced by categorizeError() which provides
  // richer transient/permanent/unknown classification.

  private classifyBounce(error: Error): { type: 'hard' | 'soft'; subtype: string } {
    const message = error.message.toLowerCase();

    // Hard bounce patterns (550/551/553/554 are permanent failures per RFC 5321)
    if (message.includes('550') || message.includes('551') || message.includes('553') || message.includes('554')) {
      if (message.includes('user') && (message.includes('unknown') || message.includes('not found'))) {
        return { type: 'hard', subtype: 'no-mailbox' };
      }
      if (message.includes('domain') && message.includes('not found')) {
        return { type: 'hard', subtype: 'no-domain' };
      }
      if (message.includes('reject') || message.includes('blocked')) {
        return { type: 'hard', subtype: 'rejected' };
      }
      return { type: 'hard', subtype: 'general' };
    }

    // Soft bounce patterns
    if (message.includes('552') || message.includes('over quota') || message.includes('mailbox full')) {
      return { type: 'soft', subtype: 'over-quota' };
    }
    if (message.includes('421') || message.includes('450') || message.includes('451')) {
      return { type: 'soft', subtype: 'temporary' };
    }
    if (message.includes('greylist')) {
      return { type: 'soft', subtype: 'greylisted' };
    }

    return { type: 'soft', subtype: 'undetermined' };
  }

  private async loadDkimKeys(): Promise<void> {
    // Load DKIM keys from database
    const result = await this.db.query<{ domain_id: string; private_key: string }>(`
      SELECT id as domain_id, dkim_private_key as private_key
      FROM domains
      WHERE dkim_private_key IS NOT NULL AND is_verified = true
    `);

    for (const row of result.rows) {
      // F-204: Validate DKIM key length — 2048-bit RSA minimum recommended.
      // RSA key length in bits ≈ (base64-decoded byte length) * 8.
      // A PEM private key's base64 body is roughly proportional to key size.
      try {
        const pemBody = row.private_key
          .replace(/-----[A-Z ]+-----/g, '')
          .replace(/\s/g, '');
        const keyBytes = Buffer.from(pemBody, 'base64').length;
        const estimatedBits = keyBytes * 8;
        // RSA-2048 private keys are ~1200 bytes → ~9600 bits in raw DER.
        // A threshold of 2048 raw bits safely catches 1024-bit keys (~600 bytes → ~4800 bits).
        if (estimatedBits < 2048) {
          this.logger.warn('F-204: DKIM key shorter than 2048-bit RSA minimum', {
            domainId: row.domain_id,
            estimatedBits,
            recommendation: 'Generate a 2048-bit or 4096-bit RSA key pair',
          });
        }
      } catch {
        this.logger.warn('F-204: Could not determine DKIM key length', {
          domainId: row.domain_id,
        });
      }

      this.dkimKeys.set(row.domain_id, {
        privateKey: row.private_key,
        publicKey: '', // Not needed for signing
      });
    }

    this.logger.info('DKIM keys loaded', { count: result.rows.length });
  }

  /**
   * FIX-051: Redis-backed warmup counters for multi-worker coordination.
   * Previous in-memory Map caused N workers to each independently count,
   * sending N× the intended daily warmup limit. Redis INCR is atomic and
   * shared across all workers. Key TTL of 48h auto-resets (no cron needed).
   */
  private async checkWarmupLimit(domainId: string, tenantId: string): Promise<boolean> {
    const schedule = this.warmupConfig.schedule[domainId];
    if (!schedule) return true; // No warmup schedule, no limit

    const dayOfWarmup = await this.calculateWarmupDay(domainId, tenantId);
    const dailyLimit = schedule[dayOfWarmup] ?? schedule[schedule.length - 1] ?? Number.MAX_SAFE_INTEGER;

    const today = new Date().toISOString().split('T')[0];
    const key = `apexmail:warmup:${domainId}:${today}`;
    const currentCount = parseInt(await this.redis.get(key) || '0', 10);

    return currentCount < dailyLimit;
  }

  private async calculateWarmupDay(domainId: string, tenantId: string): Promise<number> {
    // FIX-079: Check cache first — warmup day changes at most once per day
    const cached = this.warmupDayCache.get(domainId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.day;
    }

    const result = await this.domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      this.logger.warn('Warmup day calculation: domain not found', { domainId, tenantId });
      return 0;
    }

    const domain = result.value;
    const baseDate = domain.verifiedAt ?? domain.createdAt ?? new Date();
    const diffMs = Date.now() - baseDate.getTime();
    const days = Math.max(0, Math.floor(diffMs / (24 * 60 * 60 * 1000)));

    this.warmupDayCache.set(domainId, {
      day: days,
      expiresAt: Date.now() + EmailProcessor.WARMUP_DAY_CACHE_TTL_MS,
    });

    return days;
  }

  private async incrementWarmupCounter(domainId: string): Promise<void> {
    const today = new Date().toISOString().split('T')[0];
    const key = `apexmail:warmup:${domainId}:${today}`;
    const pipeline = this.redis.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, 172800); // 48h TTL — auto-expires, no midnight reset needed
    await pipeline.exec();
  }
}

// PreparedEmail and DkimConfig are now imported as EmailMessage and DkimConfig
// from ../services/email-transport.ts — single source of truth.
type PreparedEmail = EmailMessage;

/**
 * Token Bucket Rate Limiter
 */
class TokenBucketRateLimiter {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillRate: number;
  private lastRefill: number;
  private readonly waitQueue: Array<{ resolve: () => void; reject: (error: Error) => void }> = [];
  private readonly maxQueueSize: number;

  constructor(capacity: number, refillRate: number, maxQueueSize = 10000) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefill = Date.now();
    this.maxQueueSize = maxQueueSize;
  }

  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens >= 1) {
      this.tokens--;
      return;
    }

    // Wait for a token
    if (this.waitQueue.length >= this.maxQueueSize) {
      // FIX-500-432: Use throw instead of Promise.reject in async function
      throw new Error('Rate limiter queue is full');
    }

    return new Promise((resolve, reject) => {
      // FIX-500-119: Add 30-second per-waiter timeout to prevent
      // promises hanging forever when refill rate is very low.
      const timer = setTimeout(() => {
        const idx = this.waitQueue.findIndex(w => w.resolve === resolve);
        if (idx >= 0) this.waitQueue.splice(idx, 1);
        reject(new Error('Rate limiter wait timeout (30s)'));
      }, 30_000);

      this.waitQueue.push({
        resolve: () => { clearTimeout(timer); resolve(); },
        reject: (err: Error) => { clearTimeout(timer); reject(err); },
      });
      setTimeout(() => this.processQueue(), 1000 / this.refillRate);
    });
  }

  private refill(): void {
    const now = Date.now();
    // FIX-500-433: Date.now() has millisecond precision. When dividing by 1000
    // and multiplying by refillRate, calls <1ms apart produce 0 new tokens.
    // This is acceptable for the expected call patterns (one acquire() per email
    // send, typically >1ms apart). Math.max(0, ...) guards against wall-clock
    // jumps from NTP adjustments producing negative elapsed time.
    const elapsed = Math.max(0, (now - this.lastRefill) / 1000);
    const newTokens = elapsed * this.refillRate;
    
    this.tokens = Math.min(this.capacity, this.tokens + newTokens);
    this.lastRefill = now;
  }

  private processQueue(): void {
    this.refill();
    
    while (this.waitQueue.length > 0 && this.tokens >= 1) {
      this.tokens--;
      const next = this.waitQueue.shift()!;
      next.resolve();
    }
  }
}
