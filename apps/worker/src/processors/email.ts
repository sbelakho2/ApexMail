/**
 * Email Processor - Handles email sending from queue
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { DomainsRepository, SuppressionsRepository, type Domain, type DatabasePool } from '@apexmail/db';
import { createTransport, type Transporter, type SentMessageInfo } from 'nodemailer';
import { CircuitBreakerFactory } from '../circuit-breaker.js';
import { IPRateLimiter } from '../services/ip-rate-limiter.js';
import type { QueueNotifier } from '../queue-notifier.js';

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
  private readonly notifier: QueueNotifier | undefined;
  private readonly logger: Logger;
  
  // IMP-001: messagesRepo + eventsRepo removed — handleSuccess, handleBounce,
  // handleSuppressed, failJob and retryJob now use raw SQL within transactions.
  private readonly domainsRepo: DomainsRepository;
  private readonly suppressionsRepo: SuppressionsRepository;
  private readonly circuitBreakers: CircuitBreakerFactory;
  private ipRateLimiter: IPRateLimiter | null = null;
  private transporter: Transporter | null = null;
  private isRunning = false;
  private activeJobs = 0;
  private readonly dkimKeys = new Map<string, { privateKey: string; publicKey: string }>();
  private readonly rateLimiter: TokenBucketRateLimiter;
  private dkimRefreshTimer: NodeJS.Timeout | null = null;

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

    // Initialize SMTP transporter
    this.transporter = createTransport({
      host: this.smtpConfig.host,
      port: this.smtpConfig.port,
      secure: this.smtpConfig.secure,
      auth: this.smtpConfig.auth,
      pool: this.smtpConfig.pool,
      maxConnections: this.smtpConfig.maxConnections,
      maxMessages: this.smtpConfig.maxMessages,
      tls: {
        rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== 'false',
      },
    } as Parameters<typeof createTransport>[0]);

    // Verify SMTP connection
    try {
      await this.transporter.verify();
      this.logger.info('SMTP connection verified');
    } catch (error) {
      this.logger.error('SMTP verification failed', { error });
      throw error;
    }

    // Load DKIM keys if enabled
    if (this.dkimConfig.enabled) {
      await this.loadDkimKeys();
      this.dkimRefreshTimer = setInterval(() => {
        this.loadDkimKeys().catch((error) => {
          this.logger.error('Failed to refresh DKIM keys', { error });
        });
      }, 5 * 60 * 1000); // refresh every 5 minutes
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

    // Close SMTP connection
    if (this.transporter) {
      this.transporter.close();
    }

    // Clean up IP rate limiter if initialized
    if (this.ipRateLimiter) {
      this.ipRateLimiter.shutdown();
    }

    this.logger.info('Email processor stopped');
  }

  private async poll(): Promise<void> {
    while (this.isRunning) {
      try {
        // Check if we have capacity
        const availableSlots = this.config.concurrency - this.activeJobs;
        if (availableSlots <= 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
          continue;
        }

        // Fetch jobs from queue
        const jobs = await this.fetchJobs(availableSlots);
        
        if (jobs.length === 0) {
          // LISTEN/NOTIFY wakeup: sleep until notified or fallback timeout
          if (this.notifier) {
            await this.notifier.waitForNotification('queue_email_queue', 30_000);
          } else {
            await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          }
          continue;
        }

        // Process jobs concurrently - use allSettled to prevent single failure from failing batch
        // This ensures all jobs are processed even if some fail
        const results = await Promise.allSettled(jobs.map(job => this.processJob(job)));
        
        // Log any unexpected rejections (processJob should handle its own errors)
        for (let i = 0; i < results.length; i++) {
          const result = results[i];
          if (result && result.status === 'rejected') {
            this.logger.error('Unexpected job processing error', {
              jobId: jobs[i]?.id,
              error: result.reason,
            });
          }
        }
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

  private async processJob(job: EmailJob): Promise<void> {
    this.activeJobs++;
    const startTime = Date.now();

    try {
      this.logger.debug('Processing email job', {
        jobId: job.id,
        messageId: job.messageId,
        to: job.to,
        attempt: job.attempt,
      });

      // Check suppression - findByEmail returns array, check first match
      const suppressionResult = await this.suppressionsRepo.findByEmail(job.to, job.tenantId);
      if (suppressionResult.ok && suppressionResult.value && suppressionResult.value.length > 0) {
        const firstSuppression = suppressionResult.value[0];
        if (firstSuppression) {
          await this.handleSuppressed(job, firstSuppression.reason ?? 'unknown');
          return;
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
          await this.requeueJob(job, 'ip_rate_limit');
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
      this.logger.debug('Job completed', {
        jobId: job.id,
        duration,
        activeJobs: this.activeJobs,
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
    
    // Insert before </body> or at end
    if (html.includes('</body>')) {
      return html.replace('</body>', `${pixel}</body>`);
    }
    return html + pixel;
  }

  private rewriteLinks(html: string, job: EmailJob): string {
    const trackingId = this.encodeTrackingId(job.messageId, job.tenantId);
    const clickBase = `${this.trackingConfig.baseUrl}${this.trackingConfig.clickRedirectPath}/${trackingId}`;
    
    // Rewrite <a href="..."> links
    return html.replace(
      /<a\s+([^>]*?)href=["']([^"']+)["']([^>]*?)>/gi,
      (match, before, url, after) => {
        // Skip mailto:, tel:, and tracking URLs
        if (url.startsWith('mailto:') || url.startsWith('tel:') || url.includes(this.trackingConfig.baseUrl)) {
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

  private async sendEmail(email: PreparedEmail): Promise<SentMessageInfo> {
    if (!this.transporter) {
      throw new Error('SMTP transporter not initialized');
    }

    // Use circuit breaker keyed by SMTP host to prevent overwhelming a failing server
    const circuitBreakerKey = `smtp:${this.smtpConfig.host}:${this.smtpConfig.port}`;
    const circuitBreaker = this.circuitBreakers.get(circuitBreakerKey);
    
    // Check if circuit is open (too many failures)
    const state = await circuitBreaker.getState();
    if (state === 'open') {
      this.logger.warn('Circuit breaker open for SMTP server', {
        host: this.smtpConfig.host,
        port: this.smtpConfig.port,
      });
      throw new Error(`SMTP circuit breaker open - server ${this.smtpConfig.host} temporarily unavailable`);
    }

    const mailOptions: Record<string, unknown> = {
      from: email.from,
      to: email.to,
      subject: email.subject,
      html: email.html,
      text: email.text,
      headers: email.headers,
      attachments: email.attachments,
    };

    // Add DKIM signing options
    if (email.dkim) {
      mailOptions.dkim = email.dkim;
    }

    // CRITICAL: Add timeout to prevent hung SMTP connections from blocking the worker forever
    const SMTP_TIMEOUT_MS = 30000; // 30 seconds
    
    // FIX-004: Capture the timer handle so we can clearTimeout on both
    // success and error paths. Without this, every successful send leaked
    // a 30-second dangling timer — at high throughput this accumulated
    // thousands of pending timers, wasting memory and event-loop resources.
    let timeoutHandle: ReturnType<typeof setTimeout>;
    try {
      const sendPromise = this.transporter.sendMail(mailOptions);
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error(`SMTP send timeout after ${SMTP_TIMEOUT_MS}ms`)), SMTP_TIMEOUT_MS);
      });
      
      const result = await Promise.race([sendPromise, timeoutPromise]);
      clearTimeout(timeoutHandle!);
      
      // Record success to circuit breaker
      await circuitBreaker.recordSuccess();
      
      return result;
    } catch (error) {
      clearTimeout(timeoutHandle!);
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
   */
  private async handleSuccess(job: EmailJob, result: SentMessageInfo): Promise<void> {
    this.logger.info('Email sent successfully', {
      jobId: job.id,
      messageId: job.messageId,
      response: result.response,
    });

    const client = await this.db.connect();
    try {
      await client.query('BEGIN');

      // Update message status
      await client.query(
        `UPDATE messages SET status = 'sent', sent_at = NOW(), smtp_message_id = $2, updated_at = NOW() WHERE id = $1`,
        [job.messageId, result.messageId || '']
      );

      // Record sent event
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

      // Remove from queue
      await client.query('DELETE FROM email_queue WHERE id = $1', [job.id]);

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    // Post-transaction side-effects (Redis, non-critical)
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
  }

  private async handleError(job: EmailJob, error: Error): Promise<void> {
    this.logger.error('Email send failed', {
      jobId: job.id,
      messageId: job.messageId,
      error: error.message,
      attempt: job.attempt,
    });

    const isBounce = this.isBounceError(error);
    const isRetryable = this.isRetryableError(error) && job.attempt < this.config.maxRetries;

    if (isBounce) {
      await this.handleBounce(job, error);
    } else if (isRetryable) {
      await this.retryJob(job, error);
    } else {
      await this.failJob(job, error);
    }
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
      await client.query(
        `UPDATE messages SET status = 'bounced', bounced_at = NOW(), bounce_type = $2, bounce_reason = $3, updated_at = NOW() WHERE id = $1`,
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
      await client.query(
        `UPDATE messages SET status = 'failed', metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb, updated_at = NOW() WHERE id = $1`,
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
  private async retryJob(job: EmailJob, error: Error): Promise<void> {
    const nextAttempt = job.attempt + 1;
    const delay = this.config.retryDelay * Math.pow(2, job.attempt - 1); // Exponential backoff
    const scheduledAt = new Date(Date.now() + delay);

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
          locked_until = NULL,
          updated_at = NOW()
        WHERE id = $4
      `, [nextAttempt, scheduledAt, error.message, job.id]);

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
      await client.query(
        `UPDATE messages SET status = 'failed', bounce_reason = $2, updated_at = NOW() WHERE id = $1`,
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

  private async requeueJob(job: EmailJob, reason: string): Promise<void> {
    // Requeue with delay
    const scheduledAt = new Date(Date.now() + 60000); // 1 minute

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

  private isRetryableError(error: Error): boolean {
    const message = error.message.toLowerCase();
    const retryableCodePattern = /\b(421|45[0-2])\b/;
    const retryablePatterns = ['timeout', 'econnreset', 'econnrefused', 'temporary'];
    
    return retryableCodePattern.test(message) ||
           retryablePatterns.some(pattern => message.includes(pattern));
  }

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
    const result = await this.domainsRepo.findById(domainId, tenantId);
    if (!result.ok || !result.value) {
      this.logger.warn('Warmup day calculation: domain not found', { domainId, tenantId });
      return 0;
    }

    const domain = result.value;
    const baseDate = domain.verifiedAt ?? domain.createdAt ?? new Date();
    const diffMs = Date.now() - baseDate.getTime();
    const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));

    return Math.max(0, days);
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

interface PreparedEmail {
  from: string;
  to: string;
  subject: string;
  html?: string;
  text?: string;
  headers: Record<string, string>;
  attachments?: Array<{
    filename: string;
    content: Buffer;
    contentType: string;
  }>;
  dkim?: DkimConfig;
}

interface DkimConfig {
  domainName: string;
  keySelector: string;
  privateKey: string;
}

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
      return Promise.reject(new Error('Rate limiter queue is full'));
    }

    return new Promise((resolve, reject) => {
      this.waitQueue.push({ resolve, reject });
      setTimeout(() => this.processQueue(), 1000 / this.refillRate);
    });
  }

  private refill(): void {
    const now = Date.now();
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
