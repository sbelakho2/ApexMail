/**
 * Email Processor - Handles email sending from queue
 */

import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import type { Logger } from '@apexmail/lib';
import { generateId } from '@apexmail/lib';
import { MessagesRepository, EventsRepository, DomainsRepository, SuppressionsRepository } from '@apexmail/db';
import { createTransport, type Transporter, type SentMessageInfo } from 'nodemailer';
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'crypto';

interface EmailProcessorConfig {
  db: Pool;
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
  private readonly redis: Redis;
  private readonly config: EmailProcessorConfig['config'];
  private readonly smtpConfig: EmailProcessorConfig['smtp'];
  private readonly dkimConfig: EmailProcessorConfig['dkim'];
  private readonly trackingConfig: EmailProcessorConfig['tracking'];
  private readonly warmupConfig: EmailProcessorConfig['warmup'];
  private readonly logger: Logger;
  
  private readonly messagesRepo: MessagesRepository;
  private readonly eventsRepo: EventsRepository;
  private readonly domainsRepo: DomainsRepository;
  private readonly suppressionsRepo: SuppressionsRepository;
  
  private transporter: Transporter | null = null;
  private isRunning = false;
  private activeJobs = 0;
  private readonly dkimKeys = new Map<string, { privateKey: string; publicKey: string }>();
  private readonly rateLimiter: TokenBucketRateLimiter;
  private readonly warmupCounters = new Map<string, number>();

  constructor(options: EmailProcessorConfig) {
    this.db = options.db;
    this.redis = options.redis;
    this.config = options.config;
    this.smtpConfig = options.smtp;
    this.dkimConfig = options.dkim;
    this.trackingConfig = options.tracking;
    this.warmupConfig = options.warmup;
    this.logger = options.logger;
    
    this.messagesRepo = new MessagesRepository(this.db);
    this.eventsRepo = new EventsRepository(this.db);
    this.domainsRepo = new DomainsRepository(this.db);
    this.suppressionsRepo = new SuppressionsRepository(this.db);
    
    this.rateLimiter = new TokenBucketRateLimiter(
      this.smtpConfig.rateLimitPerSecond,
      this.smtpConfig.rateLimitPerSecond
    );
  }

  async start(): Promise<void> {
    this.logger.info('Starting email processor', {
      concurrency: this.config.concurrency,
      pollInterval: this.config.pollInterval,
    });

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
        rejectUnauthorized: process.env.NODE_ENV === 'production',
      },
    });

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
    }

    // Reset warmup counters at midnight
    this.scheduleWarmupReset();

    this.isRunning = true;
    this.poll();
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping email processor');
    this.isRunning = false;

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
          await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
          continue;
        }

        // Process jobs concurrently
        await Promise.all(jobs.map(job => this.processJob(job)));
      } catch (error) {
        this.logger.error('Poll error', { error });
        await new Promise(resolve => setTimeout(resolve, this.config.pollInterval));
      }
    }
  }

  private async fetchJobs(limit: number): Promise<EmailJob[]> {
    // Use SKIP LOCKED for concurrent workers
    const result = await this.db.query<EmailJob>(`
      SELECT 
        id, message_id as "messageId", tenant_id as "tenantId", domain_id as "domainId",
        "from", "to", subject, html, text, headers, attachments,
        campaign_id as "campaignId", tags, metadata, scheduled_at as "scheduledAt",
        attempt, created_at as "createdAt"
      FROM email_queue
      WHERE status = 'pending'
        AND (scheduled_at IS NULL OR scheduled_at <= NOW())
        AND (locked_until IS NULL OR locked_until < NOW())
      ORDER BY priority DESC, created_at ASC
      LIMIT $1
      FOR UPDATE SKIP LOCKED
    `, [limit]);

    if (result.rows.length === 0) {
      return [];
    }

    // Lock the jobs
    const ids = result.rows.map(r => r.id);
    const lockUntil = new Date(Date.now() + this.config.visibilityTimeout);
    
    await this.db.query(`
      UPDATE email_queue
      SET status = 'processing', locked_until = $1, updated_at = NOW()
      WHERE id = ANY($2)
    `, [lockUntil, ids]);

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

      // Check suppression
      const suppressionResult = await this.suppressionsRepo.findByEmail(job.to, job.tenantId);
      if (suppressionResult.ok && suppressionResult.value) {
        await this.handleSuppressed(job, suppressionResult.value.reason);
        return;
      }

      // Check warmup limits
      if (this.warmupConfig.enabled) {
        const canSend = await this.checkWarmupLimit(job.domainId);
        if (!canSend) {
          await this.requeueJob(job, 'warmup_limit');
          return;
        }
      }

      // Rate limit
      await this.rateLimiter.acquire();

      // Get domain for DKIM signing
      const domainResult = await this.domainsRepo.findById(job.domainId);
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

  private async prepareEmail(job: EmailJob, domain: { name: string; dkimPrivateKey?: string }): Promise<PreparedEmail> {
    let html = job.html;
    let text = job.text;

    // Add tracking if enabled
    if (this.trackingConfig.enabled && html) {
      html = this.addTrackingPixel(html, job);
      html = this.rewriteLinks(html, job);
    }

    // Generate Message-ID
    const messageId = `<${job.messageId}@${domain.name}>`;

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

    // DKIM signing
    let dkim: DkimConfig | undefined;
    if (this.dkimConfig.enabled && domain.dkimPrivateKey) {
      dkim = {
        domainName: domain.name,
        keySelector: this.dkimConfig.selector,
        privateKey: domain.dkimPrivateKey,
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
    return `<${unsubscribeUrl}>, <mailto:unsubscribe@${job.from.split('@')[1]}?subject=Unsubscribe>`;
  }

  private async sendEmail(email: PreparedEmail): Promise<SentMessageInfo> {
    if (!this.transporter) {
      throw new Error('SMTP transporter not initialized');
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

    return await this.transporter.sendMail(mailOptions);
  }

  private async handleSuccess(job: EmailJob, result: SentMessageInfo): Promise<void> {
    this.logger.info('Email sent successfully', {
      jobId: job.id,
      messageId: job.messageId,
      response: result.response,
    });

    // Update message status
    await this.messagesRepo.updateStatus(job.messageId, 'sent', {
      smtpResponse: result.response,
      sentAt: new Date(),
    });

    // Record sent event
    await this.eventsRepo.create({
      tenantId: job.tenantId,
      messageId: job.messageId,
      eventType: 'sent',
      recipientEmail: job.to,
      metadata: {
        smtpResponse: result.response,
        messageIdHeader: result.messageId,
      },
    });

    // Remove from queue
    await this.db.query('DELETE FROM email_queue WHERE id = $1', [job.id]);

    // Update warmup counter
    if (this.warmupConfig.enabled) {
      this.incrementWarmupCounter(job.domainId);
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

  private async handleBounce(job: EmailJob, error: Error): Promise<void> {
    const bounceType = this.classifyBounce(error);

    // Update message status
    await this.messagesRepo.updateStatus(job.messageId, 'bounced', {
      bounceType: bounceType.type,
      bounceSubtype: bounceType.subtype,
      errorMessage: error.message,
    });

    // Record bounce event
    await this.eventsRepo.create({
      tenantId: job.tenantId,
      messageId: job.messageId,
      eventType: 'bounced',
      recipientEmail: job.to,
      bounceType: bounceType.type,
      bounceSubtype: bounceType.subtype,
      bounceMessage: error.message,
    });

    // Add to suppression list for hard bounces
    if (bounceType.type === 'hard') {
      await this.suppressionsRepo.create({
        tenantId: job.tenantId,
        email: job.to,
        reason: 'bounce',
        bounceType: bounceType.type,
        bounceSubtype: bounceType.subtype,
        source: 'system',
        sourceMessageId: job.messageId,
        domainId: job.domainId,
        campaignId: job.campaignId,
      });
    }

    // Remove from queue
    await this.db.query('DELETE FROM email_queue WHERE id = $1', [job.id]);
  }

  private async handleSuppressed(job: EmailJob, reason: string): Promise<void> {
    this.logger.info('Recipient suppressed', {
      jobId: job.id,
      messageId: job.messageId,
      to: job.to,
      reason,
    });

    // Update message status
    await this.messagesRepo.updateStatus(job.messageId, 'dropped', {
      dropReason: `suppressed:${reason}`,
    });

    // Record dropped event
    await this.eventsRepo.create({
      tenantId: job.tenantId,
      messageId: job.messageId,
      eventType: 'dropped',
      recipientEmail: job.to,
      metadata: { reason: `suppressed:${reason}` },
    });

    // Remove from queue
    await this.db.query('DELETE FROM email_queue WHERE id = $1', [job.id]);
  }

  private async retryJob(job: EmailJob, error: Error): Promise<void> {
    const nextAttempt = job.attempt + 1;
    const delay = this.config.retryDelay * Math.pow(2, job.attempt - 1); // Exponential backoff
    const scheduledAt = new Date(Date.now() + delay);

    await this.db.query(`
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

    // Record deferred event
    await this.eventsRepo.create({
      tenantId: job.tenantId,
      messageId: job.messageId,
      eventType: 'deferred',
      recipientEmail: job.to,
      metadata: {
        attempt: nextAttempt,
        scheduledAt: scheduledAt.toISOString(),
        error: error.message,
      },
    });
  }

  private async failJob(job: EmailJob, error: Error): Promise<void> {
    // Update message status
    await this.messagesRepo.updateStatus(job.messageId, 'failed', {
      errorMessage: error.message,
      failedAt: new Date(),
    });

    // Record failed event
    await this.eventsRepo.create({
      tenantId: job.tenantId,
      messageId: job.messageId,
      eventType: 'failed',
      recipientEmail: job.to,
      metadata: {
        error: error.message,
        attempt: job.attempt,
      },
    });

    // Move to dead letter queue
    await this.db.query(`
      INSERT INTO email_dlq (id, original_job, error_message, failed_at)
      VALUES ($1, $2, $3, NOW())
    `, [generateId('dlq'), JSON.stringify(job), error.message]);

    // Remove from queue
    await this.db.query('DELETE FROM email_queue WHERE id = $1', [job.id]);
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
    const bounceCodes = ['550', '551', '552', '553', '554', '555'];
    return bounceCodes.some(code => message.includes(code));
  }

  private isRetryableError(error: Error): boolean {
    const message = error.message.toLowerCase();
    const retryableCodes = ['421', '450', '451', '452'];
    const retryablePatterns = ['timeout', 'econnreset', 'econnrefused', 'temporary'];
    
    return retryableCodes.some(code => message.includes(code)) ||
           retryablePatterns.some(pattern => message.includes(pattern));
  }

  private classifyBounce(error: Error): { type: 'hard' | 'soft'; subtype: string } {
    const message = error.message.toLowerCase();

    // Hard bounce patterns
    if (message.includes('550') || message.includes('551') || message.includes('553')) {
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

  private async checkWarmupLimit(domainId: string): Promise<boolean> {
    const schedule = this.warmupConfig.schedule[domainId];
    if (!schedule) return true; // No warmup schedule, no limit

    const dayOfWarmup = this.calculateWarmupDay(domainId);
    const dailyLimit = schedule[dayOfWarmup] ?? schedule[schedule.length - 1];
    const currentCount = this.warmupCounters.get(domainId) ?? 0;

    return currentCount < dailyLimit;
  }

  private calculateWarmupDay(domainId: string): number {
    // In production, calculate from domain verification date
    return 0;
  }

  private incrementWarmupCounter(domainId: string): void {
    const current = this.warmupCounters.get(domainId) ?? 0;
    this.warmupCounters.set(domainId, current + 1);
  }

  private scheduleWarmupReset(): void {
    // Reset counters at midnight UTC
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    
    const msUntilMidnight = tomorrow.getTime() - now.getTime();

    setTimeout(() => {
      this.warmupCounters.clear();
      this.logger.info('Warmup counters reset');
      this.scheduleWarmupReset(); // Schedule next reset
    }, msUntilMidnight);
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
  private readonly waitQueue: Array<() => void> = [];

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();

    if (this.tokens >= 1) {
      this.tokens--;
      return;
    }

    // Wait for a token
    return new Promise(resolve => {
      this.waitQueue.push(resolve);
      setTimeout(() => this.processQueue(), 1000 / this.refillRate);
    });
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    const newTokens = elapsed * this.refillRate;
    
    this.tokens = Math.min(this.capacity, this.tokens + newTokens);
    this.lastRefill = now;
  }

  private processQueue(): void {
    this.refill();
    
    while (this.waitQueue.length > 0 && this.tokens >= 1) {
      this.tokens--;
      const resolve = this.waitQueue.shift()!;
      resolve();
    }
  }
}
