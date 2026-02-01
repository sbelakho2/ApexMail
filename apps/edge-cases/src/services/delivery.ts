/**
 * Delivery Edge Cases Service
 * 
 * Handles greylisting, loop detection, MX failover, and auto-responder detection
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import { config, GREYLIST_CODES, AUTO_SUBMITTED_VALUES } from '../config.js';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum DeliveryStatus {
  PENDING = 'pending',
  DELIVERED = 'delivered',
  DEFERRED = 'deferred',
  BOUNCED = 'bounced',
  DROPPED = 'dropped',
}

export enum ResponseType {
  SUCCESS = 'success',
  TEMPORARY_FAILURE = 'temporary_failure',
  PERMANENT_FAILURE = 'permanent_failure',
  GREYLIST = 'greylist',
  RATE_LIMIT = 'rate_limit',
  CONNECTION_ERROR = 'connection_error',
}

export interface SMTPResponse {
  code: number;
  message: string;
  enhanced?: string;
  responseType: ResponseType;
  isGreylist: boolean;
  suggestedRetryDelay?: number;
}

export interface MXRecord {
  exchange: string;
  priority: number;
  ttl?: number;
}

export interface DeliveryAttempt {
  messageId: string;
  attempt: number;
  mxHost: string;
  mxPriority: number;
  responseCode: number;
  responseMessage: string;
  responseType: ResponseType;
  timestamp: Date;
  duration: number;
}

export interface LoopDetection {
  isLoop: boolean;
  hopCount: number;
  maxHops: number;
  loopPath?: string[];
}

export interface AutoResponderDetection {
  isAutoResponder: boolean;
  type?: 'ooo' | 'vacation' | 'bounce' | 'notification' | 'system';
  confidence: number;
  indicators: string[];
}

export interface RetrySchedule {
  nextAttempt: Date;
  attemptNumber: number;
  delay: number;
  reason: string;
}

/**
 * Delivery Edge Cases Service
 */
export class DeliveryService {
  private pool: Pool;
  private redis: Redis;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Parse SMTP response and classify it
   */
  parseSMTPResponse(code: number, message: string): SMTPResponse {
    const codeStr = code.toString();
    
    // Extract enhanced status code (X.Y.Z format)
    const enhancedMatch = message.match(/([245]\.[0-9]+\.[0-9]+)/);
    const enhanced = enhancedMatch?.[1];

    // Determine response type
    let responseType: ResponseType;
    let isGreylist = false;
    let suggestedRetryDelay: number | undefined;

    if (code >= 200 && code < 300) {
      responseType = ResponseType.SUCCESS;
    } else if (code >= 400 && code < 500) {
      // Check for greylisting
      if (GREYLIST_CODES.includes(codeStr) && this.isGreylistMessage(message)) {
        responseType = ResponseType.GREYLIST;
        isGreylist = true;
        suggestedRetryDelay = config.retry.greylistRetryDelay;
      } else if (this.isRateLimitMessage(message)) {
        responseType = ResponseType.RATE_LIMIT;
        suggestedRetryDelay = this.extractRetryDelay(message);
      } else {
        responseType = ResponseType.TEMPORARY_FAILURE;
      }
    } else if (code >= 500 && code < 600) {
      responseType = ResponseType.PERMANENT_FAILURE;
    } else {
      responseType = ResponseType.CONNECTION_ERROR;
    }

    return {
      code,
      message,
      enhanced,
      responseType,
      isGreylist,
      suggestedRetryDelay,
    };
  }

  /**
   * Check if message indicates greylisting
   */
  private isGreylistMessage(message: string): boolean {
    const greylistPatterns = [
      /greylist/i,
      /gray.?list/i,
      /try again later/i,
      /please retry/i,
      /temporarily deferred/i,
      /temporary.+failure/i,
      /service.+unavailable.*later/i,
      /4\.7\.1/,
      /rate.+limit/i,
    ];

    return greylistPatterns.some(pattern => pattern.test(message));
  }

  /**
   * Check if message indicates rate limiting
   */
  private isRateLimitMessage(message: string): boolean {
    const rateLimitPatterns = [
      /rate.?limit/i,
      /too many connections/i,
      /too many messages/i,
      /sending.+too fast/i,
      /over quota/i,
      /exceeded/i,
      /throttl/i,
    ];

    return rateLimitPatterns.some(pattern => pattern.test(message));
  }

  /**
   * Extract retry delay from SMTP response
   */
  private extractRetryDelay(message: string): number | undefined {
    // Try to find explicit delay in message
    const delayMatch = message.match(/(\d+)\s*(second|minute|hour)/i);
    if (delayMatch) {
      const value = parseInt(delayMatch[1], 10);
      const unit = delayMatch[2].toLowerCase();
      
      switch (unit) {
        case 'second':
          return value * 1000;
        case 'minute':
          return value * 60 * 1000;
        case 'hour':
          return value * 60 * 60 * 1000;
      }
    }
    return undefined;
  }

  /**
   * Calculate retry schedule based on response
   */
  calculateRetrySchedule(
    response: SMTPResponse,
    currentAttempt: number
  ): RetrySchedule | null {
    // Don't retry permanent failures
    if (response.responseType === ResponseType.PERMANENT_FAILURE) {
      return null;
    }

    // Don't retry if max attempts reached
    if (currentAttempt >= config.retry.maxRetries) {
      return null;
    }

    let delay: number;
    let reason: string;

    if (response.isGreylist) {
      // Use greylist-specific delay
      delay = response.suggestedRetryDelay || config.retry.greylistRetryDelay;
      reason = 'Greylisting detected - waiting before retry';
    } else if (response.suggestedRetryDelay) {
      // Use suggested delay from response
      delay = response.suggestedRetryDelay;
      reason = 'Using server-suggested retry delay';
    } else {
      // Exponential backoff
      delay = Math.min(
        config.retry.initialDelay * Math.pow(config.retry.backoffMultiplier, currentAttempt),
        config.retry.maxDelay
      );
      reason = 'Exponential backoff retry';
    }

    const nextAttempt = new Date(Date.now() + delay);

    return {
      nextAttempt,
      attemptNumber: currentAttempt + 1,
      delay,
      reason,
    };
  }

  /**
   * Detect email loops from Received headers
   */
  detectLoop(receivedHeaders: string[]): LoopDetection {
    const maxHops = config.loopDetection.maxHops;
    const hopCount = receivedHeaders.length;

    if (hopCount > maxHops) {
      // Extract path for debugging
      const loopPath = receivedHeaders.slice(0, 10).map(header => {
        const fromMatch = header.match(/from\s+([^\s(]+)/i);
        return fromMatch?.[1] || 'unknown';
      });

      return {
        isLoop: true,
        hopCount,
        maxHops,
        loopPath,
      };
    }

    // Check for repeated hosts (potential loop)
    const hosts = receivedHeaders.map(header => {
      const fromMatch = header.match(/from\s+([^\s(]+)/i);
      return fromMatch?.[1]?.toLowerCase();
    }).filter(Boolean);

    const hostCounts = new Map<string, number>();
    for (const host of hosts) {
      hostCounts.set(host!, (hostCounts.get(host!) || 0) + 1);
    }

    // If any host appears more than 3 times, likely a loop
    for (const [host, count] of hostCounts) {
      if (count > 3) {
        return {
          isLoop: true,
          hopCount,
          maxHops,
          loopPath: [host],
        };
      }
    }

    return {
      isLoop: false,
      hopCount,
      maxHops,
    };
  }

  /**
   * Detect auto-responder/OOO messages
   */
  detectAutoResponder(headers: Map<string, string>, subject: string, body?: string): AutoResponderDetection {
    const indicators: string[] = [];
    let type: AutoResponderDetection['type'];
    let confidence = 0;

    // Check Auto-Submitted header
    const autoSubmitted = headers.get('Auto-Submitted')?.toLowerCase();
    if (autoSubmitted && AUTO_SUBMITTED_VALUES.includes(autoSubmitted)) {
      indicators.push(`Auto-Submitted: ${autoSubmitted}`);
      confidence += 40;
      type = 'system';
    }

    // Check Precedence header
    const precedence = headers.get('Precedence')?.toLowerCase();
    if (precedence === 'auto_reply' || precedence === 'bulk' || precedence === 'junk') {
      indicators.push(`Precedence: ${precedence}`);
      confidence += 30;
    }

    // Check X-Auto-Response-Suppress
    if (headers.has('X-Auto-Response-Suppress')) {
      indicators.push('X-Auto-Response-Suppress present');
      confidence += 25;
    }

    // Check X-Autorespond
    if (headers.has('X-Autorespond') || headers.has('X-Autoreply')) {
      indicators.push('Autorespond header present');
      confidence += 35;
      type = 'system';
    }

    // Check for specific return paths
    const returnPath = headers.get('Return-Path')?.toLowerCase() || '';
    if (returnPath === '<>' || returnPath.includes('mailer-daemon') || returnPath.includes('postmaster')) {
      indicators.push('Empty or system Return-Path');
      confidence += 20;
      type = type || 'bounce';
    }

    // Check subject patterns
    for (const pattern of config.autoResponder.subjectPatterns) {
      if (new RegExp(pattern, 'i').test(subject)) {
        indicators.push(`Subject matches: ${pattern}`);
        confidence += 25;
        
        if (/out.of.office|ooo|vacation|away/i.test(subject)) {
          type = 'ooo';
        } else if (/auto/i.test(subject)) {
          type = 'system';
        }
      }
    }

    // Check subject prefixes
    const subjectLower = subject.toLowerCase();
    if (subjectLower.startsWith('re: ') || subjectLower.startsWith('fw:') || subjectLower.startsWith('fwd:')) {
      // Might be a reply, need more indicators
    }

    // Check body content if available
    if (body) {
      const bodyLower = body.toLowerCase();
      
      const oooPatterns = [
        'out of the office',
        'away from the office',
        'on vacation',
        'on leave',
        'limited access to email',
        'will respond when i return',
        'currently out',
        'automatic reply',
      ];

      for (const pattern of oooPatterns) {
        if (bodyLower.includes(pattern)) {
          indicators.push(`Body contains: "${pattern}"`);
          confidence += 15;
          type = type || 'ooo';
        }
      }
    }

    // Cap confidence at 100
    confidence = Math.min(confidence, 100);

    return {
      isAutoResponder: confidence >= 50,
      type,
      confidence,
      indicators,
    };
  }

  /**
   * Resolve and sort MX records
   */
  async resolveMX(domain: string): Promise<Result<MXRecord[]>> {
    try {
      // Check cache first
      const cacheKey = `mx:records:${domain}`;
      const cached = await this.redis.get(cacheKey);
      if (cached) {
        return { ok: true, value: JSON.parse(cached) };
      }

      const { promises: dns } = await import('dns');
      const records = await dns.resolveMx(domain);

      const mxRecords: MXRecord[] = records
        .map(r => ({
          exchange: r.exchange.toLowerCase(),
          priority: r.priority,
        }))
        .sort((a, b) => a.priority - b.priority);

      // Cache for 1 hour
      await this.redis.setex(cacheKey, 3600, JSON.stringify(mxRecords));

      return { ok: true, value: mxRecords };
    } catch (error) {
      // If MX lookup fails, try A record as fallback
      try {
        const { promises: dns } = await import('dns');
        await dns.resolve4(domain);
        
        // Domain has A record, use it as implicit MX
        return {
          ok: true,
          value: [{ exchange: domain, priority: 0 }],
        };
      } catch {
        return {
          ok: false,
          error: new Error(`No MX records found for ${domain}`),
        };
      }
    }
  }

  /**
   * Select next MX to try
   */
  selectNextMX(
    mxRecords: MXRecord[],
    failedHosts: Set<string>,
    preferredPriority?: number
  ): MXRecord | null {
    // Filter out failed hosts
    const availableMX = mxRecords.filter(mx => !failedHosts.has(mx.exchange));

    if (availableMX.length === 0) {
      return null;
    }

    // If we have a preferred priority (for load balancing), try to match
    if (preferredPriority !== undefined) {
      const samePriority = availableMX.filter(mx => mx.priority === preferredPriority);
      if (samePriority.length > 0) {
        // Random selection among same priority
        return samePriority[Math.floor(Math.random() * samePriority.length)];
      }
    }

    // Return lowest priority (highest preference) available MX
    return availableMX[0];
  }

  /**
   * Record delivery attempt
   */
  async recordDeliveryAttempt(attempt: DeliveryAttempt): Promise<Result<void>> {
    try {
      await this.pool.query(`
        INSERT INTO edge_delivery_attempts (
          message_id, attempt_number, mx_host, mx_priority,
          response_code, response_message, response_type,
          attempt_time, duration_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        attempt.messageId,
        attempt.attempt,
        attempt.mxHost,
        attempt.mxPriority,
        attempt.responseCode,
        attempt.responseMessage,
        attempt.responseType,
        attempt.timestamp,
        attempt.duration,
      ]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get delivery history for a message
   */
  async getDeliveryHistory(messageId: string): Promise<Result<DeliveryAttempt[]>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM edge_delivery_attempts
        WHERE message_id = $1
        ORDER BY attempt_number ASC
      `, [messageId]);

      return {
        ok: true,
        value: result.rows.map(row => ({
          messageId: row.message_id,
          attempt: row.attempt_number,
          mxHost: row.mx_host,
          mxPriority: row.mx_priority,
          responseCode: row.response_code,
          responseMessage: row.response_message,
          responseType: row.response_type as ResponseType,
          timestamp: row.attempt_time,
          duration: row.duration_ms,
        })),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Check if domain is known for greylisting
   */
  async isKnownGreylister(domain: string): Promise<boolean> {
    const cacheKey = `greylist:domain:${domain}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached !== null) {
      return cached === '1';
    }

    try {
      const result = await this.pool.query(`
        SELECT COUNT(*) as greylist_count
        FROM edge_delivery_attempts
        WHERE mx_host LIKE $1
        AND response_type = 'greylist'
        AND attempt_time > NOW() - INTERVAL '30 days'
      `, [`%.${domain}`]);

      const isGreylister = result.rows[0].greylist_count > 10;
      await this.redis.setex(cacheKey, 86400, isGreylister ? '1' : '0');
      
      return isGreylister;
    } catch {
      return false;
    }
  }

  /**
   * Schedule a greylisted message for retry
   */
  async scheduleGreylistRetry(
    messageId: string,
    delay: number
  ): Promise<Result<Date>> {
    try {
      const retryAt = new Date(Date.now() + delay);
      
      await this.pool.query(`
        UPDATE email_queue
        SET 
          status = 'deferred',
          next_attempt_at = $2,
          retry_reason = 'greylist'
        WHERE message_id = $1
      `, [messageId, retryAt]);

      // Also set a Redis key for the worker to pick up
      await this.redis.zadd('email:retry:greylist', retryAt.getTime(), messageId);

      return { ok: true, value: retryAt };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get messages ready for greylist retry
   */
  async getGreylistRetryReady(): Promise<Result<string[]>> {
    try {
      const now = Date.now();
      const messageIds = await this.redis.zrangebyscore(
        'email:retry:greylist',
        0,
        now
      );

      if (messageIds.length > 0) {
        // Remove from the retry set
        await this.redis.zremrangebyscore('email:retry:greylist', 0, now);
      }

      return { ok: true, value: messageIds };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }
}
