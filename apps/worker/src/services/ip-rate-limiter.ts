/**
 * IP Rate Limiter Service
 * 
 * Manages per-IP rate limiting for email sending with ISP-aware warmup schedules.
 * 
 * Industry Standard Warmup Guidelines:
 * - Gmail/Google: Very strict, requires slow ramp (50/day → 30K/day over 14 days)
 * - Microsoft: More lenient, faster warmup allowed (100/day → 50K/day)
 * - Yahoo/AOL: Similar to Gmail strictness
 * - Default: Conservative approach for unknown ISPs
 * 
 * Rate Limits are based on DAILY limits per IP address per ISP, not per-second limits.
 * Per-second limits are handled by the token bucket in the email processor.
 * 
 * This service tracks:
 * 1. Per-IP daily send counts
 * 2. Per-IP per-ISP daily send counts (to respect ISP-specific limits)
 * 3. Warmup day calculation from IP warmup start date
 */

import type { Redis } from 'ioredis';
import type { Pool } from 'pg';
import type { Logger } from '@apexmail/lib';

// ISP warmup schedules - industry standard conservative values
// These are DAILY limits per IP, not per-second/minute limits
export const DEFAULT_ISP_WARMUP_SCHEDULES: Record<string, number[]> = {
  // Gmail is the strictest - slow and steady wins
  gmail: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000, 30000],
  
  // Microsoft (Outlook, Hotmail, Live) allows faster warmup
  microsoft: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000],
  
  // Yahoo/AOL - similar to Gmail
  yahoo: [50, 100, 200, 400, 800, 1500, 2500, 4000, 6000, 8000, 10000, 15000, 20000],
  
  // Apple (iCloud) - moderate strictness
  apple: [75, 150, 300, 600, 1200, 2400, 4000, 6000, 9000, 12000, 16000, 22000, 30000],
  
  // Default for unknown ISPs - conservative
  default: [100, 200, 400, 800, 1500, 3000, 5000, 8000, 12000, 18000, 25000, 35000, 50000, 75000, 100000],
};

// Default first day limit (fallback)
const DEFAULT_INITIAL_LIMIT = 100;

export interface IPRateLimiterConfig {
  redis: Redis;
  db: Pool;
  logger: Logger;
  keyPrefix?: string;
  
  // Override default schedules if needed
  ispSchedules?: Record<string, number[]>;
  
  // Global per-IP per-hour limit (applies on top of ISP limits)
  // Default: 2500/hour (prevents bursty sending that trips spam filters)
  globalHourlyLimit?: number;
  
  // Per-second burst limit (token bucket capacity)
  // Default: 50 (allows brief bursts while maintaining average)
  burstLimit?: number;
  
  // Whether to check ISP-specific limits (disable for testing)
  ispAwareLimiting?: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  reason?: string;
  currentCount?: number;
  limit?: number;
  retryAfter?: number; // seconds until retry is advised
  isp?: string;
}

export interface IPWarmupStatus {
  ipAddress: string;
  warmupDay: number;
  warmupStartedAt: Date | null;
  dailyLimit: number;
  dailySent: number;
  isWarmedUp: boolean;
  ispLimits: Record<string, { limit: number; sent: number }>;
}

/**
 * IP Rate Limiter with ISP-aware warmup tracking
 */
export class IPRateLimiter {
  private readonly redis: Redis;
  private readonly db: Pool;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly ispSchedules: Record<string, number[]>;
  private readonly globalHourlyLimit: number;
  private readonly ispAwareLimiting: boolean;
  
  // In-memory cache for IP warmup status (refreshed from DB periodically)
  private readonly warmupCache = new Map<string, { status: IPWarmupStatus; expiresAt: number }>();
  private readonly cacheTtlMs = 60000; // 1 minute cache
  
  // MEM-005 FIX: MX lookup cache with LRU eviction to prevent unbounded growth
  private readonly mxCache = new Map<string, { isp: string; expiresAt: number }>();
  private readonly mxCacheTtlMs = 3600000; // 1 hour cache
  private static readonly MAX_MX_CACHE_SIZE = 10000;
  private static readonly MAX_WARMUP_CACHE_SIZE = 1000;
  
  // Cleanup interval handle
  private cleanupIntervalId: ReturnType<typeof setInterval> | null = null;

  constructor(config: IPRateLimiterConfig) {
    this.redis = config.redis;
    this.db = config.db;
    this.logger = config.logger;
    this.keyPrefix = config.keyPrefix ?? 'ip_rate:';
    this.ispSchedules = { ...DEFAULT_ISP_WARMUP_SCHEDULES, ...config.ispSchedules };
    this.globalHourlyLimit = config.globalHourlyLimit ?? 2500;
    this.ispAwareLimiting = config.ispAwareLimiting ?? true;
    
    // MEM-005 FIX: Start periodic cache cleanup to prevent memory leaks
    this.startCacheCleanup();
  }

  /**
   * MEM-005 FIX: Clean up expired entries from caches and enforce size limits
   */
  private startCacheCleanup(): void {
    // Run cleanup every 5 minutes
    this.cleanupIntervalId = setInterval(() => {
      this.cleanupExpiredCacheEntries();
    }, 5 * 60 * 1000);
    
    // Don't prevent process exit
    this.cleanupIntervalId.unref();
  }

  /**
   * Clean up expired cache entries and enforce size limits
   */
  private cleanupExpiredCacheEntries(): void {
    const now = Date.now();
    let expiredMxCount = 0;
    let expiredWarmupCount = 0;

    // Clean up expired MX cache entries
    for (const [key, value] of this.mxCache.entries()) {
      if (value.expiresAt < now) {
        this.mxCache.delete(key);
        expiredMxCount++;
      }
    }

    // Clean up expired warmup cache entries
    for (const [key, value] of this.warmupCache.entries()) {
      if (value.expiresAt < now) {
        this.warmupCache.delete(key);
        expiredWarmupCount++;
      }
    }

    // Enforce size limits with LRU-like eviction (remove oldest entries first)
    if (this.mxCache.size > IPRateLimiter.MAX_MX_CACHE_SIZE) {
      const entriesToRemove = this.mxCache.size - IPRateLimiter.MAX_MX_CACHE_SIZE;
      const entries = Array.from(this.mxCache.entries())
        .sort((a, b) => a[1].expiresAt - b[1].expiresAt);
      for (let i = 0; i < entriesToRemove; i++) {
        const entry = entries[i];
        if (entry) this.mxCache.delete(entry[0]);
      }
    }

    if (this.warmupCache.size > IPRateLimiter.MAX_WARMUP_CACHE_SIZE) {
      const entriesToRemove = this.warmupCache.size - IPRateLimiter.MAX_WARMUP_CACHE_SIZE;
      const entries = Array.from(this.warmupCache.entries())
        .sort((a, b) => a[1].expiresAt - b[1].expiresAt);
      for (let i = 0; i < entriesToRemove; i++) {
        const entry = entries[i];
        if (entry) this.warmupCache.delete(entry[0]);
      }
    }

    if (expiredMxCount > 0 || expiredWarmupCount > 0) {
      this.logger.debug('Cache cleanup completed', {
        expiredMxEntries: expiredMxCount,
        expiredWarmupEntries: expiredWarmupCount,
        mxCacheSize: this.mxCache.size,
        warmupCacheSize: this.warmupCache.size,
      });
    }
  }

  /**
   * Stop the cache cleanup interval (call on shutdown)
   */
  shutdown(): void {
    if (this.cleanupIntervalId) {
      clearInterval(this.cleanupIntervalId);
      this.cleanupIntervalId = null;
    }
    this.mxCache.clear();
    this.warmupCache.clear();
  }

  /**
   * Check if sending from this IP to this recipient is allowed
   */
  async checkRateLimit(
    ipAddress: string,
    recipientDomain: string
  ): Promise<RateLimitResult> {
    try {
      // 1. Check per-IP hourly limit (burst protection)
      const hourlyResult = await this.checkHourlyLimit(ipAddress);
      if (!hourlyResult.allowed) {
        return hourlyResult;
      }

      // 2. Get IP warmup status
      const warmupStatus = await this.getWarmupStatus(ipAddress);
      
      // 3. Check global daily limit for this IP
      if (warmupStatus.dailySent >= warmupStatus.dailyLimit) {
        return {
          allowed: false,
          reason: `IP ${ipAddress} has reached daily warmup limit`,
          currentCount: warmupStatus.dailySent,
          limit: warmupStatus.dailyLimit,
          retryAfter: this.secondsUntilMidnightUTC(),
        };
      }

      // 4. Check ISP-specific limits if enabled
      if (this.ispAwareLimiting) {
        const isp = this.detectISP(recipientDomain);
        const ispLimit = this.getISPDailyLimit(isp, warmupStatus.warmupDay);
        const ispSent = await this.getISPSentCount(ipAddress, isp);
        
        if (ispSent >= ispLimit) {
          return {
            allowed: false,
            reason: `IP ${ipAddress} has reached daily limit for ${isp}`,
            currentCount: ispSent,
            limit: ispLimit,
            retryAfter: this.secondsUntilMidnightUTC(),
            isp,
          };
        }
      }

      return { 
        allowed: true,
        currentCount: warmupStatus.dailySent,
        limit: warmupStatus.dailyLimit,
      };
    } catch (error) {
      this.logger.error('Rate limit check failed', { error, ipAddress, recipientDomain });
      // Fail open to avoid blocking emails due to rate limiter errors
      // In production, you might want to fail closed for security
      return { allowed: true };
    }
  }

  /**
   * Record that an email was sent from this IP
   */
  async recordSend(ipAddress: string, recipientDomain: string): Promise<void> {
    const today = this.getTodayKey();
    const isp = this.ispAwareLimiting ? this.detectISP(recipientDomain) : 'default';
    const hour = this.getHourKey();

    const pipeline = this.redis.pipeline();
    
    // Increment daily counter for IP
    const dailyKey = `${this.keyPrefix}daily:${ipAddress}:${today}`;
    pipeline.incr(dailyKey);
    pipeline.expire(dailyKey, 172800); // 48 hour TTL
    
    // Increment ISP-specific daily counter
    const ispKey = `${this.keyPrefix}isp:${ipAddress}:${isp}:${today}`;
    pipeline.incr(ispKey);
    pipeline.expire(ispKey, 172800);
    
    // Increment hourly counter (for burst protection)
    const hourlyKey = `${this.keyPrefix}hourly:${ipAddress}:${hour}`;
    pipeline.incr(hourlyKey);
    pipeline.expire(hourlyKey, 7200); // 2 hour TTL

    await pipeline.exec();
    
    // Update database asynchronously (non-blocking)
    this.updateDatabaseCounters(ipAddress).catch(err => {
      this.logger.warn('Failed to update database counters', { error: err });
    });
  }

  /**
   * Get warmup status for an IP address
   */
  async getWarmupStatus(ipAddress: string): Promise<IPWarmupStatus> {
    // Check cache first
    const cached = this.warmupCache.get(ipAddress);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.status;
    }

    // Fetch from database
    const client = await this.db.connect();
    try {
      const result = await client.query<{
        ip_address: string;
        warmup_enabled: boolean;
        warmup_started_at: Date | null;
        warmup_day: number;
        daily_limit: number | null;
        daily_sent: number;
      }>(`
        SELECT ip_address, warmup_enabled, warmup_started_at, warmup_day, daily_limit, daily_sent
        FROM ip_pool_addresses
        WHERE ip_address = $1
      `, [ipAddress]);

      let status: IPWarmupStatus;
      const defaultSchedule = this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];

      if (result.rows.length === 0 || !result.rows[0]) {
        // IP not registered - use default warmup from day 0
        status = {
          ipAddress,
          warmupDay: 0,
          warmupStartedAt: null,
          dailyLimit: defaultSchedule[0] ?? DEFAULT_INITIAL_LIMIT,
          dailySent: await this.getDailySentCount(ipAddress),
          isWarmedUp: false,
          ispLimits: {},
        };
      } else {
        const row = result.rows[0];
        const warmupDay = row.warmup_started_at 
          ? this.calculateWarmupDay(row.warmup_started_at)
          : row.warmup_day;
        
        // Get daily limit from database or calculate from schedule
        const scheduledLimit = defaultSchedule[warmupDay] ?? defaultSchedule[defaultSchedule.length - 1];
        const dailyLimit = row.daily_limit ?? scheduledLimit ?? DEFAULT_INITIAL_LIMIT;
        
        status = {
          ipAddress,
          warmupDay,
          warmupStartedAt: row.warmup_started_at,
          dailyLimit,
          dailySent: row.daily_sent || await this.getDailySentCount(ipAddress),
          isWarmedUp: warmupDay >= defaultSchedule.length,
          ispLimits: {},
        };
      }

      // Cache the result
      this.warmupCache.set(ipAddress, {
        status,
        expiresAt: Date.now() + this.cacheTtlMs,
      });

      return status;
    } finally {
      client.release();
    }
  }

  /**
   * Register a new IP for warmup
   */
  async registerIP(
    ipAddress: string,
    poolId: string,
    options?: { hostname?: string; startWarmup?: boolean }
  ): Promise<void> {
    const client = await this.db.connect();
    const defaultSchedule = this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];
    const initialLimit = defaultSchedule[0] ?? DEFAULT_INITIAL_LIMIT;
    
    try {
      await client.query(`
        INSERT INTO ip_pool_addresses (id, pool_id, ip_address, hostname, warmup_enabled, warmup_started_at, warmup_day, daily_limit, daily_sent, status)
        VALUES ($1, $2, $3, $4, true, $5, 0, $6, 0, 'active')
        ON CONFLICT (ip_address) DO UPDATE SET
          pool_id = EXCLUDED.pool_id,
          hostname = COALESCE(EXCLUDED.hostname, ip_pool_addresses.hostname),
          updated_at = NOW()
      `, [
        this.generateId(),
        poolId,
        ipAddress,
        options?.hostname ?? null,
        options?.startWarmup ? new Date() : null,
        initialLimit,
      ]);
      
      // Invalidate cache
      this.warmupCache.delete(ipAddress);
      
      this.logger.info('IP registered for warmup', { 
        ipAddress, 
        poolId, 
        initialLimit,
      });
    } finally {
      client.release();
    }
  }

  /**
   * Start warmup for an existing IP
   */
  async startWarmup(ipAddress: string): Promise<void> {
    const client = await this.db.connect();
    const defaultSchedule = this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];
    const initialLimit = defaultSchedule[0] ?? DEFAULT_INITIAL_LIMIT;
    
    try {
      await client.query(`
        UPDATE ip_pool_addresses
        SET warmup_started_at = NOW(),
            warmup_day = 0,
            daily_limit = $2,
            daily_sent = 0,
            updated_at = NOW()
        WHERE ip_address = $1
      `, [ipAddress, initialLimit]);
      
      // Invalidate cache
      this.warmupCache.delete(ipAddress);
      
      this.logger.info('IP warmup started', { ipAddress, initialLimit });
    } finally {
      client.release();
    }
  }

  /**
   * Advance warmup day for an IP (called by scheduled job)
   */
  async advanceWarmupDay(ipAddress: string): Promise<void> {
    const client = await this.db.connect();
    try {
      const status = await this.getWarmupStatus(ipAddress);
      const newDay = status.warmupDay + 1;
      const defaultSchedule = this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];
      const newLimit = defaultSchedule[newDay] ?? defaultSchedule[defaultSchedule.length - 1] ?? DEFAULT_INITIAL_LIMIT;

      await client.query(`
        UPDATE ip_pool_addresses
        SET warmup_day = $2,
            daily_limit = $3,
            daily_sent = 0,
            last_reset_at = CURRENT_DATE,
            updated_at = NOW()
        WHERE ip_address = $1
      `, [ipAddress, newDay, newLimit]);
      
      // Invalidate cache
      this.warmupCache.delete(ipAddress);
      
      this.logger.info('IP warmup advanced', { ipAddress, newDay, newLimit });
    } finally {
      client.release();
    }
  }

  /**
   * Get statistics for all IPs
   */
  async getIPStatistics(): Promise<Array<IPWarmupStatus & { poolId: string }>> {
    const client = await this.db.connect();
    try {
      const result = await client.query<{
        pool_id: string;
        ip_address: string;
        warmup_enabled: boolean;
        warmup_started_at: Date | null;
        warmup_day: number;
        daily_limit: number;
        daily_sent: number;
      }>(`
        SELECT pool_id, ip_address, warmup_enabled, warmup_started_at, warmup_day, daily_limit, daily_sent
        FROM ip_pool_addresses
        WHERE status = 'active'
        ORDER BY warmup_day DESC, daily_sent DESC
      `);

      const defaultSchedule = this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];
      
      return result.rows.map(row => ({
        poolId: row.pool_id,
        ipAddress: row.ip_address,
        warmupDay: row.warmup_day,
        warmupStartedAt: row.warmup_started_at,
        dailyLimit: row.daily_limit,
        dailySent: row.daily_sent,
        isWarmedUp: row.warmup_day >= defaultSchedule.length,
        ispLimits: {},
      }));
    } finally {
      client.release();
    }
  }

  // === Private Methods ===

  private async checkHourlyLimit(ipAddress: string): Promise<RateLimitResult> {
    const hour = this.getHourKey();
    const key = `${this.keyPrefix}hourly:${ipAddress}:${hour}`;
    
    const count = await this.redis.get(key);
    const currentCount = parseInt(count || '0', 10);
    
    if (currentCount >= this.globalHourlyLimit) {
      return {
        allowed: false,
        reason: `IP ${ipAddress} has reached hourly limit`,
        currentCount,
        limit: this.globalHourlyLimit,
        retryAfter: this.secondsUntilNextHour(),
      };
    }
    
    return { allowed: true, currentCount, limit: this.globalHourlyLimit };
  }

  private async getDailySentCount(ipAddress: string): Promise<number> {
    const today = this.getTodayKey();
    const key = `${this.keyPrefix}daily:${ipAddress}:${today}`;
    const count = await this.redis.get(key);
    return parseInt(count || '0', 10);
  }

  private async getISPSentCount(ipAddress: string, isp: string): Promise<number> {
    const today = this.getTodayKey();
    const key = `${this.keyPrefix}isp:${ipAddress}:${isp}:${today}`;
    const count = await this.redis.get(key);
    return parseInt(count || '0', 10);
  }

  private getISPDailyLimit(isp: string, warmupDay: number): number {
    const schedule = this.ispSchedules[isp] ?? this.ispSchedules['default'] ?? [DEFAULT_INITIAL_LIMIT];
    return schedule[warmupDay] ?? schedule[schedule.length - 1] ?? DEFAULT_INITIAL_LIMIT;
  }

  private detectISP(domain: string): string {
    // Check cache
    const cached = this.mxCache.get(domain);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.isp;
    }

    // For common domains, use direct mapping
    const directMapping = this.getDirectISPMapping(domain);
    if (directMapping) {
      this.mxCache.set(domain, { isp: directMapping, expiresAt: Date.now() + this.mxCacheTtlMs });
      return directMapping;
    }

    // For unknown domains, return default
    const isp = 'default';
    this.mxCache.set(domain, { isp, expiresAt: Date.now() + this.mxCacheTtlMs });
    return isp;
  }

  private getDirectISPMapping(domain: string): string | null {
    const domainLower = domain.toLowerCase();
    
    // Gmail
    if (domainLower === 'gmail.com' || domainLower === 'googlemail.com' || 
        domainLower.endsWith('.google.com')) {
      return 'gmail';
    }
    
    // Microsoft
    if (domainLower === 'outlook.com' || domainLower === 'hotmail.com' || 
        domainLower === 'live.com' || domainLower === 'msn.com' ||
        domainLower.endsWith('.outlook.com')) {
      return 'microsoft';
    }
    
    // Yahoo/AOL
    if (domainLower === 'yahoo.com' || domainLower === 'aol.com' ||
        domainLower.endsWith('.yahoo.com') || domainLower.endsWith('.aol.com')) {
      return 'yahoo';
    }
    
    // Apple
    if (domainLower === 'icloud.com' || domainLower === 'me.com' ||
        domainLower.endsWith('.apple.com')) {
      return 'apple';
    }
    
    return null;
  }

  private async updateDatabaseCounters(ipAddress: string): Promise<void> {
    const dailySent = await this.getDailySentCount(ipAddress);
    const today = new Date().toISOString().split('T')[0] ?? new Date().toISOString().substring(0, 10);
    
    await this.db.query(`
      UPDATE ip_pool_addresses
      SET daily_sent = $2,
          last_reset_at = $3,
          updated_at = NOW()
      WHERE ip_address = $1
    `, [ipAddress, dailySent, today]);
  }

  private calculateWarmupDay(startDate: Date): number {
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - startDate.getTime());
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  }

  private getTodayKey(): string {
    const isoString = new Date().toISOString();
    return isoString.split('T')[0] ?? isoString.substring(0, 10);
  }

  private getHourKey(): string {
    const now = new Date();
    const date = now.toISOString().split('T')[0] ?? now.toISOString().substring(0, 10);
    return `${date}-${now.getUTCHours()}`;
  }

  private secondsUntilMidnightUTC(): number {
    const now = new Date();
    const midnight = new Date(now);
    midnight.setUTCDate(midnight.getUTCDate() + 1);
    midnight.setUTCHours(0, 0, 0, 0);
    return Math.ceil((midnight.getTime() - now.getTime()) / 1000);
  }

  private secondsUntilNextHour(): number {
    const now = new Date();
    const nextHour = new Date(now);
    nextHour.setUTCHours(nextHour.getUTCHours() + 1, 0, 0, 0);
    return Math.ceil((nextHour.getTime() - now.getTime()) / 1000);
  }

  private generateId(): string {
    // Generate ULID-like ID
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 12);
    return `${timestamp}${random}`.substring(0, 26);
  }
}
