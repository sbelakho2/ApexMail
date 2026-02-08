/**
 * Rate Limiting Service
 * 
 * Per-tenant rate limiting:
 * - Sliding window rate limiting
 * - Token bucket algorithm
 * - Quota enforcement
 * - Burst handling
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { QuotaConfig } from '../config.js';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  burstLimit?: number;
  keyPrefix?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfter?: number;
  limit: number;
}

export interface TokenBucketConfig {
  capacity: number;
  refillRate: number;
  refillIntervalMs: number;
}

export class RateLimitService {
  private redis: Redis;

  constructor(redis: Redis) {
    this.redis = redis;
  }

  /**
   * Check rate limit using sliding window algorithm
   */
  async checkRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<Result<RateLimitResult>> {
    const now = Date.now();
    const windowStart = now - config.windowMs;
    const fullKey = `${config.keyPrefix || 'ratelimit'}:${key}`;
    const requestId = `${now}:${Math.random().toString(36).substring(2)}`;

    try {
      // Use Redis sorted set for sliding window
      const multi = this.redis.multi();

      // Remove old entries
      multi.zremrangebyscore(fullKey, '-inf', windowStart);

      // Count current requests in window
      multi.zcard(fullKey);

      // Add current request with stable ID
      multi.zadd(fullKey, now, requestId);

      // Set expiry
      multi.pexpire(fullKey, config.windowMs);

      const results = await multi.exec();
      
      if (!results) {
        return { ok: false, error: new Error('Redis transaction failed') };
      }

      const currentCount = (results[1]?.[1] as number) || 0;
      const allowed = currentCount < config.maxRequests;
      const remaining = Math.max(0, config.maxRequests - currentCount - 1);

      const resetAt = new Date(now + config.windowMs);
      const retryAfter = allowed ? undefined : Math.ceil((config.windowMs - (now - windowStart)) / 1000);

      if (!allowed) {
        // Remove the request we just added using the same requestId
        await this.redis.zrem(fullKey, requestId);
      }

      return {
        ok: true,
        value: {
          allowed,
          remaining,
          resetAt,
          retryAfter,
          limit: config.maxRequests,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Check rate limit using token bucket algorithm
   *
   * FIX-500-421: This implementation uses separate HGETALL → compute → HSET
   * which is a classic TOCTOU race. Between the read and write, another request
   * can read stale data and double-count tokens. This should be converted to a
   * Lua script for atomicity, similar to the sliding-window approach above that
   * already uses MULTI. TODO: Migrate to atomic Lua script.
   */
  async checkTokenBucket(
    key: string,
    config: TokenBucketConfig,
    tokensRequested: number = 1
  ): Promise<Result<RateLimitResult>> {
    const fullKey = `tokenbucket:${key}`;
    const now = Date.now();

    try {
      // Get current bucket state
      const bucketData = await this.redis.hgetall(fullKey);

      let tokens = config.capacity;
      let lastRefill = now;

      if (bucketData.tokens) {
        tokens = parseFloat(bucketData.tokens);
        lastRefill = parseInt(bucketData.lastRefill ?? String(now));

        // Calculate tokens to add since last refill
        const timePassed = now - lastRefill;
        const tokensToAdd = (timePassed / config.refillIntervalMs) * config.refillRate;
        tokens = Math.min(config.capacity, tokens + tokensToAdd);
      }

      const allowed = tokens >= tokensRequested;
      
      if (allowed) {
        tokens -= tokensRequested;
      }

      // Update bucket
      await this.redis.hset(fullKey, {
        tokens: tokens.toString(),
        lastRefill: now.toString(),
      });
      await this.redis.pexpire(fullKey, config.refillIntervalMs * 10);

      // Calculate when tokens will be available
      let retryAfter: number | undefined;
      if (!allowed) {
        const tokensNeeded = tokensRequested - tokens;
        retryAfter = Math.ceil((tokensNeeded / config.refillRate) * (config.refillIntervalMs / 1000));
      }

      return {
        ok: true,
        value: {
          allowed,
          remaining: Math.floor(tokens),
          resetAt: new Date(now + config.refillIntervalMs),
          retryAfter,
          limit: config.capacity,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Check workspace quota
   */
  async checkWorkspaceQuota(
    workspaceId: string,
    metric: keyof QuotaConfig,
    quota: QuotaConfig,
    _increment: number = 1
  ): Promise<Result<RateLimitResult>> {
    const limit = quota[metric];
    const key = `quota:${workspaceId}:${metric}`;

    // Determine window based on metric
    let windowMs: number;
    switch (metric) {
      case 'apiRequestsPerMinute':
        windowMs = 60 * 1000;
        break;
      case 'emailsPerMonth':
      case 'webhooksPerMonth':
        windowMs = 30 * 24 * 60 * 60 * 1000;
        break;
      default:
        // Non-time-based limits (e.g., contacts, templates)
        return this.checkResourceLimit(workspaceId, metric, limit);
    }

    return this.checkRateLimit(key, {
      windowMs,
      maxRequests: limit,
    });
  }

  /**
   * Check non-time-based resource limit
   */
  private async checkResourceLimit(
    workspaceId: string,
    metric: string,
    limit: number
  ): Promise<Result<RateLimitResult>> {
    const key = `resource:${workspaceId}:${metric}`;

    try {
      const current = await this.redis.get(key);
      const currentCount = current ? parseInt(current) : 0;

      const allowed = currentCount < limit;

      return {
        ok: true,
        value: {
          allowed,
          remaining: Math.max(0, limit - currentCount),
          resetAt: new Date(Date.now() + 86400000), // 24 hours
          limit,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Increment resource counter
   */
  async incrementResourceCount(workspaceId: string, metric: string, amount: number = 1): Promise<Result<number>> {
    const key = `resource:${workspaceId}:${metric}`;

    try {
      const newValue = await this.redis.incrby(key, amount);
      return { ok: true, value: newValue };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Decrement resource counter
   */
  async decrementResourceCount(workspaceId: string, metric: string, amount: number = 1): Promise<Result<number>> {
    const key = `resource:${workspaceId}:${metric}`;

    try {
      const newValue = await this.redis.decrby(key, amount);
      const finalValue = Math.max(0, newValue);
      
      if (finalValue !== newValue) {
        await this.redis.set(key, finalValue);
      }

      return { ok: true, value: finalValue };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Set resource count (for sync with database)
   */
  async setResourceCount(workspaceId: string, metric: string, count: number): Promise<Result<void>> {
    const key = `resource:${workspaceId}:${metric}`;

    try {
      await this.redis.set(key, count);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get current rate limit status
   */
  async getRateLimitStatus(
    key: string,
    config: RateLimitConfig
  ): Promise<Result<RateLimitResult>> {
    const now = Date.now();
    const windowStart = now - config.windowMs;
    const fullKey = `${config.keyPrefix || 'ratelimit'}:${key}`;

    try {
      // Remove old entries and count
      await this.redis.zremrangebyscore(fullKey, '-inf', windowStart);
      const currentCount = await this.redis.zcard(fullKey);

      return {
        ok: true,
        value: {
          allowed: currentCount < config.maxRequests,
          remaining: Math.max(0, config.maxRequests - currentCount),
          resetAt: new Date(now + config.windowMs),
          limit: config.maxRequests,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Reset rate limit for a key
   */
  async resetRateLimit(key: string, keyPrefix: string = 'ratelimit'): Promise<Result<void>> {
    const fullKey = `${keyPrefix}:${key}`;

    try {
      await this.redis.del(fullKey);
      return { ok: true, value: undefined };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Create rate limiter middleware config for a workspace
   */
  getWorkspaceRateLimitConfigs(quota: QuotaConfig): Record<string, RateLimitConfig> {
    return {
      api: {
        windowMs: 60 * 1000,
        maxRequests: quota.apiRequestsPerMinute,
        keyPrefix: 'ratelimit:api',
        burstLimit: Math.ceil(quota.apiRequestsPerMinute * 0.1),
      },
      email: {
        windowMs: 30 * 24 * 60 * 60 * 1000, // 30 days
        maxRequests: quota.emailsPerMonth,
        keyPrefix: 'ratelimit:email',
      },
      webhook: {
        windowMs: 30 * 24 * 60 * 60 * 1000,
        maxRequests: quota.webhooksPerMonth,
        keyPrefix: 'ratelimit:webhook',
      },
    };
  }

  /**
   * Distributed rate limiting across multiple instances
   */
  async checkDistributedRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<Result<RateLimitResult>> {
    // Use Lua script for atomic operation
    const luaScript = `
      local key = KEYS[1]
      local now = tonumber(ARGV[1])
      local window = tonumber(ARGV[2])
      local limit = tonumber(ARGV[3])
      
      local windowStart = now - window
      
      -- Remove old entries
      redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
      
      -- Count current entries
      local count = redis.call('ZCARD', key)
      
      if count < limit then
        -- Add new entry
        redis.call('ZADD', key, now, now .. ':' .. math.random())
        redis.call('PEXPIRE', key, window)
        return {1, limit - count - 1}
      else
        return {0, 0}
      end
    `;

    const now = Date.now();
    const fullKey = `${config.keyPrefix || 'ratelimit'}:${key}`;

    try {
      const result = await this.redis.eval(
        luaScript,
        1,
        fullKey,
        now,
        config.windowMs,
        config.maxRequests
      ) as [number, number];

      const allowed = result[0] === 1;
      const remaining = result[1];

      return {
        ok: true,
        value: {
          allowed,
          remaining,
          resetAt: new Date(now + config.windowMs),
          retryAfter: allowed ? undefined : Math.ceil(config.windowMs / 1000),
          limit: config.maxRequests,
        },
      };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }
}
