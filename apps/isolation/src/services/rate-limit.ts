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
   */
  async checkTokenBucket(
    key: string,
    config: TokenBucketConfig,
    tokensRequested: number = 1
  ): Promise<Result<RateLimitResult>> {
    const fullKey = `tokenbucket:${key}`;
    const now = Date.now();

    try {
      const script = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refillRate = tonumber(ARGV[3])
local refillIntervalMs = tonumber(ARGV[4])
local tokensRequested = tonumber(ARGV[5])
local ttlMs = tonumber(ARGV[6])

local data = redis.call('HGETALL', key)
local bucket = {}
for i = 1, #data, 2 do
  bucket[data[i]] = data[i + 1]
end

local tokens = capacity
local lastRefill = now

if bucket['tokens'] then
  tokens = tonumber(bucket['tokens']) or capacity
  lastRefill = tonumber(bucket['lastRefill']) or now
  local timePassed = now - lastRefill
  local tokensToAdd = (timePassed / refillIntervalMs) * refillRate
  tokens = math.min(capacity, tokens + tokensToAdd)
end

local allowed = 0
if tokens >= tokensRequested then
  allowed = 1
  tokens = tokens - tokensRequested
end

redis.call('HSET', key, 'tokens', tostring(tokens), 'lastRefill', tostring(now))
redis.call('PEXPIRE', key, ttlMs)

local retryAfter = -1
if allowed == 0 then
  local tokensNeeded = tokensRequested - tokens
  retryAfter = math.ceil((tokensNeeded / refillRate) * (refillIntervalMs / 1000))
end

return { allowed, tostring(tokens), tostring(retryAfter) }
`;

      const raw = await this.redis.eval(
        script,
        1,
        fullKey,
        now.toString(),
        config.capacity.toString(),
        config.refillRate.toString(),
        config.refillIntervalMs.toString(),
        tokensRequested.toString(),
        (config.refillIntervalMs * 10).toString()
      ) as [number | string, string, string] | null;

      if (!raw) {
        return { ok: false, error: new Error('Redis Lua execution failed') };
      }

      const allowed = String(raw[0]) === '1';
      const remainingTokens = Math.max(0, Math.floor(parseFloat(String(raw[1]))));
      const retryAfterRaw = parseInt(String(raw[2]), 10);
      const retryAfter = retryAfterRaw >= 0 ? retryAfterRaw : undefined;

      return {
        ok: true,
        value: {
          allowed,
          remaining: remainingTokens,
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
