/**
 * Rate Limiter Middleware using Redis
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { createCache } from '@apexmail/lib/cache';
import { ApiError } from './error-handler.js';

interface RateLimitState {
  count: number;
  resetAt: number;
}

export function rateLimiter(ctx: AppContext): MiddlewareHandler<AppEnv> {
  let cache: ReturnType<typeof createCache> | null = null;

  const getCache = async () => {
    if (!cache) {
      cache = createCache({
        host: ctx.config.redis.host,
        port: ctx.config.redis.port,
        password: ctx.config.redis.password,
        db: ctx.config.redis.db,
      });
    }
    return cache;
  };

  return async (c, next) => {
    const tenantId = c.get('tenantId');
    const apiKeyId = c.get('apiKeyId');
    const logger = c.get('logger');

    // Determine the rate limit key
    const limitKey = apiKeyId
      ? `ratelimit:apikey:${apiKeyId}`
      : `ratelimit:tenant:${tenantId}`;

    const windowMs = ctx.config.rateLimit.windowMs;
    const maxRequests = ctx.config.rateLimit.maxRequests;

    try {
      const redisCache = await getCache();
      const now = Date.now();
      const windowStart = Math.floor(now / windowMs) * windowMs;
      const windowEnd = windowStart + windowMs;
      const key = `${limitKey}:${windowStart}`;

      // Get current count
      const currentResult = await redisCache.get<RateLimitState>(key);
      const current = currentResult.ok ? currentResult.value : null;

      let count: number;
      if (current) {
        count = current.count + 1;
      } else {
        count = 1;
      }

      // Update count
      await redisCache.set(key, { count, resetAt: windowEnd }, Math.ceil(windowMs / 1000) + 1);

      // Set rate limit headers
      const remaining = Math.max(0, maxRequests - count);
      c.header('X-RateLimit-Limit', String(maxRequests));
      c.header('X-RateLimit-Remaining', String(remaining));
      c.header('X-RateLimit-Reset', String(Math.floor(windowEnd / 1000)));

      // Check if over limit
      if (count > maxRequests) {
        const retryAfter = Math.ceil((windowEnd - now) / 1000);
        c.header('Retry-After', String(retryAfter));

        logger.warn('Rate limit exceeded', {
          key: limitKey,
          count,
          maxRequests,
          retryAfter,
        });

        throw ApiError.tooManyRequests(
          `Rate limit exceeded. Retry after ${retryAfter} seconds.`,
          'RATE_LIMIT_EXCEEDED'
        );
      }

      return next();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      // On Redis errors, log and allow the request (fail open)
      logger.error('Rate limiter error', { error });
      return next();
    }
  };
}

/**
 * More sophisticated sliding window rate limiter for high-precision limiting
 */
export function slidingWindowRateLimiter(ctx: AppContext): MiddlewareHandler<AppEnv> {
  let cache: ReturnType<typeof createCache> | null = null;

  const getCache = async () => {
    if (!cache) {
      cache = createCache({
        host: ctx.config.redis.host,
        port: ctx.config.redis.port,
        password: ctx.config.redis.password,
        db: ctx.config.redis.db,
      });
    }
    return cache;
  };

  return async (c, next) => {
    const tenantId = c.get('tenantId');
    const apiKeyId = c.get('apiKeyId');
    const logger = c.get('logger');

    const limitKey = apiKeyId
      ? `ratelimit:sw:apikey:${apiKeyId}`
      : `ratelimit:sw:tenant:${tenantId}`;

    const windowMs = ctx.config.rateLimit.windowMs;
    const maxRequests = ctx.config.rateLimit.maxRequests;

    try {
      const redisCache = await getCache();
      const now = Date.now();
      const windowStart = now - windowMs;

      // Use sorted set for sliding window
      // This is a simplified implementation - in production you'd use Redis commands directly
      const key = limitKey;
      
      // For this implementation, we'll use a simpler fixed window approach
      // that approximates sliding window behavior
      const currentWindow = Math.floor(now / windowMs);
      const previousWindow = currentWindow - 1;
      
      const currentKey = `${key}:${currentWindow}`;
      const previousKey = `${key}:${previousWindow}`;

      const [currentCountResult, previousCountResult] = await Promise.all([
        redisCache.get<{ count: number }>(currentKey),
        redisCache.get<{ count: number }>(previousKey),
      ]);

      const currentCount = (currentCountResult.ok ? currentCountResult.value?.count : 0) ?? 0;
      const previousCount = (previousCountResult.ok ? previousCountResult.value?.count : 0) ?? 0;

      // Calculate weighted count based on time into current window
      const windowProgress = (now % windowMs) / windowMs;
      const weightedPreviousCount = previousCount * (1 - windowProgress);
      const totalCount = currentCount + weightedPreviousCount;

      // Update current window count
      await redisCache.set(currentKey, { count: currentCount + 1 }, Math.ceil(windowMs * 2 / 1000));

      // Set headers
      const remaining = Math.max(0, Math.floor(maxRequests - totalCount));
      const resetAt = (currentWindow + 1) * windowMs;
      
      c.header('X-RateLimit-Limit', String(maxRequests));
      c.header('X-RateLimit-Remaining', String(remaining));
      c.header('X-RateLimit-Reset', String(Math.floor(resetAt / 1000)));

      if (totalCount >= maxRequests) {
        const retryAfter = Math.ceil((resetAt - now) / 1000);
        c.header('Retry-After', String(retryAfter));

        logger.warn('Sliding window rate limit exceeded', {
          key: limitKey,
          totalCount: Math.ceil(totalCount),
          maxRequests,
        });

        throw ApiError.tooManyRequests(
          `Rate limit exceeded. Try again later.`,
          'RATE_LIMIT_EXCEEDED'
        );
      }

      return next();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      logger.error('Sliding window rate limiter error', { error });
      return next();
    }
  };
}
