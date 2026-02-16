/**
 * Rate Limiter Middleware using Redis
 * 
 * SECURITY: Uses atomic Redis INCR operations to prevent TOCTOU race conditions
 * that could allow rate limit bypass under concurrent requests.
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { createCache } from '@apexmail/lib/cache';
import { ApiError } from './error-handler.js';

export function rateLimiter(ctx: AppContext): MiddlewareHandler<AppEnv> {
  let cache: ReturnType<typeof createCache> | null = null;

  const getCache = async () => {
    if (!cache) {
      cache = createCache({
        type: 'redis',
        prefix: 'apexmail:ratelimit:',
        redisOptions: {
          host: ctx.config.redis.host,
          port: ctx.config.redis.port,
          password: ctx.config.redis.password,
          db: ctx.config.redis.db,
        },
      });
    }
    return cache;
  };

  return async (c, next) => {
    const tenantId = c.get('tenantId');
    const apiKeyId = c.get('apiKeyId');
    const logger = c.get('logger');

    // F-206: Rate limit by both tenant/API-key AND IP address.
    // The tenant key prevents a single tenant from monopolising the API.
    // The IP key prevents credential-stuffing or abuse from a single source.
    const tenantLimitKey = apiKeyId
      ? `ratelimit:apikey:${apiKeyId}`
      : `ratelimit:tenant:${tenantId}`;

    const clientIp = c.req.header('X-Validated-Client-IP') || 'unknown';
    const ipLimitKey = `ratelimit:ip:${clientIp}`;

    const windowMs = ctx.config.rateLimit.windowMs;
    const maxRequests = ctx.config.rateLimit.maxRequests;
    // F-206: Per-IP limit is higher than per-tenant to allow shared IPs (NAT)
    const maxRequestsPerIp = Math.floor(maxRequests * 2);

    try {
      const redisCache = await getCache();
      const now = Date.now();
      const windowStart = Math.floor(now / windowMs) * windowMs;
      const windowEnd = windowStart + windowMs;

      // C-132 fallback: use INCR + EXPIRE with shared cache interface
      const ttlSeconds = Math.ceil(windowMs / 1000) + 1;

      const tenantKey = `${tenantLimitKey}:${windowStart}`;
      const ipKey = `${ipLimitKey}:${windowStart}`;

      const [tenantCount, ipCount] = await Promise.all([
        (async () => {
          const count = await redisCache.incr(tenantKey);
          if (count === 1) await redisCache.expire(tenantKey, ttlSeconds);
          return count;
        })(),
        (async () => {
          const count = await redisCache.incr(ipKey);
          if (count === 1) await redisCache.expire(ipKey, ttlSeconds);
          return count;
        })(),
      ]);

      // Use the more restrictive of the two counts for headers
      const count = Math.max(tenantCount, Math.ceil(ipCount * (maxRequests / maxRequestsPerIp)));

      // Set rate limit headers
      const remaining = Math.max(0, maxRequests - count);
      c.header('X-RateLimit-Limit', String(maxRequests));
      c.header('X-RateLimit-Remaining', String(remaining));
      c.header('X-RateLimit-Reset', String(Math.floor(windowEnd / 1000)));

      // Check if either limit is exceeded
      if (tenantCount > maxRequests || ipCount > maxRequestsPerIp) {
        const retryAfter = Math.ceil((windowEnd - now) / 1000);
        c.header('Retry-After', String(retryAfter));

        logger.warn('Rate limit exceeded', {
          tenantKey: tenantLimitKey,
          ipKey: ipLimitKey,
          tenantCount,
          ipCount,
          maxRequests,
          maxRequestsPerIp,
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

      // SECURITY FIX: On Redis errors, fail CLOSED to prevent DDoS during outages
      // This is a defense-in-depth measure to prevent abuse when Redis is unavailable
      logger.error('Rate limiter error - failing closed for security', { error });
      
      // In production, fail closed to prevent abuse
      // In development, allow requests for easier debugging
      if (ctx.config.env === 'production') {
        throw ApiError.serviceUnavailable(
          'Service temporarily unavailable. Please try again later.',
          'RATE_LIMITER_UNAVAILABLE'
        );
      }
      
      // Only fail open in non-production environments
      logger.warn('Rate limiter failing open (non-production environment)');
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
        type: 'redis',
        prefix: 'apexmail:ratelimit:sw:',
        redisOptions: {
          host: ctx.config.redis.host,
          port: ctx.config.redis.port,
          password: ctx.config.redis.password,
          db: ctx.config.redis.db,
        },
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

      // Use sorted set for sliding window
      // This is a simplified implementation - in production you'd use Redis commands directly
      const key = limitKey;
      
      // For this implementation, we'll use a simpler fixed window approach
      // that approximates sliding window behavior
      const currentWindow = Math.floor(now / windowMs);
      const previousWindow = currentWindow - 1;
      
      const currentKey = `${key}:${currentWindow}`;
      const previousKey = `${key}:${previousWindow}`;

      // SECURITY FIX: Get previous count first, then atomically increment current
      // This ensures we don't have a race condition on the current window count
      // IMP-002 FIX: Read as raw number — incr() stores "42" not '{"count":42}'.
      // JSON.parse("42") returns 42 (number), so get<number> is correct here.
      const previousCount = (await redisCache.get<number>(previousKey)) ?? 0;

      const currentCount = await redisCache.incr(currentKey);
      if (currentCount === 1) {
        await redisCache.expire(currentKey, Math.ceil(windowMs * 2 / 1000));
      }

      // Calculate weighted count based on time into current window
      const windowProgress = (now % windowMs) / windowMs;
      const weightedPreviousCount = previousCount * (1 - windowProgress);
      const totalCount = currentCount + weightedPreviousCount;

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

      // SECURITY FIX: On Redis errors, fail CLOSED to prevent DDoS during outages
      logger.error('Sliding window rate limiter error - failing closed for security', { error });
      
      if (ctx.config.env === 'production') {
        throw ApiError.serviceUnavailable(
          'Service temporarily unavailable. Please try again later.',
          'RATE_LIMITER_UNAVAILABLE'
        );
      }
      
      logger.warn('Sliding window rate limiter failing open (non-production environment)');
      return next();
    }
  };
}
