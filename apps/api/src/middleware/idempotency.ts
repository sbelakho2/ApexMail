/**
 * Idempotency Middleware
 * Ensures that requests with the same idempotency key return the same response
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { createCache } from '@apexmail/lib/cache';
import { ApiError } from './error-handler.js';
import crypto from 'crypto';

interface IdempotentResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  createdAt: number;
  fingerprint: string;
}

export function idempotencyMiddleware(ctx: AppContext): MiddlewareHandler<AppEnv> {
  let cache: ReturnType<typeof createCache> | null = null;

  const getCache = async () => {
    if (!cache) {
      cache = createCache({
        type: 'redis',
        prefix: 'apexmail:idempotency:',
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
    // Only apply to mutation methods
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method)) {
      return next();
    }

    const idempotencyKey = c.req.header('X-Idempotency-Key');
    
    // Idempotency key is optional but recommended for mutations
    if (!idempotencyKey) {
      return next();
    }

    // Validate idempotency key format (should be a UUID or similar)
    if (idempotencyKey.length > 64 || !/^[a-zA-Z0-9_-]+$/.test(idempotencyKey)) {
      throw ApiError.badRequest(
        'Invalid idempotency key format. Must be alphanumeric with - and _ allowed, max 64 characters.',
        'INVALID_IDEMPOTENCY_KEY'
      );
    }

    const tenantId = c.get('tenantId');
    const logger = c.get('logger');
    const redisCache = await getCache();

    // Create a cache key combining tenant, endpoint, and idempotency key
    const cacheKey = `idempotency:${tenantId}:${c.req.path}:${idempotencyKey}`;
    
    // Create request fingerprint (hash of request body)
    const bodyText = await c.req.text();
    const fingerprint = crypto
      .createHash('sha256')
      .update(bodyText)
      .digest('hex');

    // Check for existing response
    const existing = await redisCache.get<IdempotentResponse>(cacheKey);

    if (existing) {
      // Verify request fingerprint matches
      if (existing.fingerprint !== fingerprint) {
        logger.warn('Idempotency key reused with different request body', {
          idempotencyKey,
          originalFingerprint: existing.fingerprint,
          newFingerprint: fingerprint,
        });

        throw ApiError.conflict(
          'Idempotency key has already been used with a different request body',
          'IDEMPOTENCY_KEY_MISMATCH'
        );
      }

      logger.info('Returning idempotent response', {
        idempotencyKey,
        originalCreatedAt: existing.createdAt,
      });

      // Restore headers
      for (const [key, value] of Object.entries(existing.headers)) {
        c.header(key, value);
      }
      c.header('X-Idempotent-Replayed', 'true');

      // Return cached response
      return c.body(existing.body, existing.status as 200);
    }

    // Lock to prevent concurrent requests with same idempotency key
    // SECURITY FIX: Use atomic SETNX operation to prevent TOCTOU race condition
    const lockKey = `${cacheKey}:lock`;
    const lockAcquired = await redisCache.setNX(lockKey, { locked: true, timestamp: Date.now() }, { ttlSeconds: 60 });

    if (!lockAcquired) {
      throw ApiError.conflict(
        'A request with this idempotency key is currently being processed',
        'IDEMPOTENCY_KEY_IN_PROGRESS'
      );
    }

    try {
      // Reconstruct request body for downstream handlers
      // Store body in context for handlers to access
      (c.req as { _body?: string })._body = bodyText;

      // Process the request
      await next();

      // Capture the response
      const response = c.res;
      const responseBody = await response.clone().text();
      const responseHeaders: Record<string, string> = {};
      
      response.headers.forEach((value, key) => {
        // Only cache safe headers
        if (!['set-cookie', 'x-idempotent-replayed'].includes(key.toLowerCase())) {
          responseHeaders[key] = value;
        }
      });

      // Only cache successful responses (2xx and 4xx client errors)
      if (response.status < 500) {
        const idempotentResponse: IdempotentResponse = {
          status: response.status,
          headers: responseHeaders,
          body: responseBody,
          createdAt: Date.now(),
          fingerprint,
        };

        // Store response
        await redisCache.set(cacheKey, idempotentResponse, { ttlSeconds: ctx.config.idempotency.ttlSeconds });
        
        logger.info('Stored idempotent response', {
          idempotencyKey,
          status: response.status,
        });
      }
    } catch (error) {
      // FIX: Properly catch and re-throw errors to ensure lock is released
      logger.error('Idempotent request failed', {
        idempotencyKey,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      // Release lock
      await redisCache.delete(lockKey);
    }
  };
}

/**
 * Generate an idempotency key from request data
 * Useful for auto-generating keys based on request content
 */
export function generateIdempotencyKey(data: Record<string, unknown>): string {
  const normalized = JSON.stringify(data, Object.keys(data).sort());
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 32);
}
