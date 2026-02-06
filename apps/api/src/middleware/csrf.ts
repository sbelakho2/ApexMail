/**
 * CSRF Protection Middleware
 * 
 * Protects state-changing requests (POST, PUT, DELETE, PATCH) by requiring
 * a valid X-CSRF-Token header. Tokens are generated via GET /v1/auth/csrf-token.
 * 
 * Requests authenticated via API key are exempt (API keys are already a
 * proof-of-intent mechanism and are used programmatically, not from browsers).
 */

import type { MiddlewareHandler } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { createCache, type CacheProvider } from '@apexmail/lib/cache';
import { secureRandomHex } from '@apexmail/lib/crypto';
import { ApiError } from './error-handler.js';

const CSRF_TOKEN_TTL_SECONDS = 3600; // 1 hour
const CSRF_TOKEN_BYTES = 32;

let csrfCache: CacheProvider | null = null;

function getCsrfCache(ctx: AppContext): CacheProvider {
  if (!csrfCache) {
    csrfCache = createCache({
      type: 'redis',
      prefix: 'apexmail:csrf:',
      redisOptions: {
        host: ctx.config.redis.host,
        port: ctx.config.redis.port,
        password: ctx.config.redis.password,
        db: ctx.config.redis.db,
      },
    });
  }
  return csrfCache;
}

/**
 * Generate a CSRF token for a given session/user and store it in Redis.
 */
export async function generateCsrfToken(ctx: AppContext, sessionId: string): Promise<string> {
  const cache = getCsrfCache(ctx);
  const token = secureRandomHex(CSRF_TOKEN_BYTES);
  const key = `${sessionId}:${token}`;
  await cache.set(key, { valid: true }, { ttlSeconds: CSRF_TOKEN_TTL_SECONDS });
  return token;
}

/**
 * Verify a CSRF token is valid for a given session.
 */
async function verifyCsrfToken(ctx: AppContext, sessionId: string, token: string): Promise<boolean> {
  const cache = getCsrfCache(ctx);
  const key = `${sessionId}:${token}`;
  const result = await cache.get<{ valid: boolean }>(key);
  return result !== null && result.valid === true;
}

/**
 * CSRF protection middleware.
 * 
 * Skips CSRF validation for:
 * - Safe methods (GET, HEAD, OPTIONS)
 * - API key authenticated requests (X-API-Key header present)
 * - Requests with no browser-session context (no JWT)
 */
export function csrfProtection(ctx: AppContext): MiddlewareHandler<AppEnv> {
  const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

  return async (c, next) => {
    // Skip for safe methods
    if (!STATE_CHANGING_METHODS.has(c.req.method)) {
      return next();
    }

    // Skip for API key authenticated requests — they don't use browser sessions
    const apiKeyId = c.get('apiKeyId');
    if (apiKeyId) {
      return next();
    }

    // For JWT-authenticated browser requests, enforce CSRF
    const userId = c.get('userId');
    if (!userId) {
      // No authenticated session, let auth middleware handle it
      return next();
    }

    const csrfToken = c.req.header('X-CSRF-Token');
    if (!csrfToken) {
      throw ApiError.forbidden(
        'Missing CSRF token. Include X-CSRF-Token header for state-changing requests.',
        'CSRF_TOKEN_MISSING'
      );
    }

    const sessionId = `user:${userId}`;
    const isValid = await verifyCsrfToken(ctx, sessionId, csrfToken);
    if (!isValid) {
      throw ApiError.forbidden(
        'Invalid or expired CSRF token. Fetch a new token from GET /v1/auth/csrf-token.',
        'CSRF_TOKEN_INVALID'
      );
    }

    return next();
  };
}
