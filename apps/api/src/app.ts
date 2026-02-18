/**
 * Main Hono Application Setup
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { compress } from 'hono/compress';
import { etag } from 'hono/etag';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { prettyJSON } from 'hono/pretty-json';
import { bodyLimit } from 'hono/body-limit';
import { timeout } from 'hono/timeout';
import { HTTPException } from 'hono/http-exception';
import type { Logger } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';
import type { Redis } from 'ioredis';
import type { Config } from './config.js';

import { errorHandler } from './middleware/error-handler.js';
import { requestLogger } from './middleware/request-logger.js';
import { authMiddleware } from './middleware/auth.js';
import { rateLimiter } from './middleware/rate-limiter.js';
import { idempotencyMiddleware } from './middleware/idempotency.js';
import { csrfProtection } from './middleware/csrf.js';
import { trustedProxyMiddleware } from './middleware/trusted-proxy.js';

import { healthRoutes } from './routes/health.js';
import { authRoutes, publicAuthRoutes } from './routes/auth.js';
import { messagesRoutes } from './routes/messages.js';
import { domainsRoutes } from './routes/domains.js';
import { templatesRoutes } from './routes/templates.js';
import { suppressionsRoutes } from './routes/suppressions.js';
import { eventsRoutes } from './routes/events.js';
import { webhooksRoutes } from './routes/webhooks.js';
import { analyticsRoutes } from './routes/analytics.js';
import { supportRoutes } from './routes/support.js';
import { scimRoutes } from './routes/scim.js';
import { campaignsRoutes } from './routes/campaigns.js';
import { contactsRoutes } from './routes/contacts.js';
import { automationsRoutes } from './routes/automations.js';

export interface AppContext {
  db: DatabasePool;
  redis: Redis;
  config: Config;
  logger: Logger;
}

export type AppEnv = {
  Variables: {
    tenantId: string;
    userId: string | null;
    apiKeyId: string | null;
    requestId: string;
    logger: Logger;
    scopes: string[];
  };
};

export function createApp(ctx: AppContext): Hono<AppEnv> {
  const app = new Hono<AppEnv>();

  // Global middleware
  app.use('*', timing());
  app.use('*', compress());

  /**
   * F-242: ETag support for GET responses.
   * Allows clients to use conditional requests (If-None-Match) to avoid
   * re-downloading unchanged resources, reducing bandwidth and latency.
   * Uses weak ETags by default which is appropriate for API responses.
   */
  app.use('*', etag());

  app.use('*', secureHeaders());

  /**
   * G-224: Request timeout middleware.
   * Terminates any request handler that hangs for longer than 30 seconds,
   * returning a 504 Gateway Timeout. Prevents a single slow query or
   * downstream call from holding a connection open indefinitely.
   */
  app.use('*', timeout(30_000, () => {
    throw new HTTPException(504, {
      message: JSON.stringify({
        error: {
          code: 'REQUEST_TIMEOUT',
          message: 'Request timed out after 30 seconds',
        },
      }),
    });
  }));

  /**
   * E-178: Route-specific request body size enforcement.
   * - Default (all routes): 10 MB — accommodates large JSON payloads
   *   (batch sends, template content, analytics queries).
   * - File upload routes: 25 MB — handled separately below.
   */
  app.use('*', bodyLimit({
    maxSize: 10 * 1024 * 1024, // 10 MB
    onError: (c) => {
      return c.json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request body exceeds the maximum allowed size of 10MB',
        },
      }, 413);
    },
  }));

  // E-178: Higher limit for file upload endpoints (attachments, imports)
  app.use('/v1/messages/*/attachments', bodyLimit({
    maxSize: 25 * 1024 * 1024, // 25 MB
    onError: (c) => {
      return c.json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'File upload exceeds the maximum allowed size of 25MB',
        },
      }, 413);
    },
  }));
  app.use('/v1/domains/*/import', bodyLimit({
    maxSize: 25 * 1024 * 1024, // 25 MB
    onError: (c) => {
      return c.json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'File upload exceeds the maximum allowed size of 25MB',
        },
      }, 413);
    },
  }));

  app.use('*', prettyJSON());

  // F-217: Sanitize request bodies — reject null bytes (\u0000) which cause
  // errors in PostgreSQL text/varchar columns and can be used for injection.
  // FIX-500-004: Clone the request before reading to avoid consuming the body
  // stream. Previously `c.req.text()` consumed it, causing downstream
  // `c.req.json()` to fail with an empty-body error on valid POST/PUT/PATCH.
  app.use('*', async (c, next) => {
    const contentType = c.req.header('content-type') ?? '';
    if (
      (c.req.method === 'POST' || c.req.method === 'PUT' || c.req.method === 'PATCH') &&
      contentType.includes('application/json')
    ) {
      const rawBody = await c.req.raw.clone().text();
      if (rawBody.includes('\u0000')) {
        return c.json({ error: 'Request body contains invalid null bytes' }, 400);
      }
    }
    return next();
  });

  // Additional security headers not covered by secureHeaders()
  app.use('*', async (c, next) => {
    await next();
    // F-231: Communicate API version via response header
    c.header('X-API-Version', '2024-01-01');
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    c.header('X-Frame-Options', 'DENY');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    c.header('X-XSS-Protection', '0');
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    // F-208: Content-Security-Policy — API returns JSON, not HTML.
    // A strict CSP prevents XSS if API responses are ever rendered in a browser.
    c.header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  });
  
  app.use('*', cors({
    origin: ctx.config.cors.origins,
    credentials: ctx.config.cors.credentials,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Idempotency-Key', 'X-Request-ID', 'X-CSRF-Token'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-API-Version', 'Deprecation', 'Sunset'],
    // F-232: Deprecation header utility — attach to individual routes to signal deprecation.
    // Usage: c.header('Deprecation', 'true'); c.header('Sunset', 'Sat, 01 Mar 2025 00:00:00 GMT');
    maxAge: 86400,
  }));

  // Trusted proxy validation (must be before request logger to validate IPs)
  app.use('*', trustedProxyMiddleware(ctx));

  // Request logging
  app.use('*', requestLogger(ctx.logger));

  // Error handling
  app.onError(errorHandler(ctx.logger));

  // Health check (no auth)
  app.route('/health', healthRoutes(ctx));

  // Auth login route MUST be outside auth middleware (users need to obtain JWT)
  // Rate limit login separately to prevent brute-force
  // FIX-500-162: Only /login is public; /me, /api-keys, /logout, /refresh are authenticated
  const publicAuth = new Hono<AppEnv>();
  publicAuth.use('*', rateLimiter(ctx));
  publicAuth.route('/auth', publicAuthRoutes(ctx));
  app.route('/v1', publicAuth);

  // API routes with authentication
  const api = new Hono<AppEnv>();

  // Auth middleware for API routes
  api.use('*', authMiddleware(ctx));
  
  // CSRF protection for state-changing requests (after auth, so we have userId)
  api.use('*', csrfProtection(ctx));
  
  // Rate limiting
  api.use('*', rateLimiter(ctx));

  // Idempotency for mutation endpoints
  // FIX-500-487: Apply to all mutation-capable routes, not just /messages
  api.use('/messages/*', idempotencyMiddleware(ctx));
  api.use('/domains/*', idempotencyMiddleware(ctx));
  api.use('/templates/*', idempotencyMiddleware(ctx));
  api.use('/suppressions/*', idempotencyMiddleware(ctx));

  // Mount API routes (auth routes excluded — mounted above without auth)
  api.route('/auth', authRoutes(ctx)); // FIX-500-162: Authenticated auth routes (/me, /api-keys, /logout, /refresh)
  api.route('/messages', messagesRoutes(ctx));
  api.route('/domains', domainsRoutes(ctx));
  api.route('/templates', templatesRoutes(ctx));
  api.route('/suppressions', suppressionsRoutes(ctx));
  api.route('/events', eventsRoutes(ctx));
  api.route('/analytics', analyticsRoutes(ctx));
  api.route('/webhooks', webhooksRoutes(ctx));
  api.route('/support', supportRoutes(ctx));
  api.route('/scim', scimRoutes(ctx)); // SCIM 2.0 provisioning (RFC 7644)
  api.route('/campaigns', campaignsRoutes(ctx));
  api.route('/contacts', contactsRoutes(ctx));
  api.route('/automations', automationsRoutes(ctx));

  // Mount API under /v1
  app.route('/v1', api);

  // 404 handler
  app.notFound((c) => {
    return c.json({
      error: {
        code: 'NOT_FOUND',
        message: `Route not found: ${c.req.method} ${c.req.path}`,
      },
    }, 404);
  });

  return app;
}

/**
 * F-232: Deprecation header middleware factory.
 * Marks a route as deprecated by adding standard Deprecation and Sunset headers.
 * Usage:
 *   router.get('/old-endpoint', deprecated('2025-03-01'), handler);
 *
 * FIX-500-462: This middleware is defined and exported but not yet applied to
 * any route. It is ready for use when API versioning or endpoint migrations
 * require sunset signaling. No routes are currently deprecated.
 *
 * @param sunsetDate - ISO 8601 date string when the endpoint will be removed
 * @param link - Optional URL to documentation for the replacement endpoint
 */
export function deprecated(sunsetDate: string, link?: string) {
  const sunsetHttpDate = new Date(sunsetDate).toUTCString();
  return async (c: any, next: () => Promise<void>) => {
    await next();
    c.header('Deprecation', 'true');
    c.header('Sunset', sunsetHttpDate);
    if (link) {
      c.header('Link', `<${link}>; rel="successor-version"`);
    }
  };
}
