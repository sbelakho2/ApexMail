/**
 * Main Hono Application Setup
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { prettyJSON } from 'hono/pretty-json';
import { bodyLimit } from 'hono/body-limit';
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
import { authRoutes } from './routes/auth.js';
import { messagesRoutes } from './routes/messages.js';
import { domainsRoutes } from './routes/domains.js';
import { templatesRoutes } from './routes/templates.js';
import { suppressionsRoutes } from './routes/suppressions.js';
import { eventsRoutes } from './routes/events.js';
import { webhooksRoutes } from './routes/webhooks.js';
import { analyticsRoutes } from './routes/analytics.js';

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
  app.use('*', secureHeaders());

  // Body size limit to prevent DoS via oversized payloads (1MB)
  app.use('*', bodyLimit({
    maxSize: 1024 * 1024, // 1MB
    onError: (c) => {
      return c.json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request body exceeds the maximum allowed size of 1MB',
        },
      }, 413);
    },
  }));

  app.use('*', prettyJSON());

  // Additional security headers not covered by secureHeaders()
  app.use('*', async (c, next) => {
    await next();
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    c.header('X-Frame-Options', 'DENY');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    c.header('X-XSS-Protection', '0');
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  });
  
  app.use('*', cors({
    origin: ctx.config.cors.origins,
    credentials: ctx.config.cors.credentials,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Idempotency-Key', 'X-Request-ID', 'X-CSRF-Token'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
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

  // Webhook endpoints (separate auth - signature verification)
  app.route('/webhooks', webhooksRoutes(ctx));

  // Auth login route MUST be outside auth middleware (users need to obtain JWT)
  // Rate limit login separately to prevent brute-force
  const publicAuth = new Hono<AppEnv>();
  publicAuth.use('*', rateLimiter(ctx));
  publicAuth.route('/auth', authRoutes(ctx));
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
  api.use('/messages/*', idempotencyMiddleware(ctx));

  // Mount API routes (auth routes excluded — mounted above without auth)
  api.route('/messages', messagesRoutes(ctx));
  api.route('/domains', domainsRoutes(ctx));
  api.route('/templates', templatesRoutes(ctx));
  api.route('/suppressions', suppressionsRoutes(ctx));
  api.route('/events', eventsRoutes(ctx));
  api.route('/analytics', analyticsRoutes(ctx));

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
