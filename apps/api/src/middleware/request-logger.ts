/**
 * Request Logger Middleware
 */

import type { MiddlewareHandler, Context } from 'hono';
import type { Logger } from '@apexmail/lib';
import type { AppEnv } from '../app.js';
import { generateShortId } from '@apexmail/lib/id';

export function requestLogger(baseLogger: Logger): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const requestId = c.req.header('X-Request-ID') ?? generateShortId();
    const startTime = Date.now();
    
    // Create child logger with request context
    const logger = baseLogger.child({
      requestId,
      method: c.req.method,
      path: c.req.path,
    });

    // Store in context
    c.set('requestId', requestId);
    c.set('logger', logger);

    // Add request ID to response headers
    c.header('X-Request-ID', requestId);

    // Log incoming request
    logger.info('Incoming request', {
      query: c.req.query(),
      userAgent: c.req.header('User-Agent'),
      ip: getClientIp(c),
    });

    try {
      await next();
    } finally {
      const duration = Date.now() - startTime;
      const status = c.res.status;

      // C-115: Log full request processing details for observability
      const logFn = status >= 500 ? logger.error : status >= 400 ? logger.warn : logger.info;
      logFn.call(logger, 'Request completed', {
        method: c.req.method,
        path: c.req.path,
        status,
        durationMs: duration,
        tenantId: c.get('tenantId'),
        contentLength: c.res.headers.get('content-length'),
      });

      // C-115: Warn on slow requests (>3s)
      if (duration > 3000) {
        logger.warn('C-115: Slow request detected', {
          method: c.req.method,
          path: c.req.path,
          durationMs: duration,
          status,
          tenantId: c.get('tenantId'),
        });
      }
    }
  };
}

function getClientIp(c: Context): string {
  return (
    c.req.header('CF-Connecting-IP') ??
    c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ??
    c.req.header('X-Real-IP') ??
    'unknown'
  );
}
