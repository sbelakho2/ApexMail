/**
 * Request Logger Middleware
 */

import type { MiddlewareHandler } from 'hono';
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

      const logFn = status >= 500 ? logger.error : status >= 400 ? logger.warn : logger.info;
      logFn.call(logger, 'Request completed', {
        status,
        duration,
        tenantId: c.get('tenantId'),
      });
    }
  };
}

function getClientIp(c: { req: { header: (name: string) => string | undefined; raw: { socket?: { remoteAddress?: string } } } }): string {
  return (
    c.req.header('CF-Connecting-IP') ??
    c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ??
    c.req.header('X-Real-IP') ??
    c.req.raw.socket?.remoteAddress ??
    'unknown'
  );
}
