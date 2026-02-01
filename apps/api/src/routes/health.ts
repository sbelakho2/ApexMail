/**
 * Health Check Routes
 */

import { Hono } from 'hono';
import type { AppEnv, AppContext } from '../app.js';

export function healthRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();

  // Basic liveness probe
  router.get('/', (c) => {
    return c.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  // Detailed readiness probe
  router.get('/ready', async (c) => {
    const checks: Record<string, { status: string; latency?: number; error?: string }> = {};
    let healthy = true;

    // Check database
    const dbStart = Date.now();
    try {
      const result = await ctx.db.query('SELECT 1');
      checks.database = {
        status: result.ok ? 'healthy' : 'unhealthy',
        latency: Date.now() - dbStart,
      };
      if (!result.ok) {
        healthy = false;
        checks.database.error = result.error.message;
      }
    } catch (err) {
      healthy = false;
      checks.database = {
        status: 'unhealthy',
        latency: Date.now() - dbStart,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }

    // Check Redis (if configured)
    // In a full implementation, we'd check Redis connectivity here

    return c.json({
      status: healthy ? 'ready' : 'not_ready',
      timestamp: new Date().toISOString(),
      checks,
    }, healthy ? 200 : 503);
  });

  // Version info
  router.get('/version', (c) => {
    return c.json({
      name: 'apexmail-api',
      version: process.env.npm_package_version ?? '0.1.0',
      node: process.version,
      env: ctx.config.env,
    });
  });

  return router;
}
