/**
 * Health Check Routes
 * 
 * Provides comprehensive health checking for Kubernetes and load balancer probes:
 * - GET /health - Basic liveness probe (always returns 200 if service is up)
 * - GET /health/ready - Readiness probe (checks dependencies)
 * - GET /health/live - Liveness probe (lightweight check)
 * - GET /health/version - Version and build info
 * - GET /health/deep - Comprehensive check including database, redis cache, and schema validation
 */

import { Hono } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { isReady } from '../index.js';
import { verifyJwt } from '../middleware/auth.js';

export function healthRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const startTime = Date.now();

  // Basic liveness probe - lightweight, always returns 200 if process is running
  router.get('/', (c) => {
    return c.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - startTime) / 1000),
    });
  });

  // Kubernetes-style liveness probe
  router.get('/live', (c) => {
    return c.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  // Detailed readiness probe - checks all dependencies
  router.get('/ready', async (c) => {
    // G-221: If the process is shutting down, immediately return 503
    // so Kubernetes stops routing new traffic to this pod.
    if (!isReady) {
      return c.json({
        status: 'shutting_down',
        timestamp: new Date().toISOString(),
      }, 503);
    }

    const checks: Record<string, { status: string; latency?: number; error?: string }> = {};
    let healthy = true;

    // Check database
    const dbStart = Date.now();
    try {
      const result = await ctx.db.query('SELECT 1 as ok');
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

    // FIX-500-097: Check pool health via pool counters instead of
    // a database round-trip query, which avoids network latency and
    // avoids needing special DB permissions.
    if (healthy) {
      try {
        const pool = ctx.db.getPool?.() ?? ctx.db;
        const totalCount = (pool as any).totalCount ?? 0;
        const waitingCount = (pool as any).waitingCount ?? 0;
        const poolMax = (pool as any).options?.max ?? 100;

        const utilization = totalCount / poolMax;
        checks.database_pool = {
          status: utilization < 0.9 ? (waitingCount > 0 ? 'warning' : 'healthy') : 'warning',
          latency: 0,
        };
        if (utilization >= 1.0 || waitingCount > 10) {
          checks.database_pool.status = 'unhealthy';
          checks.database_pool.error = `Pool near limit: ${totalCount}/${poolMax} connections, ${waitingCount} waiting`;
        }
      } catch {
        // Non-critical check
        checks.database_pool = { status: 'unknown', latency: 0 };
      }
    }

    // G-213: Check Redis connectivity — a superficial health check that
    // only verifies the database can mask Redis outages, causing cache
    // misses, rate-limiter failures, and degraded API performance.
    const redisStart = Date.now();
    try {
      const pong = await ctx.redis.ping();
      checks.redis = {
        status: pong === 'PONG' ? 'healthy' : 'unhealthy',
        latency: Date.now() - redisStart,
      };
      if (pong !== 'PONG') {
        healthy = false;
        checks.redis.error = `Unexpected ping response: ${pong}`;
      }
    } catch (err) {
      // Redis is degraded but not critical — API can still serve requests
      // without cache. Mark as warning rather than failing readiness.
      checks.redis = {
        status: 'unhealthy',
        latency: Date.now() - redisStart,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }

    return c.json({
      status: healthy ? 'ready' : 'not_ready',
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - startTime) / 1000),
      checks,
    }, healthy ? 200 : 503);
  });

  // Deep health check - comprehensive system status
  // F-209: Require auth via bearer token or X-Health-Check-Key to prevent information leakage
  router.get('/deep', async (c) => {
    const authHeader = c.req.header('authorization');
    const healthKey = c.req.header('x-health-check-key');
    const expectedKey = process.env.HEALTH_CHECK_KEY;

    // In production, require either a valid bearer token or health check key
    if (ctx.config.env === 'production') {
      const keyAuthorized = Boolean(expectedKey && healthKey === expectedKey);
      let bearerAuthorized = false;

      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.slice(7);
        const jwtResult = await verifyJwt(token, ctx.config.auth.jwtSecret);
        bearerAuthorized = jwtResult.valid;
      }

      const authorized = keyAuthorized || bearerAuthorized;
      if (!authorized) {
        return c.json({ error: 'Authentication required for deep health check' }, 401);
      }
    }
    const checks: Record<string, { status: string; latency?: number; error?: string; details?: unknown }> = {};
    let overallHealthy = true;
    let criticalHealthy = true;

    // 1. Database connectivity
    const dbStart = Date.now();
    try {
      const result = await ctx.db.query('SELECT NOW() as server_time, current_database() as db_name');
      if (result.ok && result.value.rows[0]) {
        checks.database = {
          status: 'healthy',
          latency: Date.now() - dbStart,
          details: {
            serverTime: result.value.rows[0].server_time,
            database: result.value.rows[0].db_name,
          },
        };
      } else {
        criticalHealthy = false;
        checks.database = {
          status: 'unhealthy',
          latency: Date.now() - dbStart,
          error: 'Query failed',
        };
      }
    } catch (err) {
      criticalHealthy = false;
      checks.database = {
        status: 'unhealthy',
        latency: Date.now() - dbStart,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }

    // 2. Check critical tables exist
    try {
      const tablesResult = await ctx.db.query(`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('tenants', 'domains', 'messages', 'events')
      `);
      if (tablesResult.ok) {
        const tables = tablesResult.value.rows.map((r) => (r as { table_name: string }).table_name);
        const requiredTables = ['tenants', 'domains', 'messages', 'events'];
        const missingTables = requiredTables.filter(t => !tables.includes(t));
        
        checks.schema = {
          status: missingTables.length === 0 ? 'healthy' : 'unhealthy',
          latency: 0,
          details: {
            foundTables: tables,
            missingTables: missingTables.length > 0 ? missingTables : undefined,
          },
        };
        if (missingTables.length > 0) {
          criticalHealthy = false;
        }
      }
    } catch {
      checks.schema = { status: 'unknown', latency: 0 };
    }

    // 3. Memory usage
    const memUsage = process.memoryUsage();
    const heapUsedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    const heapTotalMB = Math.round(memUsage.heapTotal / 1024 / 1024);
    const heapPercent = Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100);
    
    checks.memory = {
      status: heapPercent < 85 ? 'healthy' : heapPercent < 95 ? 'warning' : 'unhealthy',
      latency: 0,
      details: {
        heapUsedMB,
        heapTotalMB,
        heapPercent,
        rssMB: Math.round(memUsage.rss / 1024 / 1024),
      },
    };
    if (heapPercent >= 95) {
      overallHealthy = false;
    }

    // 4. Event loop lag (simplified)
    const eventLoopStart = Date.now();
    await new Promise(resolve => setImmediate(resolve));
    const eventLoopLag = Date.now() - eventLoopStart;
    
    checks.eventLoop = {
      status: eventLoopLag < 100 ? 'healthy' : eventLoopLag < 500 ? 'warning' : 'unhealthy',
      latency: eventLoopLag,
    };

    // In production, redact internal details from unauthenticated health checks
    const redactedChecks = ctx.config.env === 'production'
      ? Object.fromEntries(
          Object.entries(checks).map(([key, val]) => [key, { status: val.status }])
        )
      : checks;

    return c.json({
      status: criticalHealthy ? (overallHealthy ? 'healthy' : 'degraded') : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - startTime) / 1000),
      checks: redactedChecks,
    }, criticalHealthy ? 200 : 503);
  });

  // Version info
  router.get('/version', (c) => {
    const info: Record<string, unknown> = {
      name: 'apexmail-api',
      version: process.env.npm_package_version ?? '1.0.0',
      uptime: Math.floor((Date.now() - startTime) / 1000),
    };

    // Only expose internals outside production
    if (ctx.config.env !== 'production') {
      info.node = process.version;
      info.env = ctx.config.env;
      info.buildTime = process.env.BUILD_TIME ?? 'unknown';
      info.commitSha = process.env.COMMIT_SHA ?? 'unknown';
    }

    return c.json(info);
  });

  return router;
}
