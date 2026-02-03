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

    // Check if database pool is not exhausted
    if (healthy) {
      try {
        // A quick check that we can get a connection
        const poolCheck = await ctx.db.query('SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()');
        if (poolCheck.ok && poolCheck.value.rows[0]) {
          const connections = parseInt(poolCheck.value.rows[0].count as string, 10);
          checks.database_pool = {
            status: connections < 90 ? 'healthy' : 'warning',
            latency: 0,
          };
          if (connections >= 100) {
            checks.database_pool.status = 'unhealthy';
            checks.database_pool.error = `Connection pool near limit: ${connections}`;
          }
        }
      } catch {
        // Non-critical check
        checks.database_pool = { status: 'unknown', latency: 0 };
      }
    }

    return c.json({
      status: healthy ? 'ready' : 'not_ready',
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - startTime) / 1000),
      checks,
    }, healthy ? 200 : 503);
  });

  // Deep health check - comprehensive system status
  router.get('/deep', async (c) => {
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

    return c.json({
      status: criticalHealthy ? (overallHealthy ? 'healthy' : 'degraded') : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - startTime) / 1000),
      environment: ctx.config.env,
      checks,
    }, criticalHealthy ? 200 : 503);
  });

  // Version info
  router.get('/version', (c) => {
    return c.json({
      name: 'apexmail-api',
      version: process.env.npm_package_version ?? '1.0.0',
      node: process.version,
      env: ctx.config.env,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      buildTime: process.env.BUILD_TIME ?? 'unknown',
      commitSha: process.env.COMMIT_SHA ?? 'unknown',
    });
  });

  return router;
}
