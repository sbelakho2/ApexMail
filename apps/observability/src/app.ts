/**
 * Observability Application
 * 
 * Main application setup with all services and middleware
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { Pool } from 'pg';
import Redis from 'ioredis';

import { config } from './config.js';
import { TracingService } from './services/tracing.js';
import { MetricsService } from './services/metrics.js';
import { LoggingService } from './services/logging.js';
import { AlertingService } from './services/alerting.js';
import { DashboardService } from './services/dashboards.js';
import { createObservabilityRoutes } from './routes/observability.js';

export interface AppContext {
  db: Pool;
  redis: Redis;
  tracing: TracingService;
  metrics: MetricsService;
  logging: LoggingService;
  alerting: AlertingService;
  dashboards: DashboardService;
}

export async function createApp(): Promise<{ app: Hono; context: AppContext }> {
  // Initialize database pool
  const db = new Pool({
    host: config.database.host,
    port: config.database.port,
    database: config.database.database,
    user: config.database.user,
    password: config.database.password,
    max: config.database.maxConnections,
  });

  // Initialize Redis
  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    db: config.redis.db,
  });

  // Initialize services
  const tracing = new TracingService(db, redis);
  const metrics = new MetricsService(db, redis);
  const logging = new LoggingService(db, redis);
  const alerting = new AlertingService(db, redis);
  const dashboards = new DashboardService(db, redis);

  // Initialize services
  await tracing.initialize();
  await metrics.initialize();
  await logging.initialize();
  await alerting.initialize();

  const context: AppContext = {
    db,
    redis,
    tracing,
    metrics,
    logging,
    alerting,
    dashboards,
  };

  // Create Hono app
  const app = new Hono();

  // Global middleware
  app.use('*', cors({
    origin: config.cors.origins,
    credentials: true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Workspace-ID'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    maxAge: 86400,
  }));

  app.use('*', logger());
  app.use('*', prettyJSON());

  // Request ID middleware
  app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-ID') || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    c.header('X-Request-ID', requestId);
    c.set('requestId', requestId);
    
    const startTime = Date.now();
    
    // Start trace span
    const span = tracing.startSpan('http.request', {
      attributes: {
        'http.method': c.req.method,
        'http.url': c.req.url,
        'http.request_id': requestId,
      },
    });

    try {
      await next();
      
      // Record metrics
      const duration = Date.now() - startTime;
      metrics.recordHttpRequest(c.req.method, c.req.path, c.res.status, duration);
      
      span.setAttribute('http.status_code', c.res.status);
      span.end();
    } catch (error) {
      const duration = Date.now() - startTime;
      metrics.recordHttpRequest(c.req.method, c.req.path, 500, duration);
      
      span.setStatus({ code: 2, message: (error as Error).message });
      span.end();
      
      throw error;
    }
  });

  // Health check
  app.get('/health', async (c) => {
    const checks = {
      database: 'unknown',
      redis: 'unknown',
    };

    try {
      await db.query('SELECT 1');
      checks.database = 'healthy';
    } catch {
      checks.database = 'unhealthy';
    }

    try {
      await redis.ping();
      checks.redis = 'healthy';
    } catch {
      checks.redis = 'unhealthy';
    }

    const isHealthy = checks.database === 'healthy' && checks.redis === 'healthy';

    return c.json({
      status: isHealthy ? 'healthy' : 'unhealthy',
      service: 'observability',
      timestamp: new Date().toISOString(),
      checks,
    }, isHealthy ? 200 : 503);
  });

  // Readiness check
  app.get('/ready', async (c) => {
    try {
      await db.query('SELECT 1');
      await redis.ping();
      return c.json({ status: 'ready' });
    } catch {
      return c.json({ status: 'not_ready' }, 503);
    }
  });

  // Liveness check
  app.get('/live', (c) => {
    return c.json({ status: 'alive' });
  });

  // API version and info
  app.get('/', (c) => {
    return c.json({
      service: 'ApexMail Observability',
      version: '1.0.0',
      description: 'Observability, tracing, metrics, logging, and alerting service',
      endpoints: {
        health: '/health',
        ready: '/ready',
        live: '/live',
        traces: '/api/v1/traces',
        metrics: '/api/v1/metrics',
        logs: '/api/v1/logs',
        alerts: '/api/v1/alerts',
        dashboards: '/api/v1/dashboards',
      },
    });
  });

  // Mount observability routes
  const observabilityRoutes = createObservabilityRoutes(
    tracing,
    metrics,
    logging,
    alerting,
    dashboards
  );
  app.route('/api/v1', observabilityRoutes);

  // Error handling
  app.onError((err, c) => {
    const requestId = c.get('requestId') || 'unknown';
    
    console.error(`[${requestId}] Error:`, err);

    // Log error
    logging.error('Request error', {
      requestId,
      method: c.req.method,
      path: c.req.path,
      error: err.message,
      stack: err.stack,
    });

    // Determine status code
    const status = (err as { status?: number }).status || 500;

    return c.json({
      error: {
        message: status === 500 ? 'Internal server error' : err.message,
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, status);
  });

  // 404 handler
  app.notFound((c) => {
    return c.json({
      error: {
        message: 'Not found',
        path: c.req.path,
        timestamp: new Date().toISOString(),
      },
    }, 404);
  });

  return { app, context };
}

/**
 * Graceful shutdown
 */
export async function shutdown(context: AppContext): Promise<void> {
  console.log('[App] Shutting down...');

  // Shutdown services
  context.tracing.shutdown();
  context.metrics.shutdown();
  context.logging.shutdown();
  context.alerting.shutdown();

  // Close connections
  await context.redis.quit();
  await context.db.end();

  console.log('[App] Shutdown complete');
}
