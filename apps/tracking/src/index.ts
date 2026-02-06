/**
 * Tracking Service - Entry Point
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { createLogger } from '@apexmail/lib';
import { config } from './config.js';
import { createRoutes } from './routes.js';
import { TrackingCodec } from './codec.js';
import { EventProcessor } from './processor.js';

const logger = createLogger({
  level: config.logging.level,
  name: 'tracking',
});

// =============================================================================
// DATABASE CONNECTION
// =============================================================================

const db = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.database,
  user: config.database.user,
  password: config.database.password,
  max: config.database.maxConnections,
  idleTimeoutMillis: config.database.idleTimeout,
  connectionTimeoutMillis: config.database.connectionTimeout,
});

db.on('error', (err: Error) => {
  logger.error('Database pool error', { error: err.message });
});

// =============================================================================
// REDIS CONNECTION
// =============================================================================

const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  db: config.redis.db,
  maxRetriesPerRequest: 3,
  retryStrategy(times: number) {
    if (times > 10) {
      logger.error('Redis connection failed after 10 retries');
      return null;
    }
    return Math.min(times * 100, 3000);
  },
});

redis.on('error', (err: Error) => {
  logger.error('Redis error', { error: err.message });
});

redis.on('connect', () => {
  logger.info('Connected to Redis');
});

// =============================================================================
// TRACKING CODEC
// =============================================================================

const defaultDevSecret = 'development-secret-key-change-in-production';
const secretKey = process.env.TRACKING_SECRET_KEY ?? (config.env === 'development' ? defaultDevSecret : undefined);
if (!secretKey || (secretKey === defaultDevSecret && config.env !== 'development')) {
  logger.error('TRACKING_SECRET_KEY must be set for non-development environments');
  process.exit(1);
}

const codec = new TrackingCodec(secretKey);

// =============================================================================
// EVENT PROCESSOR
// =============================================================================

const processor = new EventProcessor({
  db,
  redis,
  logger,
  flushIntervalMs: 1000,
  maxBufferSize: 100,
});

// =============================================================================
// APPLICATION
// =============================================================================

const app = new Hono();

// Mount tracking routes
const trackingRoutes = createRoutes({
  db,
  redis,
  logger,
  codec,
  processor,
});

app.route('/', trackingRoutes);

// =============================================================================
// METRICS SERVER
// =============================================================================

let metricsServer: ReturnType<typeof serve> | null = null;

if (config.metrics.enabled) {
  const metricsApp = new Hono();
  
  metricsApp.get('/metrics', async (c) => {
    const metrics = [
      `# HELP tracking_requests_total Total tracking requests`,
      `# TYPE tracking_requests_total counter`,
      `tracking_requests_total{type="open"} ${await redis.get('metrics:tracking:opens') ?? 0}`,
      `tracking_requests_total{type="click"} ${await redis.get('metrics:tracking:clicks') ?? 0}`,
      `tracking_requests_total{type="unsubscribe"} ${await redis.get('metrics:tracking:unsubscribes') ?? 0}`,
      '',
      `# HELP tracking_events_buffered Current events in Redis WAL pending flush`,
      `# TYPE tracking_events_buffered gauge`,
      `tracking_events_buffered ${await redis.llen('apexmail:tracking:events:pending')}`,
      '',
      `# HELP process_uptime_seconds Process uptime`,
      `# TYPE process_uptime_seconds gauge`,
      `process_uptime_seconds ${process.uptime()}`,
    ];
    
    return c.text(metrics.join('\n'));
  });
  
  metricsServer = serve({
    fetch: metricsApp.fetch,
    port: config.metrics.port,
    hostname: '0.0.0.0',
  });
  
  logger.info('Metrics server started', { port: config.metrics.port });
}

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

let isShuttingDown = false;
let httpServer: ReturnType<typeof serve> | null = null;

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;
  
  logger.info('Shutdown initiated', { signal });

  // Set a hard timeout to force exit if shutdown hangs
  const forceTimeout = setTimeout(() => {
    logger.error('Shutdown timeout exceeded, forcing exit');
    process.exit(1);
  }, 15000);
  forceTimeout.unref();

  // Stop accepting new HTTP connections
  if (httpServer) {
    httpServer.close();
    logger.info('HTTP server closed');
  }

  // Stop metrics server
  if (metricsServer) {
    metricsServer.close();
  }

  // Stop event processor (flushes remaining events)
  await processor.stop();

  // Close Redis
  await redis.quit();

  // Close database pool
  await db.end();

  logger.info('Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  shutdown('uncaughtException').catch(() => process.exit(1));
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
});

// =============================================================================
// START SERVER
// =============================================================================

async function main(): Promise<void> {
  try {
    // Test database connection
    await db.query('SELECT 1');
    logger.info('Database connected');

    // Test Redis connection
    await redis.ping();
    logger.info('Redis connected');

    // Start event processor
    processor.start();

    // Start HTTP server
    httpServer = serve({
      fetch: app.fetch,
      port: config.server.port,
      hostname: config.server.host,
    });

    logger.info('Tracking server started', {
      host: config.server.host,
      port: config.server.port,
      env: config.env,
    });

    // Keep the process running
    await new Promise(() => {});

  } catch (error) {
    logger.error('Failed to start server', { 
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    process.exit(1);
  }
}

main();
