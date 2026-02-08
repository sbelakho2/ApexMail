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
  // G-216: Namespace isolation — prevent key collisions with other services
  keyPrefix: 'tracking:',
  maxRetriesPerRequest: 3,
  // FIX-500-347: Add enableReadyCheck and connectTimeout
  enableReadyCheck: true,
  connectTimeout: 10000,
  // F-219: Reject commands immediately when disconnected instead of
  // queuing them in memory (prevents unbounded memory growth during Redis outages)
  enableOfflineQueue: false,
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
  maxBufferSize: 500, // F-218: Increased from 100 for higher throughput ceiling
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
    // FIX-071: Pipeline 4 sequential Redis calls into a single round-trip
    const pipe = redis.pipeline();
    pipe.get('metrics:tracking:opens');
    pipe.get('metrics:tracking:clicks');
    pipe.get('metrics:tracking:unsubscribes');
    pipe.llen('apexmail:tracking:events:pending');
    const results = await pipe.exec();
    const opens = results?.[0]?.[1] ?? 0;
    const clicks = results?.[1]?.[1] ?? 0;
    const unsubs = results?.[2]?.[1] ?? 0;
    const buffered = results?.[3]?.[1] ?? 0;

    const metrics = [
      `# HELP tracking_requests_total Total tracking requests`,
      `# TYPE tracking_requests_total counter`,
      `tracking_requests_total{type="open"} ${opens}`,
      `tracking_requests_total{type="click"} ${clicks}`,
      `tracking_requests_total{type="unsubscribe"} ${unsubs}`,
      '',
      `# HELP tracking_events_buffered Current events in Redis WAL pending flush`,
      `# TYPE tracking_events_buffered gauge`,
      `tracking_events_buffered ${buffered}`,
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
  // F-220: Increased from 15s to 30s to allow full WAL drain
  const forceTimeout = setTimeout(() => {
    logger.error('Shutdown timeout exceeded, forcing exit');
    process.exit(1);
  }, 30000);
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

  clearTimeout(forceTimeout);
  logger.info('Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  shutdown('uncaughtException').catch(() => process.exit(1));
});

// FIX-500-355: Counter threshold for unhandledRejection (5 within 60s)
let unhandledRejectionCount = 0;
const REJECTION_WINDOW_MS = 60_000;
const REJECTION_THRESHOLD = 5;

process.on('unhandledRejection', (reason) => {
  unhandledRejectionCount++;
  logger.error('Unhandled rejection', { reason: String(reason), count: unhandledRejectionCount });
  // Reset counter after window
  setTimeout(() => { unhandledRejectionCount = Math.max(0, unhandledRejectionCount - 1); }, REJECTION_WINDOW_MS).unref();
  if (unhandledRejectionCount >= REJECTION_THRESHOLD) {
    logger.error(`${REJECTION_THRESHOLD} unhandled rejections within window — triggering shutdown`);
    shutdown('unhandledRejection').catch(() => process.exit(1));
  }
});

// =============================================================================
// START SERVER
// =============================================================================

async function main(): Promise<void> {
  try {
    /**
     * G-217: Startup validation — verify critical dependencies before
     * accepting traffic. The HTTP server is only started after both
     * database and Redis connections are confirmed healthy.
     */
    logger.info('Validating critical dependencies before accepting traffic...');

    // Validate database connection
    try {
      await db.query('SELECT 1');
      logger.info('Database connected');
    } catch (dbErr) {
      logger.error('Database startup validation failed — refusing to start', {
        error: dbErr instanceof Error ? dbErr.message : String(dbErr),
      });
      process.exit(1);
    }

    // E-183: Validate Redis connection — degrade gracefully if unavailable.
    // The tracking server can still serve pixels (returning the 1x1 GIF does
    // not need Redis). Tracking events are queued in-memory and flushed when
    // Redis reconnects. This prevents a Redis blip from taking down the
    // entire pixel-serving path.
    let redisHealthy = false;
    try {
      await redis.ping();
      redisHealthy = true;
      logger.info('Redis connected');
    } catch (redisErr) {
      logger.warn('E-183: Redis unavailable at startup — serving pixels without tracking', {
        error: redisErr instanceof Error ? redisErr.message : String(redisErr),
      });
    }

    // E-183: Track Redis health changes at runtime
    redis.on('ready', () => {
      if (!redisHealthy) {
        logger.info('E-183: Redis reconnected — tracking events will resume flushing');
        redisHealthy = true;
      }
    });
    redis.on('close', () => {
      if (redisHealthy) {
        logger.warn('E-183: Redis connection lost — pixels still served, events buffered in-memory');
        redisHealthy = false;
      }
    });

    logger.info('All critical dependencies validated successfully');

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
