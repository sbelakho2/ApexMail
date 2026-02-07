/**
 * API Server Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { createLogger } from '@apexmail/lib';
import { getDatabase } from '@apexmail/db';
import { loadConfig } from './config.js';
import { disconnectTokenBlacklist } from './middleware/token-blacklist.js';
import { Redis } from 'ioredis';

const logger = createLogger({ name: 'api' });

/**
 * G-221: Readiness flag for Kubernetes graceful shutdown.
 * When SIGTERM is received, this flag is set to false so the
 * /health/ready probe returns 503, causing the load balancer
 * to stop routing new traffic before we close the listener.
 */
export let isReady = true;

async function main(): Promise<void> {
  const config = loadConfig();
  
  logger.info('Starting ApexMail API server', {
    env: config.env,
    port: config.port,
  });

  // Initialize database pool (uses service-specific config for 'api' = 20 connections)
  const db = getDatabase('api');

  // G-214: Verify database connectivity before accepting traffic.
  // Unlike Redis (which degrades gracefully), the API cannot function
  // without a working database connection.
  try {
    const dbCheck = await db.query('SELECT 1 AS ok');
    if (!dbCheck.ok) {
      throw new Error(`Database check failed: ${dbCheck.error.message}`);
    }
    logger.info('Database connectivity verified');
  } catch (error) {
    logger.error('G-214: Database is not reachable — cannot start API', {
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }

  // Initialize Redis for cache-aside
  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    db: config.redis.db ?? 0,
    keyPrefix: 'apexmail:',
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => {
      if (times > 10) return null;
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true,
  });

  // C-078: Handle Redis connection errors to prevent uncaught exceptions
  redis.on('error', (err: Error) => {
    logger.error('Redis connection error', { error: err.message });
  });

  try {
    await redis.connect();
    logger.info('Redis connected');
  } catch (error) {
    // Redis is optional for the API — analytics caching degrades gracefully
    logger.warn('Redis connection failed, analytics caching disabled', { error });
  }

  // Create the application
  const app = createApp({ db, redis, config, logger });

  // Start the server
  const server = serve({
    fetch: app.fetch,
    port: config.port,
    hostname: config.host,
  });

  logger.info('API server started', {
    url: `http://${config.host}:${config.port}`,
  });

  // Graceful shutdown
  /**
   * G-204: Drain in-flight requests before shutting down.
   *
   * server.close() stops accepting new connections but existing
   * keep-alive connections may linger. We give in-flight requests
   * a grace period (DRAIN_TIMEOUT) to complete. After that, we
   * proceed with resource cleanup regardless.
   */
  const DRAIN_TIMEOUT_MS = 15_000; // 15 seconds to drain in-flight requests
  const FORCE_TIMEOUT_MS = 30_000; // 30 seconds total before forced exit

  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully...`);

    // G-221: Mark as not ready BEFORE closing the listener.
    // This causes /health/ready to return 503, signalling the
    // Kubernetes load balancer to remove this pod from the
    // service endpoints while we drain in-flight requests.
    isReady = false;

    // Force exit after total timeout
    const forceTimer = setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, FORCE_TIMEOUT_MS);
    forceTimer.unref();

    // Stop accepting new connections and wait for in-flight to drain
    await new Promise<void>((resolve) => {
      const drainTimer = setTimeout(() => {
        logger.warn('Drain timeout reached, proceeding with shutdown', {
          drainTimeoutMs: DRAIN_TIMEOUT_MS,
        });
        resolve();
      }, DRAIN_TIMEOUT_MS);
      drainTimer.unref();

      server.close(() => {
        clearTimeout(drainTimer);
        logger.info('HTTP server closed, all in-flight requests completed');
        resolve();
      });
    });

    // Clean up resources
    await disconnectTokenBlacklist();
    await redis.quit().catch(() => {});
    await db.disconnect();

    logger.info('Shutdown complete');
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Global error handlers
process.on('uncaughtException', (error) => {
  // Only include stack traces in development for security
  const isDev = process.env.NODE_ENV !== 'production';
  logger.error('Uncaught exception', { error: error.message, ...(isDev && { stack: error.stack }) });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
  process.exit(1);
});

main().catch((err) => {
  logger.error('Fatal error starting server', { error: err });
  process.exit(1);
});
