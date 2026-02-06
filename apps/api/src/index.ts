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

async function main(): Promise<void> {
  const config = loadConfig();
  
  logger.info('Starting ApexMail API server', {
    env: config.env,
    port: config.port,
  });

  // Initialize database pool (uses service-specific config for 'api' = 20 connections)
  const db = getDatabase('api');

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
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    
    server.close(async () => {
      logger.info('HTTP server closed');
      
      await disconnectTokenBlacklist();
      await redis.quit().catch(() => {});
      await db.disconnect();
      
      logger.info('Shutdown complete');
      process.exit(0);
    });

    // Force exit after timeout
    const forceTimer = setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
    forceTimer.unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Global error handlers
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

main().catch((err) => {
  logger.error('Fatal error starting server', { error: err });
  process.exit(1);
});
