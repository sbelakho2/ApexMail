/**
 * Enterprise Service Entry Point
 * 
 * Starts the enterprise HTTP server and background jobs
 */

import { serve } from '@hono/node-server';
import { Pool } from 'pg';
import IORedis from 'ioredis';
import { createApp, BackgroundJobScheduler } from './app.js';
import { config } from './config.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'enterprise' });

// Initialize database connection pool
const pool = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Initialize Redis client
const redis = new IORedis.default({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  db: config.redis.db,
  retryStrategy: (times: number) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

// Graceful shutdown handler
let isShuttingDown = false;
const connections = new Set<any>();

async function gracefulShutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Received shutdown signal', { signal });

  // Stop accepting new connections
  server.close(() => {
    logger.info('HTTP server closed');
  });

  // Stop background jobs
  backgroundScheduler.stop();

  // Close existing connections with timeout
  const closeTimeout = setTimeout(() => {
    logger.warn('Forcing remaining connections closed');
    connections.forEach((conn) => conn.destroy());
  }, 10000);

  // Wait for connections to close
  await Promise.all([
    // Close database pool
    pool.end().then(() => logger.info('Database pool closed')),
    // Close Redis connection
    redis.quit().then(() => logger.info('Redis connection closed')),
  ]);

  clearTimeout(closeTimeout);
  logger.info('Graceful shutdown complete');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
});

// Create application
const app = createApp({ pool, redis });

// Create background job scheduler
const backgroundScheduler = new BackgroundJobScheduler(pool, redis);

// Start server
const server = serve({
  fetch: app.fetch,
  port: config.server.port,
}, async (info) => {
  logger.info('Enterprise service starting', { port: info.port });
  
  // Test database connection
  try {
    await pool.query('SELECT 1');
    logger.info('Database connection established');
  } catch (error) {
    logger.error('Database connection failed', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }

  // Test Redis connection
  try {
    await redis.connect();
    await redis.ping();
    logger.info('Redis connection established');
  } catch (error) {
    logger.error('Redis connection failed', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }

  // Start background jobs
  backgroundScheduler.start();
  logger.info('Background job scheduler started');

  logger.info('Enterprise service is running', {
    port: info.port,
    endpoints: ['SSO', 'Sub-Accounts', 'White-Label', 'Templates', 'Log Streaming', 'Compliance', 'Deployments', 'Support', 'QBR', 'Health'],
  });
});

// Track connections for graceful shutdown
server.on('connection', (conn: any) => {
  connections.add(conn);
  conn.on('close', () => connections.delete(conn));
});

export { app, pool, redis, backgroundScheduler };
