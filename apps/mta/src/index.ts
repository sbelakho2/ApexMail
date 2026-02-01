/**
 * MTA Entry Point - Inbound mail, bounce, and feedback loop handling
 */

import { createLogger } from '@apexmail/lib';
import { createPool } from '@apexmail/db';
import { loadConfig } from './config.js';
import { InboundServer } from './servers/inbound.js';
import { BounceServer } from './servers/bounce.js';
import { FeedbackLoopServer } from './servers/feedback-loop.js';
import Redis from 'ioredis';

const logger = createLogger({ name: 'mta' });
const config = loadConfig();

let isShuttingDown = false;
const servers: Array<{ stop: () => Promise<void> }> = [];

async function main(): Promise<void> {
  logger.info('Starting ApexMail MTA', {
    mtaId: config.mtaId,
    nodeEnv: config.nodeEnv,
  });

  // Create database pool
  const db = createPool({
    connectionString: config.database.connectionString,
    max: config.database.maxConnections,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Test database connection
  try {
    const client = await db.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    logger.info('Database connected', { serverTime: result.rows[0].now });
  } catch (error) {
    logger.fatal('Failed to connect to database', { error });
    process.exit(1);
  }

  // Create Redis client
  const redis = new Redis(config.redis.url, {
    keyPrefix: config.redis.keyPrefix,
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => {
      if (times > 10) return null;
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true,
  });

  try {
    await redis.connect();
    logger.info('Redis connected');
  } catch (error) {
    logger.fatal('Failed to connect to Redis', { error });
    process.exit(1);
  }

  // Start inbound mail server
  if (config.inbound.enabled) {
    const inboundServer = new InboundServer({
      db,
      redis,
      config: config.inbound,
      rateLimit: config.rateLimit,
      logger: logger.child({ server: 'inbound' }),
    });

    await inboundServer.start();
    servers.push(inboundServer);
  }

  // Start bounce handling server
  if (config.bounce.enabled) {
    const bounceServer = new BounceServer({
      db,
      redis,
      config: config.bounce,
      logger: logger.child({ server: 'bounce' }),
    });

    await bounceServer.start();
    servers.push(bounceServer);
  }

  // Start feedback loop server
  if (config.feedback.enabled) {
    const feedbackServer = new FeedbackLoopServer({
      db,
      redis,
      config: config.feedback,
      logger: logger.child({ server: 'feedback' }),
    });

    await feedbackServer.start();
    servers.push(feedbackServer);
  }

  logger.info('All MTA servers started', {
    inbound: config.inbound.enabled,
    bounce: config.bounce.enabled,
    feedback: config.feedback.enabled,
  });
}

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress, forcing exit');
    process.exit(1);
  }

  isShuttingDown = true;
  logger.info('Graceful shutdown initiated', { signal });

  const timeout = setTimeout(() => {
    logger.error('Graceful shutdown timeout, forcing exit');
    process.exit(1);
  }, config.gracefulShutdownTimeout);

  try {
    // Stop all servers
    await Promise.all(servers.map(s => s.stop()));

    logger.info('All servers stopped');
    clearTimeout(timeout);
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    clearTimeout(timeout);
    process.exit(1);
  }
}

// Signal handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  logger.fatal('Uncaught exception', { error });
  shutdown('uncaughtException').catch(() => process.exit(1));
});

process.on('unhandledRejection', (reason) => {
  logger.fatal('Unhandled rejection', { reason });
  shutdown('unhandledRejection').catch(() => process.exit(1));
});

// Start the MTA
main().catch((error) => {
  logger.fatal('Failed to start MTA', { error });
  process.exit(1);
});
