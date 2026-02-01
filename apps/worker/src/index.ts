/**
 * Worker Entry Point
 */

import { createLogger } from '@apexmail/lib';
import { getDatabase } from '@apexmail/db';
import { loadConfig } from './config.js';
import { EmailProcessor } from './processors/email.js';
import { WebhookProcessor } from './processors/webhook.js';
import { AnalyticsProcessor } from './processors/analytics.js';
import { MetricsServer } from './metrics.js';
import Redis from 'ioredis';

const logger = createLogger({ name: 'worker' });
const config = loadConfig();

let isShuttingDown = false;
const processors: Array<{ stop: () => Promise<void> }> = [];
let metricsServer: MetricsServer | null = null;

async function main(): Promise<void> {
  logger.info('Starting ApexMail Worker', {
    workerId: config.workerId,
    nodeEnv: config.nodeEnv,
  });

  // Get database pool (worker gets 30 connections)
  const dbPool = getDatabase('worker');
  await dbPool.connect();
  const db = dbPool.getPool();

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

  // Start metrics server
  if (config.metrics.enabled) {
    metricsServer = new MetricsServer(config.metrics.port, logger);
    await metricsServer.start();
  }

  // Initialize processors
  const emailProcessor = new EmailProcessor({
    db,
    redis,
    config: config.queues.email,
    smtp: config.smtp,
    dkim: config.dkim,
    tracking: config.tracking,
    warmup: config.warmup,
    logger: logger.child({ processor: 'email' }),
  });

  const webhookProcessor = new WebhookProcessor({
    db,
    redis,
    config: config.queues.webhook,
    logger: logger.child({ processor: 'webhook' }),
  });

  const analyticsProcessor = new AnalyticsProcessor({
    db,
    redis,
    config: config.queues.analytics,
    logger: logger.child({ processor: 'analytics' }),
  });

  processors.push(emailProcessor, webhookProcessor, analyticsProcessor);

  // Start processors
  await Promise.all([
    emailProcessor.start(),
    webhookProcessor.start(),
    analyticsProcessor.start(),
  ]);

  logger.info('All processors started', {
    emailConcurrency: config.queues.email.concurrency,
    webhookConcurrency: config.queues.webhook.concurrency,
    analyticsConcurrency: config.queues.analytics.concurrency,
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
    // Stop metrics server
    if (metricsServer) {
      await metricsServer.stop();
    }

    // Stop all processors
    await Promise.all(processors.map(p => p.stop()));

    logger.info('All processors stopped');
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

// Start the worker
main().catch((error) => {
  logger.fatal('Failed to start worker', { error });
  process.exit(1);
});
