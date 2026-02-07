/**
 * Worker Entry Point
 */

import { createLogger } from '@apexmail/lib';
import { getDatabase } from '@apexmail/db';
import { totalmem } from 'os';
import { loadConfig } from './config.js';
import { EmailProcessor } from './processors/email.js';
import { WebhookProcessor } from './processors/webhook.js';
import { AnalyticsProcessor } from './processors/analytics.js';
import { MetricsServer, setMetricsInstance } from './metrics.js';
import { QueueNotifier } from './queue-notifier.js';
import { Redis } from 'ioredis';

const logger = createLogger({ name: 'worker' });
const config = loadConfig();

/**
 * G-223: Cluster mode safety.
 *
 * Multiple worker instances can run concurrently (e.g. Kubernetes replicas,
 * PM2 cluster mode) without conflicts because:
 *
 *   1. **Job claiming** — all three processors (email, webhook, analytics)
 *      use `SELECT ... FOR UPDATE SKIP LOCKED` in their `fetchJobs()` queries.
 *      This ensures each job is claimed by exactly one worker instance.
 *
 *   2. **Unique worker ID** — each instance gets a unique `workerId` composed
 *      of `WORKER_ID` env var (if set) or `worker-${process.pid}`. In
 *      containerised deployments every pod has a distinct PID namespace,
 *      guaranteeing uniqueness.
 *
 *   3. **No shared mutable global state** — each instance holds its own
 *      in-memory caches (suppression cache, DKIM keys, circuit breakers).
 *      Redis-backed state (rate limits, dedup keys, circuit breaker counters)
 *      is inherently multi-instance safe via atomic commands.
 *
 *   4. **Stale job recovery** — the G-205 periodic sweep resets jobs stuck in
 *      'processing' for >30 min, handling cases where an instance crashes
 *      mid-processing.
 */

let isShuttingDown = false;
const processors: Array<{ stop: () => Promise<void> }> = [];
let metricsServer: MetricsServer | null = null;
let queueNotifier: QueueNotifier | null = null;
let redisClient: Redis | null = null;
let dbPool: ReturnType<typeof getDatabase> | null = null;
let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
let staleJobRecoveryTimer: ReturnType<typeof setInterval> | null = null;

async function main(): Promise<void> {
  logger.info('Starting ApexMail Worker', {
    workerId: config.workerId,
    nodeEnv: config.nodeEnv,
  });

  // Get database pool (worker gets 30 connections)
  dbPool = getDatabase('worker');
  await dbPool.connect();
  const db = dbPool.getPool();

  // Test database connection
  try {
    const client = await db.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    logger.info('Database connected', { serverTime: result.rows[0]?.now ?? 'unknown' });
  } catch (error) {
    logger.fatal('Failed to connect to database', { error });
    process.exit(1);
  }

  // Create Redis client
  redisClient = new Redis(config.redis.url, {
    keyPrefix: config.redis.keyPrefix,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => {
      if (times > 10) return null;
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true,
  });

  // C-078: Handle Redis connection errors to prevent uncaught exceptions
  redisClient.on('error', (err: Error) => {
    logger.error('Redis connection error', { error: err.message });
  });

  try {
    await redisClient.connect();
    logger.info('Redis connected');
  } catch (error) {
    logger.fatal('Failed to connect to Redis', { error });
    process.exit(1);
  }

  // Start metrics server
  if (config.metrics.enabled) {
    metricsServer = new MetricsServer(config.metrics.port, logger);
    // C-063 / G-196: Wire metrics instance so processors can record metrics
    setMetricsInstance(metricsServer);
    await metricsServer.start();
  }

  // Start queue notifier (LISTEN/NOTIFY for instant wakeup instead of polling)
  queueNotifier = new QueueNotifier(
    { connectionString: config.database.connectionString },
    logger.child({ component: 'queue-notifier' }),
  );
  await queueNotifier.start();

  // Initialize processors
  const emailProcessor = new EmailProcessor({
    db,
    dbPool,
    redis: redisClient,
    notifier: queueNotifier,
    config: config.queues.email,
    smtp: config.smtp,
    dkim: config.dkim,
    tracking: config.tracking,
    warmup: config.warmup,
    ipRateLimiting: config.ipRateLimiting,
    logger: logger.child({ processor: 'email' }),
  });

  const webhookProcessor = new WebhookProcessor({
    db,
    redis: redisClient,
    notifier: queueNotifier,
    config: config.queues.webhook,
    logger: logger.child({ processor: 'webhook' }),
  });

  const analyticsProcessor = new AnalyticsProcessor({
    db,
    redis: redisClient,
    notifier: queueNotifier,
    config: config.queues.analytics,
    logger: logger.child({ processor: 'analytics' }),
  });

  processors.push(emailProcessor, webhookProcessor, analyticsProcessor);

  // Start processors with isolation - one failure doesn't prevent others from starting
  const startResults = await Promise.allSettled([
    emailProcessor.start(),
    webhookProcessor.start(),
    analyticsProcessor.start(),
  ]);

  // Check for failures and log them
  const failures = startResults.filter(r => r.status === 'rejected');
  const successes = startResults.filter(r => r.status === 'fulfilled');

  if (failures.length > 0) {
    for (const failure of failures) {
      logger.error('Processor failed to start', { 
        error: (failure as PromiseRejectedResult).reason 
      });
    }
    
    // If all processors failed, exit
    if (successes.length === 0) {
      logger.fatal('All processors failed to start, exiting');
      process.exit(1);
    }
    
    logger.warn('Some processors failed to start, continuing with healthy ones', {
      failed: failures.length,
      succeeded: successes.length,
    });
  }

  logger.info('Processors started', {
    total: startResults.length,
    succeeded: successes.length,
    failed: failures.length,
    emailConcurrency: config.queues.email.concurrency,
    webhookConcurrency: config.queues.webhook.concurrency,
    analyticsConcurrency: config.queues.analytics.concurrency,
  });

  // G-203 + E-164: Periodic heartbeat with resource monitoring.
  // Logs worker liveness every 30s AND warns when resource usage
  // exceeds safe thresholds. Uses .unref() so the timer does not
  // prevent graceful shutdown.
  //
  // E-164 thresholds:
  //   - Memory usage > 80% of total system memory → warning
  //   - Event loop lag > 100ms → warning (indicates CPU saturation)
  let lastLoopCheck = Date.now();
  heartbeatTimer = setInterval(() => {
    const mem = process.memoryUsage();
    const totalMemBytes = totalmem();
    const memUsagePercent = (mem.rss / totalMemBytes) * 100;

    // E-164: Measure event loop lag — the difference between expected
    // and actual firing time of setInterval gives a good approximation.
    const now = Date.now();
    const expectedInterval = 30_000;
    const loopLagMs = Math.max(0, (now - lastLoopCheck) - expectedInterval);
    lastLoopCheck = now;

    const memoryMB = Math.round(mem.rss / 1024 / 1024);
    const heapUsedMB = Math.round(mem.heapUsed / 1024 / 1024);
    const heapTotalMB = Math.round(mem.heapTotal / 1024 / 1024);

    logger.info('Worker heartbeat', {
      workerId: config.workerId,
      uptimeSeconds: Math.floor(process.uptime()),
      memoryMB,
      heapUsedMB,
      heapTotalMB,
      memUsagePercent: Math.round(memUsagePercent * 100) / 100,
      eventLoopLagMs: loopLagMs,
      activeProcessors: successes.length,
    });

    // E-164: Warn when memory usage exceeds 80% of available system memory
    if (memUsagePercent > 80) {
      logger.warn('E-164: High memory usage detected', {
        memoryMB,
        totalMemoryMB: Math.round(totalMemBytes / 1024 / 1024),
        memUsagePercent: Math.round(memUsagePercent * 100) / 100,
        threshold: '80%',
      });
    }

    // E-164: Warn when event loop lag exceeds 100ms
    if (loopLagMs > 100) {
      logger.warn('E-164: High event loop lag detected', {
        eventLoopLagMs: loopLagMs,
        threshold: '100ms',
        possibleCause: 'CPU-bound work or too many synchronous operations',
      });
    }
  }, 30_000);
  heartbeatTimer.unref();

  // G-205: Periodic stale job recovery — resets jobs stuck in 'processing' state
  // for longer than 30 minutes (e.g., worker crashed mid-processing).
  // Runs every 5 minutes. Uses .unref() so timer doesn't prevent graceful shutdown.
  staleJobRecoveryTimer = setInterval(async () => {
    try {
      const tables = ['email_queue', 'webhook_queue'];
      for (const table of tables) {
        const result = await db.query(
          `UPDATE ${table}
           SET status = 'pending', locked_until = NULL, updated_at = NOW()
           WHERE status = 'processing'
             AND locked_until IS NOT NULL
             AND locked_until < NOW() - INTERVAL '30 minutes'
           RETURNING id`,
        );
        if (result.rowCount && result.rowCount > 0) {
          logger.warn('G-205: Recovered stale jobs', {
            table,
            count: result.rowCount,
            jobIds: result.rows.map((r: { id: string }) => r.id).slice(0, 10),
          });
        }
      }
    } catch (error) {
      logger.error('G-205: Failed to recover stale jobs', { error });
    }
  }, 5 * 60_000);
  staleJobRecoveryTimer.unref();
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
    // G-203: Stop heartbeat timer
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }

    // G-205: Stop stale job recovery timer
    if (staleJobRecoveryTimer) {
      clearInterval(staleJobRecoveryTimer);
      staleJobRecoveryTimer = null;
    }

    // Stop metrics server
    if (metricsServer) {
      await metricsServer.stop();
    }

    // Stop all processors with isolation - one failure doesn't prevent others from stopping
    const stopResults = await Promise.allSettled(processors.map(p => p.stop()));
    
    const stopFailures = stopResults.filter(r => r.status === 'rejected');
    if (stopFailures.length > 0) {
      for (const failure of stopFailures) {
        logger.error('Processor failed to stop cleanly', {
          error: (failure as PromiseRejectedResult).reason,
        });
      }
    }

    logger.info('All processors stopped');

    // Stop queue notifier
    if (queueNotifier) {
      await queueNotifier.stop();
      logger.info('Queue notifier stopped');
    }

    // Close Redis connection
    try {
      if (redisClient) {
        await redisClient.quit();
        logger.info('Redis connection closed');
      }
    } catch (err) {
      logger.error('Failed to close Redis connection', { error: err });
    }

    // Close database pool
    try {
      if (dbPool) {
        await dbPool.disconnect();
        logger.info('Database pool closed');
      }
    } catch (err) {
      logger.error('Failed to close database pool', { error: err });
    }

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
