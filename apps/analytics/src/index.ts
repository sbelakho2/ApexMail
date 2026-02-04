/**
 * Analytics Service - Entry Point
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { createLogger } from '@apexmail/lib';
import { config } from './config.js';
import { CompactionWorker } from './compaction.js';
import { ReconciliationWorker } from './reconciliation.js';
import { QueryEngine } from './query-engine.js';
import { SendTimeOptimizer } from './send-time-optimizer.js';
import { ChurnPredictionEngine } from './churn-prediction.js';
import { SubjectLineAnalyzer } from './subject-line-analyzer.js';
import { CampaignAutopilot } from './campaign-autopilot.js';

// Re-export for external use
export { SendTimeOptimizer } from './send-time-optimizer.js';
export { ChurnPredictionEngine } from './churn-prediction.js';
export { SubjectLineAnalyzer } from './subject-line-analyzer.js';
export { CampaignAutopilot } from './campaign-autopilot.js';
export { QueryEngine } from './query-engine.js';

// New competitive edge features
export { BotDetectionService, createBotDetectionService } from './bot-detection.js';
export { InboxPlacementService, createInboxPlacementService } from './inbox-placement.js';
export { ReplyTrackingService, createReplyTrackingService } from './reply-tracking.js';
export { EngagementTrustService, createEngagementTrustService } from './engagement-trust.js';

const logger = createLogger({
  level: config.logging.level,
  name: 'analytics',
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
// WORKERS
// =============================================================================

const compactionWorker = new CompactionWorker({
  db,
  redis,
  logger,
});

const reconciliationWorker = new ReconciliationWorker({
  db,
  redis,
  logger,
});

const queryEngine = new QueryEngine({
  db,
  redis,
  logger,
});

// Initialize Data Science modules
const sendTimeOptimizer = new SendTimeOptimizer({
  db,
  redis,
  logger,
});

const churnPredictionEngine = new ChurnPredictionEngine({
  db,
  redis,
  logger,
});

const subjectLineAnalyzer = new SubjectLineAnalyzer({
  db,
  redis,
  logger,
});

const campaignAutopilot = new CampaignAutopilot({
  db,
  redis,
  logger,
});

// Export initialized instances for external use
export {
  sendTimeOptimizer,
  churnPredictionEngine,
  subjectLineAnalyzer,
  campaignAutopilot,
  queryEngine as queryEngineInstance,
};

// =============================================================================
// CRON SCHEDULER
// =============================================================================

function parseCronSchedule(cron: string): { hour: number; minute: number } {
  // Simple parser for "minute hour * * *" format
  const parts = cron.split(' ');
  return {
    minute: parseInt(parts[0] ?? '0', 10),
    hour: parseInt(parts[1] ?? '0', 10),
  };
}

function scheduleTask(
  schedule: string,
  name: string,
  task: () => Promise<void>
): NodeJS.Timeout {
  const { hour, minute } = parseCronSchedule(schedule);

  const runIfScheduled = () => {
    const now = new Date();
    if (now.getUTCHours() === hour && now.getUTCMinutes() === minute) {
      logger.info(`Running scheduled task: ${name}`);
      task().catch(err => {
        logger.error(`Scheduled task failed: ${name}`, {
          error: err instanceof Error ? err.message : 'Unknown',
        });
      });
    }
  };

  // Check every minute
  return setInterval(runIfScheduled, 60000);
}

let compactionTimer: NodeJS.Timeout | null = null;
let reconciliationTimer: NodeJS.Timeout | null = null;
let healthCheckTimer: NodeJS.Timeout | null = null;

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

let isShuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Shutdown initiated', { signal });

  // Stop scheduled tasks
  if (compactionTimer) clearInterval(compactionTimer);
  if (reconciliationTimer) clearInterval(reconciliationTimer);
  if (healthCheckTimer) clearInterval(healthCheckTimer);

  // Stop workers
  await Promise.all([
    compactionWorker.stop(),
    reconciliationWorker.stop(),
    queryEngine.close(),
  ]);

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
// START SERVICE
// =============================================================================

async function main(): Promise<void> {
  try {
    logger.info('Starting analytics service', { env: config.env });

    // Test database connection
    await db.query('SELECT 1');
    logger.info('Database connected');

    // Test Redis connection
    await redis.ping();
    logger.info('Redis connected');

    // Initialize query engine
    await queryEngine.initialize();

    // Start workers
    if (config.compaction.enabled) {
      await compactionWorker.start();
      
      // Schedule daily compaction
      compactionTimer = scheduleTask(
        config.compaction.schedule,
        'compaction',
        () => compactionWorker.runCompaction()
      );
      
      logger.info('Compaction worker started', { schedule: config.compaction.schedule });
    }

    if (config.reconciliation.enabled) {
      await reconciliationWorker.start();
      
      // Schedule daily reconciliation
      reconciliationTimer = scheduleTask(
        config.reconciliation.schedule,
        'reconciliation',
        async () => {
          const yesterday = new Date();
          yesterday.setDate(yesterday.getDate() - 1);
          await reconciliationWorker.runReconciliation(yesterday);
        }
      );
      
      logger.info('Reconciliation worker started', { schedule: config.reconciliation.schedule });
    }

    // Run health check periodically with error handling
    healthCheckTimer = setInterval(() => {
      reconciliationWorker.quickHealthCheck()
        .then(health => {
          if (!health.healthy) {
            logger.warn('Health check issues', { issues: health.issues });
          }
        })
        .catch(err => {
          logger.error('Health check failed', { error: err instanceof Error ? err.message : err });
        });
    }, 60000); // Every minute

    logger.info('Analytics service started successfully');

    // Keep the process running
    await new Promise(() => {});

  } catch (error) {
    logger.error('Failed to start analytics service', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    process.exit(1);
  }
}

main();
