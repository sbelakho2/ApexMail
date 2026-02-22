/**
 * Billing Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { config, loadConfig } from './config.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'billing' });

// Track interval handles for cleanup
const intervalHandles: NodeJS.Timeout[] = [];
const timeoutHandles: NodeJS.Timeout[] = [];

async function main(): Promise<void> {
  logger.info('Starting ApexMail Billing Service...');

  // Load config early
  loadConfig();

  const { app, ctx } = createApp();

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    logger.info('Shutting down billing service...');

    // Clear all intervals first to prevent callbacks executing after cleanup
    for (const handle of intervalHandles) {
      clearInterval(handle);
    }
    for (const handle of timeoutHandles) {
      clearTimeout(handle);
    }
    logger.info(`Cleared ${intervalHandles.length} intervals and ${timeoutHandles.length} timeouts`);

    // FIX-500-364: Shutdown metering service (clears its internal flush timer)
    await ctx.metering.shutdown();

    // Stop dedicated IP billing sync
    ctx.dedicatedIpBilling.stopSync();

    // Close Redis connection
    await ctx.redis.quit();

    // Close database pool
    await ctx.db.disconnect();

    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  // Start server
  serve({
    fetch: app.fetch,
    port: config.port,
    hostname: config.host,
  });

  logger.info(`Billing service running on http://${config.host}:${config.port}`);

  // Start background workers
  await startBackgroundWorkers(ctx);
}

async function startBackgroundWorkers(ctx: ReturnType<typeof createApp>['ctx']): Promise<void> {
  logger.info('Starting background workers...');

  // Recover any metering events that were pending when the process last stopped.
  // CRITICAL: must run before the periodic flush to prevent data loss.
  try {
    const recovered = await ctx.metering.recoverPendingEvents();
    if (recovered.ok && recovered.value > 0) {
      logger.info('Recovered pending metering events from Redis', { count: recovered.value });
    }
  } catch (error) {
    logger.error('Failed to recover pending metering events', {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  // Usage alert checker - runs every 5 minutes
  const usageAlertInterval = setInterval(async () => {
    try {
      const result = await ctx.usageAlerts.checkAllTenants();
      if (result.ok) {
        logger.info('Usage alerts checked', { tenantsChecked: result.value.tenantsChecked });
      }
    } catch (error) {
      logger.error('Usage alert check failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 5 * 60 * 1000);
  usageAlertInterval.unref();
  intervalHandles.push(usageAlertInterval);

  // Metering flush - runs every minute
  const meteringInterval = setInterval(async () => {
    try {
      const result = await ctx.metering.flush();
      if (result.ok && result.value > 0) {
        logger.info('Flushed metering events', { count: result.value });
      }
    } catch (error) {
      logger.error('Metering flush failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 60 * 1000);
  meteringInterval.unref();
  intervalHandles.push(meteringInterval);

  // Dunning processor - runs every hour
  const dunningInterval = setInterval(async () => {
    try {
      const result = await ctx.dunning.processGracePeriodExpirations();
      if (result.ok) {
        logger.info('Dunning processed', { processedCount: result.value.processedCount });
      }
    } catch (error) {
      logger.error('Dunning processing failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 60 * 60 * 1000);
  dunningInterval.unref();
  intervalHandles.push(dunningInterval);

  // SLA credits checker - runs daily at midnight
  scheduleDailyTask(async () => {
    try {
      const result = await ctx.slaCredits.runMonthlyCheck();
      if (result.ok) {
        logger.info('SLA credits processed', { totalCredits: result.value.totalCredits });
      }
    } catch (error) {
      logger.error('SLA credits processing failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 0, 0); // 00:00

  // Cost margin checker - runs every 15 minutes
  const costMarginInterval = setInterval(async () => {
    try {
      const result = await ctx.costCircuit.runMarginChecks();
      if (result.ok) {
        logger.info('Cost margins checked', { checked: result.value.checked });
      }
    } catch (error) {
      logger.error('Cost margin check failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 15 * 60 * 1000);
  costMarginInterval.unref();
  intervalHandles.push(costMarginInterval);

  // Wallet cleanup (expired reservations) - runs every 30 minutes
  const walletInterval = setInterval(async () => {
    try {
      const result = await ctx.wallet.processExpiredReservations();
      if (result.ok && result.value.releasedCount > 0) {
        logger.info('Cleaned up expired wallet reservations', { releasedCount: result.value.releasedCount });
      }
    } catch (error) {
      logger.error('Wallet cleanup failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 30 * 60 * 1000);
  walletInterval.unref();
  intervalHandles.push(walletInterval);

  // Enterprise contract checker - runs daily at 06:00
  scheduleDailyTask(async () => {
    try {
      const result = await ctx.contracts.checkExpiringContracts();
      if (result.ok) {
        logger.info('Contract check complete', { expiringSoon: result.value.expiringSoon.length });
      }
    } catch (error) {
      logger.error('Contract check failed', { error: error instanceof Error ? error.message : String(error) });
    }
  }, 6, 0); // 06:00

  logger.info('Background workers started');
}

function scheduleDailyTask(task: () => Promise<void>, hour: number, minute: number): void {
  const now = new Date();
  const targetTime = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    hour,
    minute,
    0,
    0
  );

  // If target time has passed today, schedule for tomorrow
  if (targetTime <= now) {
    targetTime.setDate(targetTime.getDate() + 1);
  }

  const msUntilTarget = targetTime.getTime() - now.getTime();

  const timeout = setTimeout(() => {
    // Run the task
    task().catch((err) => logger.error('Scheduled daily task failed', { error: err instanceof Error ? err.message : String(err) }));

    // Schedule for next day
    const interval = setInterval(() => {
      task().catch((err) => logger.error('Scheduled daily task failed', { error: err instanceof Error ? err.message : String(err) }));
    }, 24 * 60 * 60 * 1000);
    interval.unref();
    intervalHandles.push(interval);
  }, msUntilTarget);
  timeout.unref();
  timeoutHandles.push(timeout);
}

// Global error handlers
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
  process.exit(1);
});

main().catch((error) => {
  logger.error('Fatal error', { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});
