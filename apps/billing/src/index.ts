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
let shutdownHandler: ((reason: string, error?: unknown) => Promise<void>) | null = null;
let shutdownInProgress = false;

async function triggerGracefulShutdown(reason: string, error?: unknown): Promise<void> {
  if (shutdownInProgress) return;
  shutdownInProgress = true;

  logger.error('Fatal process event', {
    reason,
    error: error instanceof Error ? error.message : String(error ?? ''),
  });

  if (!shutdownHandler) {
    process.exit(1);
    return;
  }

  const forceExitTimer = setTimeout(() => {
    logger.error('Forced process exit after graceful shutdown timeout', { reason });
    process.exit(1);
  }, 15_000);
  forceExitTimer.unref();

  try {
    await shutdownHandler(reason, error);
    process.exit(1);
  } finally {
    clearTimeout(forceExitTimer);
  }
}

async function main(): Promise<void> {
  logger.info('Starting ApexMail Billing Service...');

  // Load config early
  loadConfig();

  const { app, ctx } = await createApp();

  // Graceful shutdown
  const shutdown = async (reason = 'signal', error?: unknown): Promise<void> => {
    logger.info('Shutting down billing service...', {
      reason,
      error: error instanceof Error ? error.message : String(error ?? ''),
    });

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

  };

  shutdownHandler = shutdown;

  process.on('SIGTERM', () => { void shutdown('SIGTERM').then(() => process.exit(0)); });
  process.on('SIGINT', () => { void shutdown('SIGINT').then(() => process.exit(0)); });

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

type BillingAppContext = Awaited<ReturnType<typeof createApp>>['ctx'];

async function startBackgroundWorkers(ctx: BillingAppContext): Promise<void> {
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

      const retryResult = await ctx.stripe.processScheduledRetries();
      if (retryResult.ok && retryResult.value.attempted > 0) {
        logger.info('Scheduled Stripe retries processed', retryResult.value);
      }

      const cleanupResult = await ctx.stripe.cleanupStuckSubscriptionSagas();
      if (cleanupResult.ok && cleanupResult.value.cleaned > 0) {
        logger.info('Cleaned stuck subscription sagas', cleanupResult.value);
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
  const targetTime = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
    hour,
    minute,
    0,
    0
  ));

  // If target time has passed today, schedule for tomorrow
  if (targetTime <= now) {
    targetTime.setUTCDate(targetTime.getUTCDate() + 1);
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
  void triggerGracefulShutdown('uncaughtException', error);
});

process.on('unhandledRejection', (reason) => {
  void triggerGracefulShutdown('unhandledRejection', reason);
});

main().catch((error) => {
  void triggerGracefulShutdown('main.catch', error);
});
