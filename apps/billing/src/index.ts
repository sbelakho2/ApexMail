/**
 * Billing Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { config } from './config.js';

async function main(): Promise<void> {
  console.log('Starting ApexMail Billing Service...');

  const { app, ctx } = createApp();

  // Graceful shutdown
  const shutdown = async (): Promise<void> => {
    console.log('Shutting down billing service...');

    // Close Redis connection
    await ctx.redis.quit();

    // Close database pool
    await ctx.db.end();

    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  // Start server
  const server = serve({
    fetch: app.fetch,
    port: config.port,
    hostname: config.host,
  });

  console.log(`Billing service running on http://${config.host}:${config.port}`);

  // Start background workers
  await startBackgroundWorkers(ctx);
}

async function startBackgroundWorkers(ctx: ReturnType<typeof createApp>['ctx']): Promise<void> {
  console.log('Starting background workers...');

  // Usage alert checker - runs every 5 minutes
  setInterval(async () => {
    try {
      const result = await ctx.usageAlerts.checkAllTenants();
      if (result.ok) {
        console.log(`Usage alerts checked: ${result.value.checked} tenants`);
      }
    } catch (error) {
      console.error('Usage alert check failed:', error);
    }
  }, 5 * 60 * 1000);

  // Metering flush - runs every minute
  setInterval(async () => {
    try {
      const result = await ctx.metering.flushPendingEvents();
      if (result.ok && result.value > 0) {
        console.log(`Flushed ${result.value} metering events`);
      }
    } catch (error) {
      console.error('Metering flush failed:', error);
    }
  }, 60 * 1000);

  // Dunning processor - runs every hour
  setInterval(async () => {
    try {
      const result = await ctx.dunning.processAll();
      if (result.ok) {
        console.log(`Dunning processed: ${result.value.processed} accounts`);
      }
    } catch (error) {
      console.error('Dunning processing failed:', error);
    }
  }, 60 * 60 * 1000);

  // SLA credits checker - runs daily at midnight
  scheduleDailyTask(async () => {
    try {
      const result = await ctx.slaCredits.processMonthlyCredits();
      if (result.ok) {
        console.log(`SLA credits processed: ${result.value.credits} credits issued`);
      }
    } catch (error) {
      console.error('SLA credits processing failed:', error);
    }
  }, 0, 0); // 00:00

  // Cost margin checker - runs every 15 minutes
  setInterval(async () => {
    try {
      const result = await ctx.costCircuit.checkAllTenants();
      if (result.ok) {
        console.log(`Cost margins checked: ${result.value.checked} tenants`);
      }
    } catch (error) {
      console.error('Cost margin check failed:', error);
    }
  }, 15 * 60 * 1000);

  // Wallet cleanup (expired reservations) - runs every 30 minutes
  setInterval(async () => {
    try {
      const result = await ctx.wallet.cleanupExpiredReservations();
      if (result.ok && result.value > 0) {
        console.log(`Cleaned up ${result.value} expired wallet reservations`);
      }
    } catch (error) {
      console.error('Wallet cleanup failed:', error);
    }
  }, 30 * 60 * 1000);

  // Enterprise contract checker - runs daily at 06:00
  scheduleDailyTask(async () => {
    try {
      const result = await ctx.contracts.checkExpiringContracts();
      if (result.ok) {
        console.log(`Contract check: ${result.value.expiring} contracts expiring soon`);
      }
    } catch (error) {
      console.error('Contract check failed:', error);
    }
  }, 6, 0); // 06:00

  // Viral attribution processor - runs every 10 minutes
  setInterval(async () => {
    try {
      const result = await ctx.viralLoop.processUnattributedConversions();
      if (result.ok && result.value > 0) {
        console.log(`Attributed ${result.value} viral conversions`);
      }
    } catch (error) {
      console.error('Viral attribution failed:', error);
    }
  }, 10 * 60 * 1000);

  console.log('Background workers started');
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

  setTimeout(() => {
    // Run the task
    task().catch(console.error);

    // Schedule for next day
    setInterval(() => {
      task().catch(console.error);
    }, 24 * 60 * 60 * 1000);
  }, msUntilTarget);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
