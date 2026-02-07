/**
 * Observability Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp, shutdown } from './app.js';
import { config } from './config.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'observability' });

async function main(): Promise<void> {
  logger.info('Starting observability service...');

  const { app, context } = await createApp();

  const server = serve({
    fetch: app.fetch,
    port: config.port,
  });

  logger.info('Observability service listening', { port: config.port });

  // Graceful shutdown handlers
  const handleShutdown = async (signal: string) => {
    logger.info('Received shutdown signal', { signal });
    
    server.close(async () => {
      await shutdown(context);
      process.exit(0);
    });

    // Force exit after timeout
    const forceTimer = setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
    forceTimer.unref();
  };

  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));

  // Handle uncaught errors
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception', { error: error.message, stack: error.stack });
    handleShutdown('uncaughtException');
  });

  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
  });
}

main().catch((error) => {
  logger.error('Failed to start', { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});
