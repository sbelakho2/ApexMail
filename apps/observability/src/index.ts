/**
 * Observability Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp, shutdown } from './app.js';
import { config } from './config.js';

async function main(): Promise<void> {
  console.log('[Observability] Starting service...');

  const { app, context } = await createApp();

  const server = serve({
    fetch: app.fetch,
    port: config.port,
  });

  console.log(`[Observability] Service listening on port ${config.port}`);

  // Graceful shutdown handlers
  const handleShutdown = async (signal: string) => {
    console.log(`[Observability] Received ${signal}, shutting down...`);
    
    server.close(async () => {
      await shutdown(context);
      process.exit(0);
    });

    // Force exit after timeout
    setTimeout(() => {
      console.error('[Observability] Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));

  // Handle uncaught errors
  process.on('uncaughtException', (error) => {
    console.error('[Observability] Uncaught exception:', error);
    handleShutdown('uncaughtException');
  });

  process.on('unhandledRejection', (reason) => {
    console.error('[Observability] Unhandled rejection:', reason);
  });
}

main().catch((error) => {
  console.error('[Observability] Failed to start:', error);
  process.exit(1);
});
