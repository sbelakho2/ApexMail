/**
 * API Server Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { createLogger } from '@apexmail/lib';
import { getDatabase } from '@apexmail/db';
import { loadConfig } from './config.js';

const logger = createLogger({ name: 'api' });

async function main(): Promise<void> {
  const config = loadConfig();
  
  logger.info('Starting ApexMail API server', {
    env: config.env,
    port: config.port,
  });

  // Initialize database pool (uses service-specific config for 'api' = 20 connections)
  const db = getDatabase('api');

  // Create the application
  const app = createApp({ db, config, logger });

  // Start the server
  const server = serve({
    fetch: app.fetch,
    port: config.port,
    hostname: config.host,
  });

  logger.info('API server started', {
    url: `http://${config.host}:${config.port}`,
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    
    server.close(async () => {
      logger.info('HTTP server closed');
      
      await db.disconnect();
      
      logger.info('Shutdown complete');
      process.exit(0);
    });

    // Force exit after timeout
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error('Fatal error starting server', { error: err });
  process.exit(1);
});
