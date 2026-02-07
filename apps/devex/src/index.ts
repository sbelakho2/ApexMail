/**
 * DevEx Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp, createDbPool, config } from './app.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'devex' });

async function main() {
  logger.info('Starting DevEx service...');

  // Create database pool
  const db = createDbPool();

  // Verify database connection
  try {
    await db.query('SELECT 1');
    logger.info('Database connection established');
  } catch (error) {
    logger.error('Failed to connect to database', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }

  // Create app
  const app = createApp(db);

  // Start server
  const server = serve({
    fetch: app.fetch,
    port: config.port,
  });

  logger.info('DevEx service running', { port: config.port, apiVersion: config.currentApiVersion, env: config.nodeEnv });

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down DevEx service...');
    
    server.close();
    await db.end();
    
    logger.info('DevEx service stopped');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((error) => {
  logger.error('Fatal error', { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});
