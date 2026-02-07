/**
 * HA Service - Entry Point
 */

import { serve } from '@hono/node-server';
import { app, initializeServices } from './app.js';
import { config } from './config.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'ha' });

async function main(): Promise<void> {
  try {
    // Initialize all services
    await initializeServices();
    
    // Start HTTP server
    const server = serve({
      fetch: app.fetch,
      port: config.port,
    });
    
    logger.info('High Availability service running', {
      port: config.port,
      environment: config.environment,
      region: config.region,
    });
    
    // Handle server errors
    server.on('error', (err) => {
      logger.error('Server error', { error: err.message, stack: err.stack });
      process.exit(1);
    });
    
  } catch (error) {
    logger.error('Failed to start', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }
}

main();
