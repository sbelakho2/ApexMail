/**
 * Edge Cases Service Entry Point
 * 
 * Starts the HTTP server for edge case handling
 */

import { serve } from '@hono/node-server';
import { createApp, initializeServices, shutdown } from './app.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'edge-cases' });

const PORT = parseInt(process.env.EDGE_CASES_PORT || '4600', 10);
const HOST = process.env.EDGE_CASES_HOST || '0.0.0.0';

/**
 * Main entry point
 */
async function main(): Promise<void> {
  logger.info('Starting edge cases service...');
  
  try {
    // Initialize all services
    await initializeServices();
    
    // Create application
    const app = createApp();
    
    // Start HTTP server
    const server = serve({
      fetch: app.fetch,
      port: PORT,
      hostname: HOST,
    });
    
    logger.info('Edge cases service running', { host: HOST, port: PORT });

    // Available endpoints:
    // - Health: GET /health, GET /ready, GET /live
    // - EAI Validation: POST /api/v1/eai/validate
    // - Attachments: POST /api/v1/attachments/validate
    // - Calendar: POST /api/v1/calendar/invite
    // - Delivery: POST /api/v1/delivery/parse-response
    
    // Graceful shutdown handlers
    const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
    
    signals.forEach((signal) => {
      process.on(signal, async () => {
        logger.info('Received shutdown signal', { signal });
        
        try {
          // Stop accepting new connections
          server.close();
          
          // Shutdown services
          await shutdown();
          
          logger.info('Graceful shutdown complete');
          process.exit(0);
        } catch (error) {
          logger.error('Error during shutdown', { error: error instanceof Error ? error.message : String(error) });
          process.exit(1);
        }
      });
    });
    
    // Unhandled rejection handler
    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
    });
    
    // Uncaught exception handler
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', { error: error.message, stack: error.stack });
      process.exit(1);
    });
    
  } catch (error) {
    logger.error('Failed to start service', { error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  }
}

// Start the service
main();
