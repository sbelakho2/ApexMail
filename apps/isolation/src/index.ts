/**
 * Multi-Tenant Isolation Service Entry Point
 * 
 * Starts the HTTP server for tenant isolation
 */

import { serve } from '@hono/node-server';
import { createApp, initializeServices, shutdown } from './app.js';
import { createLogger } from '@apexmail/lib';

const logger = createLogger({ name: 'isolation' });

const PORT = parseInt(process.env.ISOLATION_PORT || '4500', 10);
const HOST = process.env.ISOLATION_HOST || '0.0.0.0';

/**
 * Main entry point
 */
async function main(): Promise<void> {
  logger.info('Starting multi-tenant isolation service...');
  
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
    
    logger.info('Isolation service running', { host: HOST, port: PORT });

    // Available endpoints:
    // - Health: GET /health, GET /ready, GET /live
    // - Organizations: /api/v1/organizations
    // - Workspaces: /api/v1/workspaces
    // - Isolation: /api/v1/isolation
    // - Audit: /api/v1/organizations/:orgId/audit
    
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
