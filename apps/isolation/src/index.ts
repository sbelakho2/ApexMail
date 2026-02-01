/**
 * Multi-Tenant Isolation Service Entry Point
 * 
 * Starts the HTTP server for tenant isolation
 */

import { serve } from '@hono/node-server';
import { createApp, initializeServices, shutdown } from './app.js';

const PORT = parseInt(process.env.ISOLATION_PORT || '4500', 10);
const HOST = process.env.ISOLATION_HOST || '0.0.0.0';

/**
 * Main entry point
 */
async function main(): Promise<void> {
  console.log('[Isolation] Starting multi-tenant isolation service...');
  
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
    
    console.log(`[Isolation] Server running on http://${HOST}:${PORT}`);
    console.log('[Isolation] Endpoints:');
    console.log('  - Health: GET /health');
    console.log('  - Ready: GET /ready');
    console.log('  - Live: GET /live');
    console.log('  - Organizations: /api/v1/organizations');
    console.log('  - Workspaces: /api/v1/workspaces');
    console.log('  - Isolation: /api/v1/isolation');
    console.log('  - Audit: /api/v1/organizations/:orgId/audit');
    
    // Graceful shutdown handlers
    const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
    
    signals.forEach((signal) => {
      process.on(signal, async () => {
        console.log(`\n[Isolation] Received ${signal}, starting graceful shutdown...`);
        
        try {
          // Stop accepting new connections
          server.close();
          
          // Shutdown services
          await shutdown();
          
          console.log('[Isolation] Graceful shutdown complete');
          process.exit(0);
        } catch (error) {
          console.error('[Isolation] Error during shutdown:', error);
          process.exit(1);
        }
      });
    });
    
    // Unhandled rejection handler
    process.on('unhandledRejection', (reason, promise) => {
      console.error('[Isolation] Unhandled Rejection at:', promise, 'reason:', reason);
    });
    
    // Uncaught exception handler
    process.on('uncaughtException', (error) => {
      console.error('[Isolation] Uncaught Exception:', error);
      process.exit(1);
    });
    
  } catch (error) {
    console.error('[Isolation] Failed to start service:', error);
    process.exit(1);
  }
}

// Start the service
main();
