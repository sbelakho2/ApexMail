/**
 * Edge Cases Service Entry Point
 * 
 * Starts the HTTP server for edge case handling
 */

import { serve } from '@hono/node-server';
import { createApp, initializeServices, shutdown } from './app.js';

const PORT = parseInt(process.env.EDGE_CASES_PORT || '4600', 10);
const HOST = process.env.EDGE_CASES_HOST || '0.0.0.0';

/**
 * Main entry point
 */
async function main(): Promise<void> {
  console.log('[EdgeCases] Starting edge cases service...');
  
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
    
    console.log(`[EdgeCases] Server running on http://${HOST}:${PORT}`);
    console.log('[EdgeCases] Endpoints:');
    console.log('  - Health: GET /health');
    console.log('  - Ready: GET /ready');
    console.log('  - Live: GET /live');
    console.log('  - EAI Validation: POST /api/v1/eai/validate');
    console.log('  - Attachments: POST /api/v1/attachments/validate');
    console.log('  - Calendar: POST /api/v1/calendar/invite');
    console.log('  - Delivery: POST /api/v1/delivery/parse-response');
    
    // Graceful shutdown handlers
    const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
    
    signals.forEach((signal) => {
      process.on(signal, async () => {
        console.log(`\n[EdgeCases] Received ${signal}, starting graceful shutdown...`);
        
        try {
          // Stop accepting new connections
          server.close();
          
          // Shutdown services
          await shutdown();
          
          console.log('[EdgeCases] Graceful shutdown complete');
          process.exit(0);
        } catch (error) {
          console.error('[EdgeCases] Error during shutdown:', error);
          process.exit(1);
        }
      });
    });
    
    // Unhandled rejection handler
    process.on('unhandledRejection', (reason, promise) => {
      console.error('[EdgeCases] Unhandled Rejection at:', promise, 'reason:', reason);
    });
    
    // Uncaught exception handler
    process.on('uncaughtException', (error) => {
      console.error('[EdgeCases] Uncaught Exception:', error);
      process.exit(1);
    });
    
  } catch (error) {
    console.error('[EdgeCases] Failed to start service:', error);
    process.exit(1);
  }
}

// Start the service
main();
