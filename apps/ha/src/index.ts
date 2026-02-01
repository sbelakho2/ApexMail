/**
 * HA Service - Entry Point
 */

import { serve } from '@hono/node-server';
import { app, initializeServices } from './app.js';
import { config } from './config.js';

async function main(): Promise<void> {
  try {
    // Initialize all services
    await initializeServices();
    
    // Start HTTP server
    const server = serve({
      fetch: app.fetch,
      port: config.port,
    });
    
    console.log(`[HA] High Availability service running on port ${config.port}`);
    console.log(`[HA] Environment: ${config.environment}`);
    console.log(`[HA] Region: ${config.region}`);
    console.log(`[HA] Health: http://localhost:${config.port}/api/v1/health`);
    
    // Handle server errors
    server.on('error', (err) => {
      console.error('[HA] Server error:', err);
      process.exit(1);
    });
    
  } catch (error) {
    console.error('[HA] Failed to start:', error);
    process.exit(1);
  }
}

main();
