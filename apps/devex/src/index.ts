/**
 * DevEx Service Entry Point
 */

import { serve } from '@hono/node-server';
import { createApp, createDbPool, config } from './app.js';

async function main() {
  console.log('Starting DevEx service...');

  // Create database pool
  const db = createDbPool();

  // Verify database connection
  try {
    await db.query('SELECT 1');
    console.log('Database connection established');
  } catch (error) {
    console.error('Failed to connect to database:', error);
    process.exit(1);
  }

  // Create app
  const app = createApp(db);

  // Start server
  const server = serve({
    fetch: app.fetch,
    port: config.port,
  });

  console.log(`DevEx service running on port ${config.port}`);
  console.log(`API Version: ${config.currentApiVersion}`);
  console.log(`Environment: ${config.nodeEnv}`);

  // Graceful shutdown
  const shutdown = async () => {
    console.log('Shutting down DevEx service...');
    
    server.close();
    await db.end();
    
    console.log('DevEx service stopped');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
