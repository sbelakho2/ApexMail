/**
 * Enterprise Service Entry Point
 * 
 * Starts the enterprise HTTP server and background jobs
 */

import { serve } from '@hono/node-server';
import { Pool } from 'pg';
import IORedis from 'ioredis';
import { createApp, BackgroundJobScheduler } from './app.js';
import { config } from './config.js';

// Initialize database connection pool
const pool = new Pool({
  host: config.database.host,
  port: config.database.port,
  database: config.database.name,
  user: config.database.user,
  password: config.database.password,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Initialize Redis client
const redis = new IORedis.default({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password || undefined,
  db: config.redis.db,
  retryStrategy: (times: number) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 3,
  lazyConnect: true,
});

// Graceful shutdown handler
let isShuttingDown = false;
const connections = new Set<any>();

async function gracefulShutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`\nReceived ${signal}. Starting graceful shutdown...`);

  // Stop accepting new connections
  server.close(() => {
    console.log('HTTP server closed');
  });

  // Stop background jobs
  backgroundScheduler.stop();

  // Close existing connections with timeout
  const closeTimeout = setTimeout(() => {
    console.log('Forcing remaining connections closed');
    connections.forEach((conn) => conn.destroy());
  }, 10000);

  // Wait for connections to close
  await Promise.all([
    // Close database pool
    pool.end().then(() => console.log('Database pool closed')),
    // Close Redis connection
    redis.quit().then(() => console.log('Redis connection closed')),
  ]);

  clearTimeout(closeTimeout);
  console.log('Graceful shutdown complete');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
});

// Create application
const app = createApp({ pool, redis });

// Create background job scheduler
const backgroundScheduler = new BackgroundJobScheduler(pool, redis);

// Start server
const server = serve({
  fetch: app.fetch,
  port: config.server.port,
}, async (info) => {
  console.log(`Enterprise service starting on port ${info.port}...`);
  
  // Test database connection
  try {
    await pool.query('SELECT 1');
    console.log('✓ Database connection established');
  } catch (error) {
    console.error('✗ Database connection failed:', error);
    process.exit(1);
  }

  // Test Redis connection
  try {
    await redis.connect();
    await redis.ping();
    console.log('✓ Redis connection established');
  } catch (error) {
    console.error('✗ Redis connection failed:', error);
    process.exit(1);
  }

  // Start background jobs
  backgroundScheduler.start();
  console.log('✓ Background job scheduler started');

  console.log(`\n🚀 Enterprise service is running at http://localhost:${info.port}`);
  console.log('\nAvailable endpoints:');
  console.log('  SSO:              /api/sso/*');
  console.log('  Sub-Accounts:     /api/sub-accounts/*');
  console.log('  White-Label:      /api/whitelabel/*');
  console.log('  Templates:        /api/templates/*');
  console.log('  Log Streaming:    /api/log-streams/*');
  console.log('  Compliance:       /api/compliance/*');
  console.log('  Deployments:      /api/deployments/*');
  console.log('  Support:          /api/support/*');
  console.log('  QBR:              /api/qbr/*');
  console.log('  Health:           /api/health');
});

// Track connections for graceful shutdown
server.on('connection', (conn: any) => {
  connections.add(conn);
  conn.on('close', () => connections.delete(conn));
});

export { app, pool, redis, backgroundScheduler };
