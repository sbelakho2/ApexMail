/**
 * MTA Entry Point - Inbound mail, bounce, and feedback loop handling
 */

import { createServer, type Server } from 'http';
import { createLogger } from '@apexmail/lib';
import { Pool } from 'pg';
import { loadConfig } from './config.js';
import { InboundServer } from './servers/inbound.js';
import { BounceServer } from './servers/bounce.js';
import { FeedbackLoopServer } from './servers/feedback-loop.js';
import { Redis } from 'ioredis';

const logger = createLogger({ name: 'mta' });
const config = loadConfig();

let isShuttingDown = false;
const servers: Array<{ stop: () => Promise<void> }> = [];
let healthServer: Server | null = null;
let dbPool: Pool | null = null;
let redisClient: Redis | null = null;

async function main(): Promise<void> {
  logger.info('Starting ApexMail MTA', {
    mtaId: config.mtaId,
    nodeEnv: config.nodeEnv,
  });

  // Create database pool
  dbPool = new Pool({
    connectionString: config.database.connectionString,
    max: config.database.maxConnections,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Test database connection
  try {
    const client = await dbPool.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    logger.info('Database connected', { serverTime: result.rows[0]?.now ?? 'unknown' });
  } catch (error) {
    logger.fatal('Failed to connect to database', { error });
    process.exit(1);
  }

  // Create Redis client
  redisClient = new Redis(config.redis.url, {
    keyPrefix: config.redis.keyPrefix,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => {
      if (times > 10) return null;
      return Math.min(times * 100, 3000);
    },
    lazyConnect: true,
  });

  // C-078: Handle Redis connection errors to prevent uncaught exceptions
  redisClient.on('error', (err: Error) => {
    logger.error('Redis connection error', { error: err.message });
  });

  try {
    await redisClient.connect();
    logger.info('Redis connected');
  } catch (error) {
    logger.fatal('Failed to connect to Redis', { error });
    process.exit(1);
  }

  // Start health check HTTP server for Kubernetes probes
  await startHealthServer(config.healthPort);

  // Start inbound mail server
  if (config.inbound.enabled) {
    const inboundServer = new InboundServer({
      db: dbPool,
      redis: redisClient,
      config: config.inbound,
      rateLimit: config.rateLimit,
      emailAuth: {
        requireSPF: config.emailAuth?.requireSPF ?? true,
        requireDKIM: config.emailAuth?.requireDKIM ?? true,
        enforceDMARC: config.emailAuth?.enforceDMARC ?? true,
        allowSoftFail: config.emailAuth?.allowSoftFail ?? true,
        trustedRelays: config.emailAuth?.trustedRelays ?? [],
      },
      logger: logger.child({ server: 'inbound' }),
    });

    await inboundServer.start();
    servers.push(inboundServer);
  }

  // Start bounce handling server
  if (config.bounce.enabled) {
    const bounceServer = new BounceServer({
      db: dbPool,
      redis: redisClient,
      config: {
        ...config.bounce,
        maxMessageSize: config.inbound.maxMessageSize,
      },
      logger: logger.child({ server: 'bounce' }),
    });

    await bounceServer.start();
    servers.push(bounceServer);
  }

  // Start feedback loop server
  if (config.feedback.enabled) {
    const feedbackServer = new FeedbackLoopServer({
      db: dbPool,
      redis: redisClient,
      config: {
        ...config.feedback,
        maxMessageSize: config.inbound.maxMessageSize,
      },
      logger: logger.child({ server: 'feedback' }),
    });

    await feedbackServer.start();
    servers.push(feedbackServer);
  }

  logger.info('All MTA servers started', {
    inbound: config.inbound.enabled,
    bounce: config.bounce.enabled,
    feedback: config.feedback.enabled,
  });
}

/**
 * Start HTTP health check server for Kubernetes liveness/readiness probes
 */
async function startHealthServer(port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    healthServer = createServer(async (req, res) => {
      if (req.url === '/health' && req.method === 'GET') {
        // Basic liveness check
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
      } else if (req.url === '/ready' && req.method === 'GET') {
        // Readiness check - verify DB and Redis are accessible
        try {
          const checks: Record<string, boolean> = {};
          
          // Check database
          if (dbPool) {
            const client = await dbPool.connect();
            await client.query('SELECT 1');
            client.release();
            checks.database = true;
          } else {
            checks.database = false;
          }
          
          // Check Redis
          if (redisClient && redisClient.status === 'ready') {
            await redisClient.ping();
            checks.redis = true;
          } else {
            checks.redis = false;
          }
          
          const allReady = Object.values(checks).every(Boolean);
          res.writeHead(allReady ? 200 : 503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: allReady ? 'ready' : 'not_ready', checks }));
        } catch (error) {
          logger.warn('Readiness check failed', { error: error instanceof Error ? error.message : String(error) });
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            status: 'error', 
            error: 'Readiness check failed' 
          }));
        }
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    healthServer.on('error', (error) => {
      logger.error('Health server error', { error });
      reject(error);
    });

    healthServer.listen(port, () => {
      logger.info('Health server started', { port });
      resolve();
    });
  });
}

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress, forcing exit');
    process.exit(1);
  }

  isShuttingDown = true;
  logger.info('Graceful shutdown initiated', { signal });

  const timeout = setTimeout(() => {
    logger.error('Graceful shutdown timeout, forcing exit');
    process.exit(1);
  }, config.gracefulShutdownTimeout);

  try {
    // Stop health server first
    if (healthServer) {
      await new Promise<void>((resolve) => {
        healthServer!.close(() => resolve());
      });
    }

    // Stop all servers
    await Promise.all(servers.map(s => s.stop()));

    logger.info('All servers stopped');
    clearTimeout(timeout);
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown', { error });
    clearTimeout(timeout);
    process.exit(1);
  }
}

// Signal handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  logger.fatal('Uncaught exception', { error });
  shutdown('uncaughtException').catch(() => process.exit(1));
});

process.on('unhandledRejection', (reason) => {
  logger.fatal('Unhandled rejection', { reason });
  shutdown('unhandledRejection').catch(() => process.exit(1));
});

// Re-export authentication and enhancement modules
export * from './auth/index.js';
export { GmailAnnotationsService, createGmailAnnotationsService } from './gmail-annotations.js';

// Start the MTA
main().catch((error) => {
  logger.fatal('Failed to start MTA', { error });
  process.exit(1);
});
