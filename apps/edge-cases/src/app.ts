/**
 * Edge Cases Application
 * 
 * Main application for email edge case handling
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import net from 'net'; // FIX-500-407: Static import instead of dynamic

import { createLogger } from '@apexmail/lib';
import { config } from './config.js';
import { EAIService } from './services/eai.js';

const edgeLogger = createLogger({ name: 'edge-cases' });
import { AttachmentService } from './services/attachment.js';
import { CalendarService } from './services/calendar.js';
import { DeliveryService } from './services/delivery.js';
import { createEdgeCaseRoutes } from './routes/edge-cases.js';

// Service instances
let eaiService: EAIService;
let attachmentService: AttachmentService;
let calendarService: CalendarService;
let deliveryService: DeliveryService;

// Database pool
let pool: Pool;
let redis: Redis;

/**
 * Initialize all services
 */
async function initializeServices(): Promise<void> {
  // Create database pool
  pool = new Pool({
    host: config.database.host,
    port: config.database.port,
    database: config.database.database,
    user: config.database.user,
    password: config.database.password,
    ssl: config.database.ssl ? { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Test database connection
  await pool.query('SELECT 1');
  edgeLogger.info('[EdgeCases] Database connection established');

  // Create Redis connection
  redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    db: config.redis.db,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => Math.min(times * 100, 3000),
  });

  redis.on('connect', () => {
    edgeLogger.info('[EdgeCases] Redis connection established');
  });

  redis.on('error', (error: Error) => {
    edgeLogger.error('[EdgeCases] Redis error:', { error: error instanceof Error ? error.message : String(error) });
  });

  // Initialize services
  eaiService = new EAIService(pool, redis);
  attachmentService = new AttachmentService(pool, redis);
  calendarService = new CalendarService(pool, redis);
  deliveryService = new DeliveryService(pool, redis);

  edgeLogger.info('[EdgeCases] All services initialized');
}

/**
 * Create Hono application
 */
export function createApp(): Hono {
  const app = new Hono();

  // Global middleware
  app.use('*', logger());
  app.use('*', cors({
    origin: config.cors.origins,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    exposeHeaders: ['X-Request-ID'],
    credentials: true,
    maxAge: 86400,
  }));
  app.use('*', prettyJSON());
  app.use('*', compress());
  app.use('*', secureHeaders());

  // Request ID middleware
  app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();
    c.header('X-Request-ID', requestId);
    await next();
  });

  // Health check endpoint
  app.get('/health', async (c) => {
    const checks: Record<string, { status: string; latency?: number }> = {};
    
    // Database health
    const dbStart = Date.now();
    try {
      await pool.query('SELECT 1');
      checks.database = { status: 'healthy', latency: Date.now() - dbStart };
    } catch (error) {
      checks.database = { status: 'unhealthy' };
    }
    
    // Redis health
    const redisStart = Date.now();
    try {
      await redis.ping();
      checks.redis = { status: 'healthy', latency: Date.now() - redisStart };
    } catch (error) {
      checks.redis = { status: 'unhealthy' };
    }

    // ClamAV health (if enabled) — FIX-500-149: real TCP PING check
    if (config.clamav.enabled) {
      const clamStart = Date.now();
      try {
        const clamPong = await new Promise<string>((resolve, reject) => {
          const socket = new net.Socket();
          socket.setTimeout(config.clamav.timeout ?? 5000);
          let data = '';
          socket.connect(config.clamav.port, config.clamav.host, () => {
            socket.write('nPING\n');
          });
          socket.on('data', (chunk: Buffer) => { data += chunk.toString(); });
          socket.on('end', () => { socket.destroy(); resolve(data.trim()); });
          socket.on('timeout', () => { socket.destroy(); reject(new Error('ClamAV timeout')); });
          socket.on('error', (err: Error) => { socket.destroy(); reject(err); });
        });
        checks.clamav = {
          status: clamPong === 'PONG' ? 'healthy' : 'unhealthy',
          latency: Date.now() - clamStart,
        };
      } catch {
        checks.clamav = { status: 'unhealthy', latency: Date.now() - clamStart };
      }
    }
    
    const overallStatus = checks.database.status === 'healthy' && checks.redis.status === 'healthy'
      ? 'healthy'
      : 'degraded';
    
    return c.json({
      status: overallStatus,
      version: '1.0.0',
      uptime: process.uptime(),
      checks,
      config: {
        maxAttachmentSize: config.attachments.maxSingleAttachmentSize,
        maxMessageSize: config.attachments.maxTotalMessageSize,
        maxHops: config.loopDetection.maxHops,
        clamavEnabled: config.clamav.enabled,
      },
      timestamp: new Date().toISOString(),
    }, overallStatus === 'healthy' ? 200 : 503);
  });

  // Readiness check
  app.get('/ready', async (c) => {
    try {
      await pool.query('SELECT 1');
      await redis.ping();
      return c.json({ ready: true });
    } catch (error) {
      return c.json({ ready: false }, 503);
    }
  });

  // Liveness check
  app.get('/live', (c) => {
    return c.json({ live: true });
  });

  // Mount edge case routes
  app.route('/api/v1', createEdgeCaseRoutes(
    eaiService,
    attachmentService,
    calendarService,
    deliveryService
  ));

  // Error handling
  app.onError((error, c) => {
    edgeLogger.error('[EdgeCases] Unhandled error:', { error: error instanceof Error ? error.message : String(error) });
    
    return c.json({
      error: 'Internal server error',
      requestId: c.res.headers.get('X-Request-ID'),
    }, 500);
  });

  // Not found handler
  app.notFound((c) => {
    return c.json({
      error: 'Not found',
      path: c.req.path,
    }, 404);
  });

  return app;
}

/**
 * Shutdown services gracefully
 */
export async function shutdown(): Promise<void> {
  edgeLogger.info('[EdgeCases] Shutting down services...');
  
  // Close Redis connection
  if (redis) {
    await redis.quit();
    edgeLogger.info('[EdgeCases] Redis connection closed');
  }
  
  // Close database pool
  if (pool) {
    await pool.end();
    edgeLogger.info('[EdgeCases] Database connection closed');
  }
  
  edgeLogger.info('[EdgeCases] Shutdown complete');
}

/**
 * Get service instances (for testing)
 */
export function getServices() {
  return {
    eaiService,
    attachmentService,
    calendarService,
    deliveryService,
    pool,
    redis,
  };
}

export { initializeServices };
