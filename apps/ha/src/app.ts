/**
 * HA Service - Main Application
 * 
 * High Availability and Disaster Recovery service for ApexMail
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { createLogger } from '@apexmail/lib';
import { config } from './config.js';
import { haRoutes } from './routes/ha.js';

const haLogger = createLogger({ name: 'ha' });
import { HealthCheckService } from './services/health-check.js';
import { FailoverService } from './services/failover.js';
import { BackupService } from './services/backup.js';
import { ReplicationService } from './services/replication.js';
import { MultiRegionService } from './services/multi-region.js';
import { CircuitBreakerService, createDefaultCircuits } from './services/circuit-breaker.js';
import { ChaosEngineeringService } from './services/chaos.js';

type Variables = {
  db: Pool;
  redis: Redis;
  healthCheck: HealthCheckService;
  failover: FailoverService;
  backup: BackupService;
  replication: ReplicationService;
  multiRegion: MultiRegionService;
  circuitBreaker: CircuitBreakerService;
  chaos: ChaosEngineeringService;
};

// Create the application
const app = new Hono<{ Variables: Variables }>();

// Initialize database pool
const db = new Pool({
  host: config.dbHost,
  port: config.dbPort,
  database: config.database,
  user: config.dbUser,
  password: config.dbPassword,
  max: config.dbPoolMax,
  idleTimeoutMillis: config.dbIdleTimeout,
  connectionTimeoutMillis: config.dbConnectionTimeout,
});

// Initialize Redis
const redis = new Redis({
  host: config.redisHost,
  port: config.redisPort,
  password: config.redisPassword,
  db: config.redisDb,
  maxRetriesPerRequest: 3,
});

// Initialize services
const healthCheck = new HealthCheckService(db, redis);
const circuitBreaker = new CircuitBreakerService(redis);
const failover = new FailoverService(db, redis, healthCheck);
const backup = new BackupService(db, redis);
const replication = new ReplicationService(db, redis);
const multiRegion = new MultiRegionService(db, redis);
const chaos = new ChaosEngineeringService(db, redis);

// Global middleware
app.use('*', logger());
app.use('*', secureHeaders());
app.use('*', cors({
  origin: config.corsOrigins,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-API-Key'],
  exposeHeaders: ['X-Request-ID', 'X-RateLimit-Remaining'],
  maxAge: 86400,
  credentials: true,
}));

// Inject services into context
app.use('*', async (c, next) => {
  c.set('db', db);
  c.set('redis', redis);
  c.set('healthCheck', healthCheck);
  c.set('failover', failover);
  c.set('backup', backup);
  c.set('replication', replication);
  c.set('multiRegion', multiRegion);
  c.set('circuitBreaker', circuitBreaker);
  c.set('chaos', chaos);
  await next();
});

// Request ID middleware
app.use('*', async (c, next) => {
  const requestId = c.req.header('x-request-id') || crypto.randomUUID();
  c.res.headers.set('x-request-id', requestId);
  await next();
});

// Authentication middleware for non-health routes
app.use('/api/*', async (c, next) => {
  const apiKey = c.req.header('x-api-key') || c.req.header('authorization')?.replace('Bearer ', '');
  
  if (!apiKey) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  
  // Validate API key (in production, check against database)
  if (apiKey !== config.internalApiKey && apiKey !== config.adminApiKey) {
    return c.json({ error: 'Invalid API key' }, 403);
  }
  
  await next();
});

// FIX-500-025: Internal endpoints also require authentication
// Previously /internal/* was completely unauthenticated
app.use('/internal/*', async (c, next) => {
  const apiKey = c.req.header('x-api-key') || c.req.header('authorization')?.replace('Bearer ', '');
  if (!apiKey) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  if (apiKey !== config.internalApiKey && apiKey !== config.adminApiKey) {
    return c.json({ error: 'Invalid API key' }, 403);
  }
  await next();
});

// Root endpoint
app.get('/', (c) => {
  return c.json({
    service: 'ApexMail HA Service',
    version: config.version,
    region: config.region,
    environment: config.environment,
  });
});

// Mount HA routes
app.route('/api/v1', haRoutes);

// Internal endpoints (cluster communication)
app.get('/internal/state', async (c) => {
  const multiRegion = c.get('multiRegion');
  const circuitBreaker = c.get('circuitBreaker');
  
  return c.json({
    region: config.region,
    role: multiRegion.getCurrentRegion()?.role,
    health: multiRegion.getHealthSummary(),
    circuits: circuitBreaker.getAllStats(),
  });
});

app.post('/internal/sync', async (c) => {
  // Receive state updates from other regions
  const body = await c.req.json();
  haLogger.info('[HA] Received sync from region:', body.sourceRegion);
  return c.json({ received: true });
});

// Error handling
app.onError((err, c) => {
  haLogger.error('[HA] Unhandled error:', { error: err instanceof Error ? err.message : String(err) });
  
  // Check if it's a chaos-induced error
  if (err.name === 'ChaosError') {
    return c.json({
      error: err.message,
      chaos: true,
    }, (err as unknown as { statusCode: number }).statusCode || 500);
  }
  
  return c.json({
    error: 'Internal server error',
    message: config.environment === 'development' ? err.message : undefined,
  }, 500);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not found',
    path: c.req.path,
  }, 404);
});

// Initialize services
async function initializeServices(): Promise<void> {
  haLogger.info('[HA] Initializing services...');
  
  // Initialize circuit breakers first
  await circuitBreaker.initialize();
  createDefaultCircuits(circuitBreaker);
  
  // Initialize health check
  healthCheck.startMonitoring();
  
  // Initialize failover
  await failover.initialize();
  
  // Initialize backup
  await backup.initialize();
  backup.scheduleBackups();
  
  // Initialize replication
  await replication.initialize();
  replication.startMonitoring();
  
  // Initialize multi-region
  await multiRegion.initialize();
  multiRegion.startServices();
  
  // Initialize chaos engineering
  await chaos.initialize();
  
  haLogger.info('[HA] All services initialized');
}

// Graceful shutdown
async function shutdown(): Promise<void> {
  haLogger.info('[HA] Shutting down...');
  
  // Stop all services
  healthCheck.stopMonitoring();
  replication.stopMonitoring();
  multiRegion.stopServices();
  circuitBreaker.shutdown();
  chaos.shutdown();
  
  // Close database connections
  await db.end();
  
  // Close Redis connections
  await redis.quit();
  
  haLogger.info('[HA] Shutdown complete');
  process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Export for use in index.ts
export { app, initializeServices, db, redis };
