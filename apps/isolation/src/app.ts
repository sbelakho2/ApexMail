/**
 * Multi-Tenant Isolation Application
 * 
 * Main application entry point for tenant isolation services
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger as honoLogger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { createLogger } from '@apexmail/lib';

import { config } from './config.js';

const logger = createLogger({ name: 'isolation:app' });
import { TenantService } from './services/tenant.js';
import { DataIsolationService } from './services/data-isolation.js';
import { EncryptionService } from './services/encryption.js';
import { RateLimitService } from './services/rate-limit.js';
import { AuditService, AuditEventType, AuditSeverity } from './services/audit.js';
import { createIsolationRoutes } from './routes/isolation.js';

// Service instances
let tenantService: TenantService;
let dataIsolationService: DataIsolationService;
let encryptionService: EncryptionService;
let rateLimitService: RateLimitService;
let auditService: AuditService;

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
    ssl: (config.database as { ssl?: boolean }).ssl ? { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Test database connection
  await pool.query('SELECT 1');
  logger.info('[Isolation] Database connection established');

  // Create Redis connection
  redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password ?? undefined,
    db: config.redis.db,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => Math.min(times * 100, 3000),
  });

  redis.on('connect', () => {
    logger.info('[Isolation] Redis connection established');
  });

  redis.on('error', (error: Error) => {
    logger.error('[Isolation] Redis error:', { error: error instanceof Error ? error.message : String(error) });
  });

  // Initialize services with dependencies
  rateLimitService = new RateLimitService(redis);

  encryptionService = new EncryptionService(
    pool,
    redis
  );

  auditService = new AuditService(pool, redis);

  tenantService = new TenantService(pool, redis);

  dataIsolationService = new DataIsolationService(pool, redis);

  logger.info('[Isolation] All services initialized');
}

/**
 * Create Hono application
 */
export function createApp(): Hono {
  const app = new Hono();

  // Global middleware
  app.use('*', honoLogger());
  app.use('*', cors({
    origin: config.cors.origins,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-User-ID', 'X-Organization-ID', 'X-Workspace-ID'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
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

  // Rate limiting middleware
  app.use('*', async (c, next) => {
    const workspaceId = c.req.header('X-Workspace-ID');
    
    if (workspaceId && rateLimitService) {
      // Get workspace for quota config
      const wsResult = await tenantService.getWorkspace(workspaceId);
      
      if (wsResult.ok) {
        const configs = rateLimitService.getWorkspaceRateLimitConfigs(wsResult.value.quota);
        const key = `${workspaceId}:api`;
        const apiConfig = configs.api;
        
        if (apiConfig) {
          const limitResult = await rateLimitService.checkRateLimit(key, apiConfig);
          
          if (limitResult.ok) {
            c.header('X-RateLimit-Limit', String(apiConfig.maxRequests));
            c.header('X-RateLimit-Remaining', String(limitResult.value.remaining));
            c.header('X-RateLimit-Reset', String(limitResult.value.resetAt.getTime()));
            
            if (!limitResult.value.allowed) {
              return c.json({
                error: 'Rate limit exceeded',
                retryAfter: Math.ceil((limitResult.value.resetAt.getTime() - Date.now()) / 1000),
              }, 429);
            }
          }
        }
      }
    }
    
    return next();
  });

  // Audit logging middleware
  app.use('*', async (c, next) => {
    const start = Date.now();
    
    await next();
    
    const duration = Date.now() - start;
    const userId = c.req.header('X-User-ID');
    const organizationId = c.req.header('X-Organization-ID');
    const workspaceId = c.req.header('X-Workspace-ID');
    
    if (userId && (organizationId || workspaceId) && auditService) {
      // Log API access for non-GET requests
      if (c.req.method !== 'GET') {
        await auditService.log({
          organizationId: organizationId || '',
          workspaceId: workspaceId ?? null,
          type: AuditEventType.DATA_READ,
          severity: AuditSeverity.INFO,
          actorId: userId,
          actorType: 'user',
          actorIp: c.req.header('X-Forwarded-For') || null,
          actorUserAgent: c.req.header('User-Agent') || null,
          resource: 'api',
          resourceId: null,
          action: c.req.method.toLowerCase(),
          details: {
            path: c.req.path,
            method: c.req.method,
            statusCode: c.res.status,
            duration,
          },
          metadata: {},
        });
      }
    }
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
    
    const overallStatus = Object.values(checks).every(c => c.status === 'healthy')
      ? 'healthy'
      : 'unhealthy';
    
    return c.json({
      status: overallStatus,
      version: '1.0.0',
      uptime: process.uptime(),
      checks,
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

  // Mount isolation routes
  app.route('/api/v1', createIsolationRoutes(
    tenantService,
    dataIsolationService,
    encryptionService,
    rateLimitService,
    auditService
  ));

  // Error handling
  app.onError((error, c) => {
    logger.error('[Isolation] Unhandled error:', { error: error instanceof Error ? error.message : String(error) });
    
    // Log critical errors
    if (auditService) {
      const organizationId = c.req.header('X-Organization-ID');
      if (organizationId) {
        auditService.log({
          organizationId,
          workspaceId: null,
          type: AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY,
          severity: AuditSeverity.CRITICAL,
          actorId: c.req.header('X-User-ID') || 'unknown',
          actorType: 'system',
          actorIp: c.req.header('X-Forwarded-For') || null,
          actorUserAgent: null,
          resource: 'api',
          resourceId: null,
          action: 'error',
          details: {
            path: c.req.path,
            method: c.req.method,
            error: error.message,
          },
          metadata: {},
        }).catch((err: unknown) => logger.error('[Isolation] Audit log failed', { error: err instanceof Error ? err.message : String(err) }));
      }
    }
    
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
  logger.info('[Isolation] Shutting down services...');
  
  // Flush audit buffer
  if (auditService) {
    await (auditService as unknown as { flushBuffer(): Promise<void> }).flushBuffer();
    logger.info('[Isolation] Audit buffer flushed');
  }
  
  // Close Redis connection
  if (redis) {
    await redis.quit();
    logger.info('[Isolation] Redis connection closed');
  }
  
  // Close database pool
  if (pool) {
    await pool.end();
    logger.info('[Isolation] Database connection closed');
  }
  
  logger.info('[Isolation] Shutdown complete');
}

/**
 * Get service instances (for testing)
 */
export function getServices() {
  return {
    tenantService,
    dataIsolationService,
    encryptionService,
    rateLimitService,
    auditService,
    pool,
    redis,
  };
}

export { initializeServices };
