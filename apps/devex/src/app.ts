/**
 * DevEx App Entry Point
 * 
 * Developer Experience application for ApexMail
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { compress } from 'hono/compress';
import { Pool } from 'pg';
import { createDevExRoutes } from './routes/devex.js';
import { ApiVersioningService } from './services/api-versioning.js';
import { OpenApiGenerator } from './services/openapi-generator.js'; // FIX-500-415: Static import
import { config } from './config.js';

type Variables = {
  tenantId: string;
  apiVersion: string;
  requestId: string;
};

/**
 * Create DevEx application
 */
export function createApp(db: Pool): Hono<{ Variables: Variables }> {
  const app = new Hono<{ Variables: Variables }>();

  // Initialize versioning middleware
  const versioningService = new ApiVersioningService(db);
  const versioningMiddleware = versioningService.createMiddleware();

  // Global middleware
  app.use('*', logger());
  app.use('*', timing());
  app.use('*', compress());
  app.use('*', prettyJSON());
  app.use('*', secureHeaders());
  app.use('*', cors({
    origin: config.corsOrigins,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-API-Version', 'X-Request-ID', 'Idempotency-Key'],
    exposeHeaders: ['X-Request-ID', 'X-API-Version', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400,
    credentials: true,
  }));

  // Request ID middleware
  app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-ID') ?? crypto.randomUUID();
    c.set('requestId', requestId);
    c.header('X-Request-ID', requestId);
    await next();
  });

  // API versioning middleware
  app.use('/api/*', versioningMiddleware);

  // Auth middleware - extract tenant from API key
  app.use('/api/*', async (c, next) => {
    const authHeader = c.req.header('Authorization');
    const apiKeyHeader = c.req.header('X-API-Key');
    
    let apiKey: string | undefined;
    
    if (authHeader?.startsWith('Bearer ')) {
      apiKey = authHeader.slice(7);
    } else if (apiKeyHeader) {
      apiKey = apiKeyHeader;
    }

    if (!apiKey) {
      return c.json({ error: { code: 'unauthorized', message: 'API key required' } }, 401);
    }

    // Validate API key and get tenant
    // For sandbox keys (am_test_*), validate with sandbox service
    // For production keys (am_live_*), validate with main auth service
    
    // In a real implementation, this would validate the key
    // For now, we'll extract a tenant ID from the key format
    const tenantId = extractTenantFromKey(apiKey);
    if (!tenantId) {
      return c.json({ error: { code: 'unauthorized', message: 'Invalid API key' } }, 401);
    }

    c.set('tenantId', tenantId);
    return next();
  });

  // Mount DevEx routes
  const devexRoutes = createDevExRoutes(db);
  app.route('/api', devexRoutes);

  // Public routes (no auth required)

  // Health check
  app.get('/health', (c) => {
    return c.json({
      status: 'healthy',
      service: 'devex',
      version: config.currentApiVersion,
      timestamp: new Date().toISOString(),
    });
  });

  // Readiness check
  app.get('/ready', async (c) => {
    try {
      // Check database connection
      await db.query('SELECT 1');
      
      return c.json({
        status: 'ready',
        checks: {
          database: 'ok',
        },
      });
    } catch (error) {
      return c.json({
        status: 'not_ready',
        checks: {
          database: 'failed',
        },
        error: (error as Error).message,
      }, 503);
    }
  });

  // Metrics endpoint
  app.get('/metrics', async (_c) => {
    // Prometheus-style metrics
    const metrics = [
      `# HELP devex_requests_total Total number of requests`,
      `# TYPE devex_requests_total counter`,
      `devex_requests_total{service="devex"} 0`,
      ``,
      `# HELP devex_sdk_downloads_total Total SDK downloads`,
      `# TYPE devex_sdk_downloads_total counter`,
      `devex_sdk_downloads_total{language="typescript"} 0`,
      `devex_sdk_downloads_total{language="python"} 0`,
      `devex_sdk_downloads_total{language="ruby"} 0`,
      `devex_sdk_downloads_total{language="go"} 0`,
      `devex_sdk_downloads_total{language="php"} 0`,
      `devex_sdk_downloads_total{language="java"} 0`,
      `devex_sdk_downloads_total{language="csharp"} 0`,
      ``,
      `# HELP devex_sandbox_environments Active sandbox environments`,
      `# TYPE devex_sandbox_environments gauge`,
      `devex_sandbox_environments{} 0`,
      ``,
      `# HELP devex_webhooks_total Total webhook endpoints`,
      `# TYPE devex_webhooks_total gauge`,
      `devex_webhooks_total{} 0`,
    ].join('\n');

    return new Response(metrics, {
      headers: {
        'Content-Type': 'text/plain; version=0.0.4',
      },
    });
  });

  // Public documentation routes
  app.get('/docs', (c) => {
    return c.redirect('https://docs.apexmail.ee');
  });

  app.get('/docs/api', (c) => {
    return c.redirect('https://docs.apexmail.ee/api');
  });

  // FIX-500-415: Reuse single OpenApiGenerator instance instead of dynamic imports
  const openApiGenerator = new OpenApiGenerator(db);

  // OpenAPI spec (public, no auth)
  app.get('/openapi.json', async (c) => {
    const result = await openApiGenerator.exportSpec('json');
    
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return new Response(result.value, {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  });

  app.get('/openapi.yaml', async (c) => {
    const result = await openApiGenerator.exportSpec('yaml');
    
    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return new Response(result.value, {
      headers: {
        'Content-Type': 'application/x-yaml',
        'Access-Control-Allow-Origin': '*',
      },
    });
  });

  // 404 handler
  app.notFound((c) => {
    return c.json({
      error: {
        code: 'not_found',
        message: 'The requested resource was not found',
        path: c.req.path,
      },
    }, 404);
  });

  // Error handler
  app.onError((err, c) => {
    console.error(`[DevEx Error]`, {
      requestId: c.get('requestId'),
      path: c.req.path,
      method: c.req.method,
      error: err.message,
      stack: err.stack,
    });

    // Don't expose internal errors
    const isInternalError = !err.message.includes('validation') && 
                           !err.message.includes('not found') &&
                           !err.message.includes('unauthorized');

    return c.json({
      error: {
        code: isInternalError ? 'internal_error' : 'error',
        message: isInternalError ? 'An internal error occurred' : err.message,
        requestId: c.get('requestId'),
      },
    }, isInternalError ? 500 : 400);
  });

  return app;
}

/**
 * Extract tenant ID from API key
 */
function extractTenantFromKey(apiKey: string): string | null {
  // API key format: am_{env}_{tenantPrefix}_{secret}
  // env: live or test
  // tenantPrefix: first 8 chars of tenant ID
  
  if (!apiKey.startsWith('am_live_') && !apiKey.startsWith('am_test_')) {
    return null;
  }

  // In production, this would validate against the database
  // For now, extract what looks like a tenant ID
  const parts = apiKey.split('_');
  if (parts.length < 3 || !parts[2]) {
    return null;
  }

  // Return a placeholder tenant ID based on key prefix
  // In production, this would be looked up from the database
  return `tenant_${parts[2].slice(0, 8)}`;
}

/**
 * Create database pool
 */
export function createDbPool(): Pool {
  return new Pool({
    host: config.dbHost,
    port: config.dbPort,
    database: config.dbName,
    user: config.dbUser,
    password: config.dbPassword,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });
}

export { config };
