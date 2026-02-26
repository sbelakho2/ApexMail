/**
 * Billing Application - Hono HTTP server
 */

import { Hono } from 'hono';
import { ZodError } from 'zod';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { ApiKeysRepository, createDatabase, DatabasePool } from '@apexmail/db';
import { Redis } from 'ioredis';
import { config, loadConfig } from './config.js';
import {
  MeteringService,
  UsageAlertsService,
  PlansService,
  ProrationEngine,
  InvoiceService,
  StripeService,
  DunningService,
  SlaCreditsService,
  EnterpriseContractService,
  WalletService,
  ViralLoopService,
  CostCircuitService,
  DedicatedIpBillingService,
} from './services/index.js';
import {
  billingRoutes,
  plansRoutes,
  enterpriseRoutes,
  webhooksRoutes,
  adminRoutes,
} from './routes/index.js';

export interface BillingEnv {
  Variables: {
    tenantId: string;
    userId: string;
    isAdmin: boolean;
    adminId: string;
    requestId: string;
  };
}

export interface BillingContext {
  db: DatabasePool;
  redis: Redis;
  metering: MeteringService;
  usageAlerts: UsageAlertsService;
  plans: PlansService;
  proration: ProrationEngine;
  invoices: InvoiceService;
  stripe: StripeService;
  dunning: DunningService;
  slaCredits: SlaCreditsService;
  contracts: EnterpriseContractService;
  wallet: WalletService;
  viralLoop: ViralLoopService;
  costCircuit: CostCircuitService;
  dedicatedIpBilling: DedicatedIpBillingService;
}

export function createApp(): { app: Hono<BillingEnv>; ctx: BillingContext } {
  // Load config first
  loadConfig();

  // Initialize connections
  const db = createDatabase();
  const redis = new Redis(config.redisUrl);

  // C-078: Handle Redis connection errors to prevent uncaught exceptions
  redis.on('error', (err: Error) => {
    console.error('Redis connection error', err.message);
  });

  // Initialize services
  const metering = new MeteringService(db, redis);
  const usageAlerts = new UsageAlertsService(db, redis, metering);
  const plans = new PlansService(db);
  const proration = new ProrationEngine(db, plans);
  const invoices = new InvoiceService(db);
  const dunning = new DunningService(db, redis);
  const stripeIntegration = new StripeService(db, dunning);
  const slaCredits = new SlaCreditsService(db);
  const contracts = new EnterpriseContractService(db);
  const wallet = new WalletService(db, redis);
  const viralLoop = new ViralLoopService(db, redis);
  const costCircuit = new CostCircuitService(db, redis);
  const dedicatedIpBilling = new DedicatedIpBillingService(db);

  const ctx: BillingContext = {
    db,
    redis,
    metering,
    usageAlerts,
    plans,
    proration,
    invoices,
    stripe: stripeIntegration,
    dunning,
    slaCredits,
    contracts,
    wallet,
    viralLoop,
    costCircuit,
    dedicatedIpBilling,
  };

  // Start dedicated IP billing sync (picks up pending charges/cancels every 30s)
  dedicatedIpBilling.startSync();

  // Create Hono app
  const app = new Hono<BillingEnv>();

  // Global middleware
  app.use('*', logger());
  app.use('*', timing());
  app.use('*', secureHeaders());
  app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-ID') ?? randomUUID();
    c.set('requestId', requestId);
    c.header('X-Request-ID', requestId);
    return next();
  });
  app.use('*', cors({
    origin: config.corsOrigins,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
    exposeHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400,
    credentials: true,
  }));

  // Health check
  app.get('/health', (c) => {
    return c.json({ status: 'healthy', service: 'billing', version: '1.0.0' });
  });

  // Readiness check
  app.get('/ready', async (c) => {
    try {
      await db.query('SELECT 1');
      await redis.ping();
      return c.json({ status: 'ready' });
    } catch (error) {
      console.error('Readiness check failed:', error);
      return c.json({ status: 'not_ready' }, 503);
    }
  });

  // Webhooks - no auth required, signature verified
  app.use('/webhooks/*', async (c, next) => {
    const MAX_WEBHOOK_BODY_BYTES = 1024 * 1024; // 1MB
    const contentLengthRaw = c.req.header('content-length');
    const contentLength = contentLengthRaw ? parseInt(contentLengthRaw, 10) : NaN;

    if (!Number.isNaN(contentLength) && contentLength > MAX_WEBHOOK_BODY_BYTES) {
      return c.json({ error: 'Payload too large' }, 413);
    }

    return next();
  });

  app.route('/webhooks', webhooksRoutes(ctx));

  // Auth middleware for all other routes
  app.use('/api/*', async (c, next) => {
    const authHeader = c.req.header('Authorization');
    const tenantHeader = c.req.header('X-Tenant-ID');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Authorization required' }, 401);
    }

    const token = authHeader.slice(7);

    // Verify token (in production, verify JWT or API key)
    const clientIp = getClientIp(c.req.header('x-forwarded-for'), c.req.header('x-real-ip'));
    const tokenResult = await verifyToken(ctx, token, clientIp);

    if (!tokenResult.valid) {
      return c.json({ error: 'Invalid or expired token' }, 401);
    }

    c.set('userId', tokenResult.userId);
    c.set('isAdmin', tokenResult.isAdmin);
    c.set('adminId', tokenResult.adminId ?? '');

    // Tenant ID from header or token
    const tenantId = tenantHeader ?? tokenResult.tenantId;

    if (!tenantId) {
      return c.json({ error: 'Tenant ID required' }, 400);
    }

    // Verify tenant access
    if (!tokenResult.isAdmin && tokenResult.tenantId !== tenantId) {
      return c.json({ error: 'Access denied to this tenant' }, 403);
    }

    c.set('tenantId', tenantId);

    return next();
  });

  // Baseline rate limiting for authenticated billing APIs
  app.use('/api/*', async (c, next) => {
    const tenantId = c.get('tenantId');
    const clientIp = getClientIp(c.req.header('x-forwarded-for'), c.req.header('x-real-ip'));
    const windowSeconds = 60;
    const maxRequestsPerWindow = 300;
    const windowBucket = Math.floor(Date.now() / (windowSeconds * 1000));
    const key = `billing:rate:${tenantId}:${clientIp}:${windowBucket}`;

    try {
      const currentCount = await ctx.redis.incr(key);
      if (currentCount === 1) {
        await ctx.redis.expire(key, windowSeconds);
      }

      c.header('X-RateLimit-Limit', String(maxRequestsPerWindow));
      c.header('X-RateLimit-Remaining', String(Math.max(0, maxRequestsPerWindow - currentCount)));
      c.header('X-RateLimit-Reset', String((windowBucket + 1) * windowSeconds));

      if (currentCount > maxRequestsPerWindow) {
        return c.json({ error: 'Too many requests' }, 429);
      }
    } catch (error) {
      console.error('Rate limit check failed:', error);
    }

    return next();
  });

  // API routes
  app.route('/api/billing', billingRoutes(ctx));
  app.route('/api/plans', plansRoutes(ctx));
  app.route('/api/enterprise', enterpriseRoutes(ctx));
  app.route('/api/admin', adminRoutes(ctx));

  // Error handler
  app.onError((err, c) => {
    const requestId = c.get('requestId');
    console.error('Billing API Error:', { requestId, error: err });

    if (err instanceof ZodError) {
      return c.json({ requestId, error: 'Validation error', fields: err.issues.map((i) => ({ path: i.path, message: i.message })) }, 400);
    }

    return c.json({ requestId, error: 'Internal server error' }, 500);
  });

  // 404 handler
  app.notFound((c) => {
    return c.json({ error: 'Not found' }, 404);
  });

  return { app, ctx };
}

interface TokenResult {
  valid: boolean;
  userId: string;
  tenantId?: string;
  isAdmin: boolean;
  adminId?: string;
}

async function verifyToken(ctx: BillingContext, token: string, clientIp?: string): Promise<TokenResult> {
  // Check if it's an API key
  if (token.startsWith('am_')) {
    const apiKeysRepo = new ApiKeysRepository(ctx.db);
    const verifyResult = await apiKeysRepo.verify(token, clientIp);
    if (!verifyResult.ok || !verifyResult.value.valid || !verifyResult.value.apiKey) {
      return { valid: false, userId: '', isAdmin: false };
    }

    const apiKey = verifyResult.value.apiKey;
    const tenantResult = await ctx.db.query<{ admin_access: boolean }>(
      'SELECT admin_access FROM tenants WHERE id = $1',
      [apiKey.tenantId]
    );
    const adminAccess = tenantResult.ok && tenantResult.value.rows[0]?.admin_access === true;
    return {
      valid: true,
      userId: apiKey.userId ?? apiKey.id,
      tenantId: apiKey.tenantId,
      isAdmin: adminAccess,
      adminId: adminAccess ? (apiKey.userId ?? apiKey.id) : undefined,
    };
  }

  // Otherwise, treat as JWT - SECURITY: Now properly verifies signature
  try {
    const decoded = verifyJwt(token);

    if (!decoded) {
      return { valid: false, userId: '', isAdmin: false };
    }

    return {
      valid: true,
      userId: decoded.sub,
      tenantId: decoded.tenant_id,
      isAdmin: decoded.admin === true,
      adminId: decoded.admin ? decoded.sub : undefined,
    };
  } catch {
    return { valid: false, userId: '', isAdmin: false };
  }
}

function getClientIp(xForwardedFor?: string | null, xRealIp?: string | null): string | undefined {
  if (xForwardedFor) {
    return xForwardedFor.split(',')[0]?.trim();
  }
  if (xRealIp) {
    return xRealIp.trim();
  }
  return undefined;
}

interface JwtPayload {
  sub: string;
  tenant_id?: string;
  admin?: boolean;
  exp: number;
}

/**
 * SECURITY: Properly verify JWT signature to prevent token forgery
 * The signature is verified using HMAC-SHA256 with timing-safe comparison
 */
function verifyJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    if (!headerB64 || !payloadB64 || !signatureB64) return null;

    // Decode and validate header - prevent algorithm confusion attack
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8'));
    if (header.alg !== 'HS256') {
      console.error('[JWT] Invalid algorithm:', header.alg);
      return null;
    }

    // Get JWT secret from config - MUST be set in production
    const jwtSecret = config.jwtSecret;
    if (!jwtSecret) {
      console.error('[JWT] JWT_SECRET not configured');
      return null;
    }

    // Compute expected signature
    const expectedSignature = createHmac('sha256', jwtSecret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    // Timing-safe comparison to prevent timing attacks
    const sigBuffer = Buffer.from(signatureB64);
    const expectedBuffer = Buffer.from(expectedSignature);
    
    if (sigBuffer.length !== expectedBuffer.length || 
        !timingSafeEqual(sigBuffer, expectedBuffer)) {
      console.error('[JWT] Signature verification failed');
      return null;
    }

    // Decode and validate payload
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    
    // Validate expiration
    if (!payload.exp || payload.exp < Date.now() / 1000) {
      return null;
    }

    return payload as JwtPayload;
  } catch (error) {
    console.error('[JWT] Verification error:', error instanceof Error ? error.message : 'Unknown');
    return null;
  }
}
