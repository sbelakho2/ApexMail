/**
 * Billing Application - Hono HTTP server
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { createDatabase, DatabasePool } from '@apexmail/db';
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
  const stripeIntegration = new StripeService(db);
  const dunning = new DunningService(db, redis);
  const slaCredits = new SlaCreditsService(db);
  const contracts = new EnterpriseContractService(db);
  const wallet = new WalletService(db, redis);
  const viralLoop = new ViralLoopService(db, redis);
  const costCircuit = new CostCircuitService(db, redis);

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
  };

  // Create Hono app
  const app = new Hono<BillingEnv>();

  // Global middleware
  app.use('*', logger());
  app.use('*', timing());
  app.use('*', secureHeaders());
  app.use('*', cors({
    origin: config.corsOrigins,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
    exposeHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining'],
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
      return c.json({ status: 'not_ready', error: String(error) }, 503);
    }
  });

  // Webhooks - no auth required, signature verified
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
    const tokenResult = await verifyToken(ctx, token);

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

  // API routes
  app.route('/api/billing', billingRoutes(ctx));
  app.route('/api/plans', plansRoutes(ctx));
  app.route('/api/enterprise', enterpriseRoutes(ctx));
  app.route('/api/admin', adminRoutes(ctx));

  // Error handler
  app.onError((err, c) => {
    console.error('Billing API Error:', err);

    if (err.name === 'ZodError') {
      return c.json({ error: 'Validation error', details: err }, 400);
    }

    return c.json({ error: 'Internal server error' }, 500);
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

async function verifyToken(ctx: BillingContext, token: string): Promise<TokenResult> {
  // Check if it's an API key
  if (token.startsWith('am_')) {
    const result = await ctx.db.query<{
      id: string;
      tenant_id: string;
      user_id: string;
      scopes: string[];
      admin_access: boolean;
    }>(
      `SELECT ak.id, ak.tenant_id, ak.user_id, ak.scopes, t.admin_access
       FROM api_keys ak
       JOIN tenants t ON ak.tenant_id = t.id
       WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL AND ak.expires_at > NOW()`,
      [hashApiKey(token)]
    );

    if (!result.ok || result.value.rows.length === 0) {
      return { valid: false, userId: '', isAdmin: false };
    }

    const row = result.value.rows[0]!;
    return {
      valid: true,
      userId: row.user_id,
      tenantId: row.tenant_id,
      isAdmin: row.admin_access === true,
      adminId: row.admin_access ? row.user_id : undefined,
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

function hashApiKey(key: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(key).digest('hex');
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
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('[JWT] JWT_SECRET not configured');
      return null;
    }

    // Compute expected signature
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const expectedSignature = crypto
      .createHmac('sha256', jwtSecret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    // Timing-safe comparison to prevent timing attacks
    const sigBuffer = Buffer.from(signatureB64);
    const expectedBuffer = Buffer.from(expectedSignature);
    
    if (sigBuffer.length !== expectedBuffer.length || 
        !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
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
