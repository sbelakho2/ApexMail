/**
 * Billing Application - Hono HTTP server
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { config } from './config.js';
import { getStripeClient } from './lib/stripe-client.js';
import {
  MeteringService,
  UsageAlertsService,
  PlansService,
  ProrationService,
  InvoiceService,
  StripeIntegrationService,
  DunningService,
  SlaCreditsService,
  EnterpriseContractsService,
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
  db: Pool;
  redis: Redis;
  metering: MeteringService;
  usageAlerts: UsageAlertsService;
  plans: PlansService;
  proration: ProrationService;
  invoices: InvoiceService;
  stripe: StripeIntegrationService;
  dunning: DunningService;
  slaCredits: SlaCreditsService;
  contracts: EnterpriseContractsService;
  wallet: WalletService;
  viralLoop: ViralLoopService;
  costCircuit: CostCircuitService;
}

export function createApp(): { app: Hono<BillingEnv>; ctx: BillingContext } {
  // Initialize connections
  const db = new Pool({ connectionString: config.databaseUrl });
  const redis = new Redis(config.redisUrl);
  const stripe = getStripeClient();

  // Initialize services
  const metering = new MeteringService(db, redis);
  const usageAlerts = new UsageAlertsService(db, redis);
  const plans = new PlansService(db);
  const proration = new ProrationService(db);
  const invoices = new InvoiceService(db);
  const stripeIntegration = new StripeIntegrationService(db, stripe);
  const dunning = new DunningService(db, redis);
  const slaCredits = new SlaCreditsService(db);
  const contracts = new EnterpriseContractsService(db);
  const wallet = new WalletService(db);
  const viralLoop = new ViralLoopService(db);
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

    await next();
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
  if (token.startsWith('apx_')) {
    const result = await ctx.db.query(
      `SELECT ak.id, ak.tenant_id, ak.user_id, ak.scopes, t.admin_access
       FROM api_keys ak
       JOIN tenants t ON ak.tenant_id = t.id
       WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL AND ak.expires_at > NOW()`,
      [hashApiKey(token)]
    );

    if (result.rows.length === 0) {
      return { valid: false, userId: '', isAdmin: false };
    }

    const row = result.rows[0];
    return {
      valid: true,
      userId: row.user_id,
      tenantId: row.tenant_id,
      isAdmin: row.admin_access === true,
      adminId: row.admin_access ? row.user_id : undefined,
    };
  }

  // Otherwise, treat as JWT
  try {
    const decoded = decodeJwt(token);

    if (!decoded || decoded.exp < Date.now() / 1000) {
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
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(key).digest('hex');
}

interface JwtPayload {
  sub: string;
  tenant_id?: string;
  admin?: boolean;
  exp: number;
}

function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}
