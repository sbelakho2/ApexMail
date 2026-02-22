/**
 * Dedicated IPs Routes — Customer self-service dedicated IP management
 *
 * F-213: Response envelope standard.
 * Single: { dedicatedIp: T }   List: { dedicatedIps: T[], pagination: {...} }
 *
 * Plan gating:
 * - Pro ($65/mo): eligible, 0 included, add-on $30/mo each
 * - Growth ($150/mo): eligible, 1 included
 * - Scale ($350/mo): eligible, 3 included
 * - Enterprise ($800/mo): eligible, 10 included
 * - Free / Starter / PAYG: NOT eligible
 *
 * RBAC: Requires `dedicated-ips:read` for GET, `dedicated-ips:write` for POST/DELETE
 */

import { Hono } from 'hono';
import type { AppEnv, AppContext } from '../app.js';
import { ApiError } from '../middleware/error-handler.js';
import { requireScopes } from '../middleware/auth.js';
import { DedicatedIpService } from '../services/dedicated-ip-service.js';

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const VALID_STATUSES = ['pending', 'warming', 'active', 'suspended', 'retired'] as const;

export function dedicatedIpsRoutes(ctx: AppContext): Hono<AppEnv> {
  const router = new Hono<AppEnv>();
  const ipService = new DedicatedIpService(ctx.db, ctx.logger);

  /**
   * Helper: Get plan features for the authenticated tenant.
   * Queries the tenant's plan directly from the DB and parses the features JSON.
   * Throws 403 if the plan does not support dedicated IPs.
   */
  async function getPlanFeaturesOrThrow(tenantId: string, requireEnabled = true) {
    const planResult = await ctx.db.query<{
      [key: string]: unknown;
      features: string;
    }>(
      `SELECT p.features
       FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId],
    );

    if (!planResult.ok) {
      throw ApiError.internal('Failed to check plan eligibility');
    }

    const row = planResult.value.rows[0];
    if (!row) {
      throw ApiError.forbidden(
        'No active plan found. Please subscribe to a plan to manage dedicated IPs.',
        'NO_PLAN',
      );
    }

    let features: { dedicatedIp: boolean; dedicatedIpCount: number };
    try {
      features = JSON.parse(row.features) as { dedicatedIp: boolean; dedicatedIpCount: number };
    } catch {
      throw ApiError.internal('Failed to parse plan features');
    }

    if (requireEnabled && !features.dedicatedIp) {
      throw ApiError.forbidden(
        'Dedicated IPs are available on Pro plans and above. Please upgrade your plan.',
        'PLAN_NOT_ELIGIBLE',
      );
    }

    return features;
  }

  // ────────────────────────────────────────────
  // GET / — List dedicated IPs
  // ────────────────────────────────────────────
  router.get('/', requireScopes('dedicated-ips:read'), async (c) => {
    const tenantId = c.get('tenantId');

    // Plan check (read-only, don't block if plan doesn't support — just return empty)
    const features = await getPlanFeaturesOrThrow(tenantId, false);

    const statusParam = c.req.query('status');
    let status: typeof VALID_STATUSES[number] | undefined;
    if (statusParam) {
      if (!VALID_STATUSES.includes(statusParam as typeof VALID_STATUSES[number])) {
        throw ApiError.badRequest(
          `Invalid status. Must be one of: ${VALID_STATUSES.join(', ')}`,
        );
      }
      status = statusParam as typeof VALID_STATUSES[number];
    }

    const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') ?? '50', 10) || 50, 100));
    const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0', 10) || 0);

    const result = await ipService.listByTenant(tenantId, { limit, offset, status });

    if (!result.ok) {
      throw ApiError.internal('Failed to list dedicated IPs');
    }

    // Also include allocation info
    const allocation = await ipService.getAllocation(tenantId, features);

    return c.json({
      dedicatedIps: result.value.ips.map(formatIpResponse),
      allocation: allocation.ok ? allocation.value : null,
      pagination: {
        total: result.value.total,
        limit,
        offset,
        hasMore: offset + limit < result.value.total,
      },
    });
  });

  // ────────────────────────────────────────────
  // GET /allocation — Get IP allocation summary
  // ────────────────────────────────────────────
  router.get('/allocation', requireScopes('dedicated-ips:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const features = await getPlanFeaturesOrThrow(tenantId, false);
    const allocation = await ipService.getAllocation(tenantId, features);

    if (!allocation.ok) {
      throw ApiError.internal('Failed to get IP allocation');
    }

    return c.json({ allocation: allocation.value });
  });

  // ────────────────────────────────────────────
  // GET /:id — Get dedicated IP by ID
  // ────────────────────────────────────────────
  router.get('/:id', requireScopes('dedicated-ips:read'), async (c) => {
    const tenantId = c.get('tenantId');
    const ipId = c.req.param('id');

    if (!uuidRegex.test(ipId)) {
      throw ApiError.badRequest('Invalid dedicated IP ID format', 'INVALID_ID');
    }

    const result = await ipService.findById(ipId, tenantId);

    if (!result.ok) {
      throw ApiError.internal('Failed to fetch dedicated IP');
    }

    if (!result.value) {
      throw ApiError.notFound('Dedicated IP');
    }

    return c.json({ dedicatedIp: formatIpResponse(result.value) });
  });

  // ────────────────────────────────────────────
  // POST / — Provision a new dedicated IP
  // ────────────────────────────────────────────
  router.post('/', requireScopes('dedicated-ips:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const logger = c.get('logger');

    // Plan eligibility — MUST be on Pro+ plan with dedicatedIp enabled
    const features = await getPlanFeaturesOrThrow(tenantId, true);

    logger.info('Provisioning dedicated IP', { tenantId });

    const result = await ipService.provision(
      { tenantId, userId },
      features,
    );

    if (!result.ok) {
      const errorMessage = result.error.message;

      switch (errorMessage) {
        case 'PLAN_NOT_ELIGIBLE':
          throw ApiError.forbidden(
            'Dedicated IPs are available on Pro plans and above.',
            'PLAN_NOT_ELIGIBLE',
          );
        case 'MAX_IPS_REACHED':
          throw ApiError.badRequest(
            'Maximum dedicated IP limit reached (50 per account).',
            'MAX_IPS_REACHED',
          );
        case 'PROVISIONING_FAILED':
          throw ApiError.serviceUnavailable(
            'Unable to provision a dedicated IP at this time. Please try again later or contact support.',
            'PROVISIONING_FAILED',
          );
        case 'PROVISIONING_UNAVAILABLE':
          throw ApiError.serviceUnavailable(
            'Dedicated IP provisioning is temporarily unavailable. Please contact support.',
            'PROVISIONING_UNAVAILABLE',
          );
        default:
          logger.error('Failed to provision dedicated IP', { error: errorMessage });
          throw ApiError.internal('Failed to provision dedicated IP');
      }
    }

    logger.info('Dedicated IP provisioned successfully', {
      tenantId,
      ipId: result.value.id,
      ipAddress: result.value.ipAddress,
    });

    return c.json({
      dedicatedIp: formatIpResponse(result.value),
      message: 'Dedicated IP provisioned. Warmup will begin automatically and takes approximately 14 days.',
    }, 201);
  });

  // ────────────────────────────────────────────
  // DELETE /:id — Release a dedicated IP
  // ────────────────────────────────────────────
  router.delete('/:id', requireScopes('dedicated-ips:write'), async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const ipId = c.req.param('id');
    const logger = c.get('logger');

    if (!uuidRegex.test(ipId)) {
      throw ApiError.badRequest('Invalid dedicated IP ID format', 'INVALID_ID');
    }

    logger.info('Releasing dedicated IP', { tenantId, ipId });

    const result = await ipService.release(ipId, tenantId, userId);

    if (!result.ok) {
      const errorMessage = result.error.message;

      switch (errorMessage) {
        case 'IP_NOT_FOUND':
          throw ApiError.notFound('Dedicated IP');
        case 'IP_ALREADY_RETIRED':
          throw ApiError.conflict(
            'This dedicated IP has already been released.',
            'IP_ALREADY_RETIRED',
          );
        default:
          logger.error('Failed to release dedicated IP', { error: errorMessage });
          throw ApiError.internal('Failed to release dedicated IP');
      }
    }

    logger.info('Dedicated IP released successfully', { tenantId, ipId });

    return c.json({
      message: 'Dedicated IP released successfully. Billing will be prorated.',
    });
  });

  return router;
}

// ────────────────────────────────────────────
// Response Formatting
// ────────────────────────────────────────────

function formatIpResponse(ip: {
  id: string;
  ipAddress: string;
  ptrRecord: string | null;
  status: string;
  warmingStartedAt: Date | null;
  warmingCompletedAt: Date | null;
  warmingProgressPercent: number;
  currentDailyLimit: number | null;
  reputationScore: number;
  emailsSentTotal: number;
  bouncesTotal: number;
  complaintsTotal: number;
  blocklisted: boolean;
  billingStatus: string;
  stripeSubscriptionItemId: string | null;
  billingStartedAt: Date | null;
  billingEndedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: ip.id,
    ipAddress: ip.ipAddress,
    ptrRecord: ip.ptrRecord,
    status: ip.status,
    warmup: {
      startedAt: ip.warmingStartedAt,
      completedAt: ip.warmingCompletedAt,
      progressPercent: ip.warmingProgressPercent,
      currentDailyLimit: ip.currentDailyLimit,
    },
    reputation: {
      score: ip.reputationScore,
      blocklisted: ip.blocklisted,
    },
    stats: {
      emailsSentTotal: ip.emailsSentTotal,
      bouncesTotal: ip.bouncesTotal,
      complaintsTotal: ip.complaintsTotal,
    },
    billing: {
      status: ip.billingStatus,
      startedAt: ip.billingStartedAt,
      endedAt: ip.billingEndedAt,
    },
    createdAt: ip.createdAt,
    updatedAt: ip.updatedAt,
  };
}
