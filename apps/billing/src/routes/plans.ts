/**
 * Plans Routes - API endpoints for plan management
 */

import { Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { z } from 'zod';
import type { PlanFeatures } from '../services/plans.js';
import type { BillingEnv, BillingContext } from '../app.js';

const PLAN_FEATURE_KEYS = [
  'dedicatedIp',
  'dedicatedIpCount',
  'maxSendingDomains',
  'ssoEnabled',
  'auditLogs',
  'apiAccess',
  'webhooksEnabled',
  'inboundEmail',
  'advancedAnalytics',
  'sendTimeOptimization',
  'abTesting',
  'timeTravelDebugging',
  'dataExport',
  'customTrackingDomain',
  'customTemplates',
  'templateApprovalWorkflow',
  'whiteLabel',
  'poweredByFooter',
  'customRetention',
  'maxRetentionDays',
  'maxTeamMembers',
  'subaccounts',
  'maxSubaccounts',
  'supportLevel',
  'dedicatedCsm',
  'priorityOnboarding',
  'byoip',
  'slaGuarantee',
  'slaCreditPercentage',
  'hipaaCompliance',
  'soc2Compliance',
  'privateCloud',
] as const satisfies readonly (keyof PlanFeatures)[];

const featureParamSchema = z.enum(PLAN_FEATURE_KEYS);

export function plansRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  const requireAdmin: MiddlewareHandler<BillingEnv> = async (c, next) => {
    const isAdmin = c.get('isAdmin');
    if (!isAdmin) {
      return c.json({ error: 'Admin access required' }, 403);
    }
    return next();
  };

  // Get all plans
  router.get('/', async (c) => {
    const result = await ctx.plans.getActivePlans();

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ plans: result.value });
  });

  // Get plan by ID (using name)
  router.get('/:planId', async (c) => {
    const planId = c.req.param('planId');

    const result = await ctx.plans.getPlanByName(planId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
      return c.json({ error: 'Plan not found' }, 404);
    }

    return c.json(result.value);
  });

  // Get tenant's current plan
  router.get('/tenant/current', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.plans.getPlanLimits(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Check feature access
  router.get('/features/:feature', async (c) => {
    const tenantId = c.get('tenantId');
    const feature = featureParamSchema.parse(c.req.param('feature'));

    const result = await ctx.plans.hasFeature(tenantId, feature);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ feature, hasAccess: result.value });
  });

  // Get all features for tenant
  router.get('/tenant/features', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.plans.getPlanLimits(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value?.features ?? {});
  });

  // Get plan limits
  router.get('/tenant/limits', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.plans.getPlanLimits(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Compare plans
  router.get('/compare/:planId1/:planId2', async (c) => {
    const planId1 = c.req.param('planId1');
    const planId2 = c.req.param('planId2');

    const [plan1Result, plan2Result] = await Promise.all([
      ctx.plans.getPlanByName(planId1),
      ctx.plans.getPlanByName(planId2),
    ]);

    if (!plan1Result.ok || !plan2Result.ok) {
      return c.json({ error: 'Failed to fetch plans' }, 500);
    }

    if (!plan1Result.value || !plan2Result.value) {
      return c.json({ error: 'One or both plans not found' }, 404);
    }

    const comparison = {
      plan1: {
        id: plan1Result.value.id,
        name: plan1Result.value.name,
        priceMonthly: plan1Result.value.priceMonthly,
        features: plan1Result.value.features,
        limits: { emailLimit: plan1Result.value.emailLimit, apiCallLimit: plan1Result.value.apiCallLimit },
      },
      plan2: {
        id: plan2Result.value.id,
        name: plan2Result.value.name,
        priceMonthly: plan2Result.value.priceMonthly,
        features: plan2Result.value.features,
        limits: { emailLimit: plan2Result.value.emailLimit, apiCallLimit: plan2Result.value.apiCallLimit },
      },
      differences: {
        priceDifference: plan2Result.value.priceMonthly - plan1Result.value.priceMonthly,
        featureDifferences: calculateFeatureDifferences(
          plan1Result.value.features as unknown as Record<string, boolean>,
          plan2Result.value.features as unknown as Record<string, boolean>
        ),
      },
    };

    return c.json(comparison);
  });

  // Admin: Create plan
  router.post('/', requireAdmin, async (c) => {
    const body = await c.req.json();

    const schema = z.object({
      name: z.string(),
      displayName: z.string(),
      description: z.string(),
      priceMonthly: z.number().min(0),
      priceYearly: z.number().min(0),
      features: z.record(z.boolean()),
      limits: z.object({
        emailsPerMonth: z.number(),
        contactsLimit: z.number(),
        apiCallsPerMinute: z.number(),
        webhooksPerDay: z.number(),
        teamMembersLimit: z.number(),
        storageGb: z.number(),
        dedicatedIps: z.number(),
        customDomainsLimit: z.number(),
      }),
      stripePriceIdMonthly: z.string().optional(),
      stripePriceIdYearly: z.string().optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.plans.createOrUpdatePlan({
      name: parsed.name,
      displayName: parsed.displayName,
      description: parsed.description,
      priceMonthly: parsed.priceMonthly,
      priceYearly: parsed.priceYearly,
      emailLimit: parsed.limits.emailsPerMonth,
      apiCallLimit: parsed.limits.apiCallsPerMinute,
      features: parsed.features as unknown as import('../services/plans.js').PlanFeatures,
      stripePriceIdMonthly: parsed.stripePriceIdMonthly,
      stripePriceIdYearly: parsed.stripePriceIdYearly,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Admin: Update plan
  router.patch('/:planId', requireAdmin, async (c) => {
    const planId = c.req.param('planId');
    const body = await c.req.json();

    const schema = z.object({
      displayName: z.string().optional(),
      description: z.string().optional(),
      priceMonthly: z.number().min(0).optional(),
      priceYearly: z.number().min(0).optional(),
      features: z.record(z.boolean()).optional(),
      limits: z.object({
        emailsPerMonth: z.number().optional(),
        contactsLimit: z.number().optional(),
        apiCallsPerMinute: z.number().optional(),
        webhooksPerDay: z.number().optional(),
        teamMembersLimit: z.number().optional(),
        storageGb: z.number().optional(),
        dedicatedIps: z.number().optional(),
        customDomainsLimit: z.number().optional(),
      }).optional(),
      stripePriceIdMonthly: z.string().optional(),
      stripePriceIdYearly: z.string().optional(),
    });

    const parsed = schema.parse(body);
    
    // Get existing plan first
    const existingResult = await ctx.plans.getPlanByName(planId);
    if (!existingResult.ok) {
      return c.json({ error: existingResult.error.message }, 500);
    }
    if (!existingResult.value) {
      return c.json({ error: 'Plan not found' }, 404);
    }

    const existing = existingResult.value;
    const result = await ctx.plans.createOrUpdatePlan({
      name: planId,
      displayName: parsed.displayName ?? existing.displayName,
      description: parsed.description ?? existing.description,
      priceMonthly: parsed.priceMonthly ?? existing.priceMonthly,
      priceYearly: parsed.priceYearly ?? existing.priceYearly,
      emailLimit: parsed.limits?.emailsPerMonth ?? existing.emailLimit,
      apiCallLimit: parsed.limits?.apiCallsPerMinute ?? existing.apiCallLimit,
      features: (parsed.features ?? existing.features) as import('../services/plans.js').PlanFeatures,
      stripePriceIdMonthly: parsed.stripePriceIdMonthly ?? existing.stripePriceIdMonthly ?? undefined,
      stripePriceIdYearly: parsed.stripePriceIdYearly ?? existing.stripePriceIdYearly ?? undefined,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Admin: Seed default plans
  router.post('/seed', requireAdmin, async (c) => {
    const result = await ctx.plans.initializeDefaultPlans();

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ message: 'Default plans seeded' });
  });

  return router;
}

function calculateFeatureDifferences(
  features1: Record<string, boolean>,
  features2: Record<string, boolean>
): Array<{ feature: string; plan1: boolean; plan2: boolean }> {
  const differences: Array<{ feature: string; plan1: boolean; plan2: boolean }> = [];
  const allFeatures = new Set([...Object.keys(features1), ...Object.keys(features2)]);

  for (const feature of allFeatures) {
    const val1 = features1[feature] ?? false;
    const val2 = features2[feature] ?? false;

    if (val1 !== val2) {
      differences.push({ feature, plan1: val1, plan2: val2 });
    }
  }

  return differences;
}
