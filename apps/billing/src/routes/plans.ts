/**
 * Plans Routes - API endpoints for plan management
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { BillingEnv, BillingContext } from '../app.js';

export function plansRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Get all plans
  router.get('/', async (c) => {
    const result = await ctx.plans.getAllPlans();

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ plans: result.value });
  });

  // Get plan by ID
  router.get('/:planId', async (c) => {
    const planId = c.req.param('planId');

    const result = await ctx.plans.getPlan(planId);

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

    const result = await ctx.plans.getTenantPlan(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Check feature access
  router.get('/features/:feature', async (c) => {
    const tenantId = c.get('tenantId');
    const feature = c.req.param('feature');

    const result = await ctx.plans.checkFeatureAccess(tenantId, feature);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ feature, hasAccess: result.value });
  });

  // Get all features for tenant
  router.get('/tenant/features', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.plans.getTenantFeatures(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get plan limits
  router.get('/tenant/limits', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.plans.getTenantLimits(tenantId);

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
      ctx.plans.getPlan(planId1),
      ctx.plans.getPlan(planId2),
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
        limits: plan1Result.value.limits,
      },
      plan2: {
        id: plan2Result.value.id,
        name: plan2Result.value.name,
        priceMonthly: plan2Result.value.priceMonthly,
        features: plan2Result.value.features,
        limits: plan2Result.value.limits,
      },
      differences: {
        priceDifference: plan2Result.value.priceMonthly - plan1Result.value.priceMonthly,
        featureDifferences: calculateFeatureDifferences(
          plan1Result.value.features,
          plan2Result.value.features
        ),
      },
    };

    return c.json(comparison);
  });

  // Admin: Create plan
  router.post('/', async (c) => {
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
    const result = await ctx.plans.createPlan(parsed);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Admin: Update plan
  router.patch('/:planId', async (c) => {
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
    const result = await ctx.plans.updatePlan(planId, parsed);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Admin: Seed default plans
  router.post('/seed', async (c) => {
    const result = await ctx.plans.seedDefaultPlans();

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ message: 'Default plans seeded', count: result.value });
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
