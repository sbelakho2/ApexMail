/**
 * Enterprise Routes - API endpoints for enterprise contracts
 */

import { Hono } from 'hono';
import { z } from 'zod';
import type { BillingEnv, BillingContext } from '../app.js';

export function enterpriseRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  // Get all contracts for tenant
  router.get('/contracts', async (c) => {
    const tenantId = c.get('tenantId');

    const result = await ctx.contracts.listContracts(tenantId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json({ contracts: result.value });
  });

  // Get contract by ID
  router.get('/contracts/:contractId', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');

    const result = await ctx.contracts.getContract(tenantId, contractId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
      return c.json({ error: 'Contract not found' }, 404);
    }

    return c.json(result.value);
  });

  // Get contract PDF
  router.get('/contracts/:contractId/pdf', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');

    const result = await ctx.contracts.getContract(tenantId, contractId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    if (!result.value) {
      return c.json({ error: 'Contract not found' }, 404);
    }

    const pdfContent = ctx.contracts.generateContractPdf(result.value);

    return c.html(pdfContent);
  });

  // Get contract usage
  router.get('/contracts/:contractId/usage', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');

    const result = await ctx.contracts.getContractUsage(tenantId, contractId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Admin: Create contract
  router.post('/contracts', async (c) => {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      startDate: z.string().datetime(),
      endDate: z.string().datetime(),
      baseFee: z.number().min(0),
      committedVolume: z.object({
        emails: z.number().min(0),
        apiCalls: z.number().min(0),
        storage: z.number().min(0),
      }),
      overageRates: z.object({
        emailsPerThousand: z.number().min(0),
        apiCallsPerThousand: z.number().min(0),
        storagePerGb: z.number().min(0),
      }),
      paymentTerms: z.enum(['net30', 'net60']),
      customFeatures: z.array(z.string()).optional(),
      allowPurchaseOrders: z.boolean().optional(),
      dedicatedSupport: z.boolean().optional(),
      customSla: z.object({
        uptimeTarget: z.number().min(99).max(100),
        responseTimeMinutes: z.number().min(1),
        creditTiers: z.array(z.object({
          threshold: z.number(),
          creditPercent: z.number(),
        })),
      }).optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.createContract({
      tenantId,
      ...parsed,
      startDate: new Date(parsed.startDate),
      endDate: new Date(parsed.endDate),
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Submit contract for signature
  router.post('/contracts/:contractId/submit', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');

    const result = await ctx.contracts.submitForSignature(tenantId, contractId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Sign contract
  router.post('/contracts/:contractId/sign', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');
    const body = await c.req.json();

    const schema = z.object({
      signatureData: z.string(),
      signerName: z.string(),
      signerTitle: z.string(),
      signedAt: z.string().datetime(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.signContract(tenantId, contractId, {
      ...parsed,
      signedAt: new Date(parsed.signedAt),
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Request contract amendment
  router.post('/contracts/:contractId/amendments', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');
    const body = await c.req.json();

    const schema = z.object({
      reason: z.string(),
      proposedChanges: z.object({
        baseFee: z.number().min(0).optional(),
        committedVolume: z.object({
          emails: z.number().min(0).optional(),
          apiCalls: z.number().min(0).optional(),
          storage: z.number().min(0).optional(),
        }).optional(),
        overageRates: z.object({
          emailsPerThousand: z.number().min(0).optional(),
          apiCallsPerThousand: z.number().min(0).optional(),
          storagePerGb: z.number().min(0).optional(),
        }).optional(),
        endDate: z.string().datetime().optional(),
      }),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.requestAmendment(tenantId, contractId, parsed);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Cancel contract
  router.post('/contracts/:contractId/cancel', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');
    const body = await c.req.json();

    const schema = z.object({
      reason: z.string(),
      effectiveDate: z.string().datetime().optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.cancelContract(tenantId, contractId, {
      reason: parsed.reason,
      effectiveDate: parsed.effectiveDate ? new Date(parsed.effectiveDate) : undefined,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Get contract renewal quote
  router.get('/contracts/:contractId/renewal-quote', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');

    const result = await ctx.contracts.getRenewalQuote(tenantId, contractId);

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value);
  });

  // Renew contract
  router.post('/contracts/:contractId/renew', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');
    const body = await c.req.json();

    const schema = z.object({
      newEndDate: z.string().datetime(),
      newTerms: z.object({
        baseFee: z.number().min(0).optional(),
        committedVolume: z.object({
          emails: z.number().min(0).optional(),
          apiCalls: z.number().min(0).optional(),
          storage: z.number().min(0).optional(),
        }).optional(),
        overageRates: z.object({
          emailsPerThousand: z.number().min(0).optional(),
          apiCallsPerThousand: z.number().min(0).optional(),
          storagePerGb: z.number().min(0).optional(),
        }).optional(),
      }).optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.renewContract(tenantId, contractId, {
      newEndDate: new Date(parsed.newEndDate),
      newTerms: parsed.newTerms,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  // Submit purchase order
  router.post('/contracts/:contractId/purchase-orders', async (c) => {
    const tenantId = c.get('tenantId');
    const contractId = c.req.param('contractId');
    const body = await c.req.json();

    const schema = z.object({
      poNumber: z.string(),
      amount: z.number().min(0),
      issuedDate: z.string().datetime(),
      expiryDate: z.string().datetime().optional(),
      attachmentUrl: z.string().url().optional(),
    });

    const parsed = schema.parse(body);
    const result = await ctx.contracts.submitPurchaseOrder(tenantId, contractId, {
      ...parsed,
      issuedDate: new Date(parsed.issuedDate),
      expiryDate: parsed.expiryDate ? new Date(parsed.expiryDate) : undefined,
    });

    if (!result.ok) {
      return c.json({ error: result.error.message }, 500);
    }

    return c.json(result.value, 201);
  });

  return router;
}
