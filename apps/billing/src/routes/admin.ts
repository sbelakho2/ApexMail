/**
 * Admin Routes - Administrative billing endpoints
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { withTransaction } from '@apexmail/db';
import { randomUUID } from 'node:crypto';
import type { BillingEnv, BillingContext } from '../app.js';
import { logger } from '../lib/logger.js';

export function adminRoutes(ctx: BillingContext): Hono<BillingEnv> {
  const router = new Hono<BillingEnv>();

  const parseQueryDate = (value: string | undefined): Date | null => {
    if (!value) return null;
    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) return null;
    return new Date(timestamp);
  };

  // SEC-005 FIX: Helper to check if admin has access to specific tenant
  const canAccessTenant = (adminScope: string[] | undefined, tenantId: string): boolean => {
    // If no scope defined, deny by default (fail-secure)
    if (!adminScope || adminScope.length === 0) {
      return false;
    }
    // Wildcard scope allows access to all tenants
    if (adminScope.includes('tenant:*')) {
      return true;
    }
    // Check for specific tenant scope
    return adminScope.includes(`tenant:${tenantId}`);
  };

  // Admin middleware
  router.use('*', async (c, next) => {
    const isAdmin = c.get('isAdmin');
    if (!isAdmin) {
      return c.json({ error: 'Admin access required' }, 403);
    }
    return next();
  });

  // SEC-005 FIX: Middleware to check tenant-specific access
  const requireTenantAccess = async (c: Parameters<typeof router.get>[1] extends (c: infer C, n: unknown) => unknown ? C : never) => {
    const adminScope = c.get('adminScope') as string[] | undefined;
    const tenantId = c.req.param('tenantId');
    if (tenantId && !canAccessTenant(adminScope, tenantId)) {
      return c.json({ error: 'Tenant access denied' }, 403);
    }
    return null; // Access allowed
  };

  // List all tenants with billing status
  router.get('/tenants', async (c) => {
    const limit = Math.min(Math.max(parseInt(c.req.query('limit') ?? '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(c.req.query('offset') ?? '0', 10) || 0, 0);
    const status = c.req.query('status');

    let query = `
      SELECT 
        t.id,
        t.name,
        t.created_at,
        s.status as subscription_status,
        s.current_period_end,
        p.name as plan_name,
        d.dunning_state,
        w.balance as wallet_balance
      FROM tenants t
      LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
      LEFT JOIN plans p ON s.plan_id = p.id
      LEFT JOIN dunning_states d ON t.id = d.tenant_id
      LEFT JOIN wallets w ON t.id = w.tenant_id
    `;

    const params: (string | number)[] = [];

    if (status) {
      query += ` WHERE s.status = $1`;
      params.push(status);
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await ctx.db.query(query, params);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'listTenants' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ tenants: result.value.rows, limit, offset });
  });

  // Get tenant billing details
  router.get('/tenants/:tenantId', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');

    const [subscription, planLimits, dunning, wallet, invoices] = await Promise.all([
      ctx.stripe.getSubscription(tenantId),
      ctx.plans.getPlanLimits(tenantId),
      ctx.dunning.getFullState(tenantId),
      ctx.wallet.getBalance(tenantId),
      ctx.invoices.listInvoices(tenantId, { limit: 10 }),
    ]);

    return c.json({
      tenantId,
      subscription: subscription.ok ? subscription.value : null,
      plan: planLimits.ok ? planLimits.value : null,
      dunning: dunning.ok ? dunning.value : null,
      wallet: wallet.ok ? wallet.value : null,
      recentInvoices: invoices.ok ? invoices.value : [],
    });
  });

  // Apply credit to tenant
  router.post('/tenants/:tenantId/credits', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      amount: z.number().positive(),
      reason: z.string(),
      expiresAt: z.string().datetime().optional(),
      idempotencyKey: z.string().optional(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    // Use client-provided idempotency key, or generate unique fallback to avoid collisions
    const idempotencyKey = parsed.idempotencyKey ?? 
      `admin_credit_${adminId}_${tenantId}_${Date.now()}_${randomUUID()}`;

    const result = await ctx.wallet.credit(
      tenantId,
      parsed.amount,
      `Admin credit: ${parsed.reason}`,
      idempotencyKey
    );

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'applyCredit' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json(result.value, 201);
  });

  // Override plan for tenant
  router.post('/tenants/:tenantId/plan-override', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      planId: z.string(),
      reason: z.string(),
      expiresAt: z.string().datetime().optional(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    await ctx.db.query(
      `INSERT INTO plan_overrides (
        tenant_id, plan_id, reason, admin_id, expires_at, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (tenant_id) DO UPDATE SET
        plan_id = $2,
        reason = $3,
        admin_id = $4,
        expires_at = $5,
        updated_at = NOW()`,
      [
        tenantId,
        parsed.planId,
        parsed.reason,
        adminId,
        parsed.expiresAt ? new Date(parsed.expiresAt) : null,
      ]
    );

    await ctx.db.query(
      `INSERT INTO billing_audit_log (
        tenant_id, action, actor_id, actor_type, details, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())`,
      [
        tenantId,
        'plan_override',
        adminId,
        'admin',
        JSON.stringify({
          planId: parsed.planId,
          reason: parsed.reason,
          expiresAt: parsed.expiresAt ?? null,
        }),
      ]
    );

    return c.json({ success: true, message: 'Plan override applied' });
  });

  // Force subscription status
  router.post('/tenants/:tenantId/subscription-status', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      status: z.enum(['active', 'past_due', 'canceled', 'suspended']),
      reason: z.string(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');

    const txResult = await withTransaction(ctx.db, async (tx) => {
      const updateResult = await tx.client.query(
        `UPDATE stripe_subscriptions 
         SET status = $2, admin_override_at = NOW(), admin_override_by = $3, admin_override_reason = $4
         WHERE tenant_id = $1`,
        [tenantId, parsed.status, adminId, parsed.reason]
      );

      if (updateResult.rowCount !== 1) {
        throw new Error('Subscription not found for tenant');
      }

      const auditResult = await tx.client.query(
        `INSERT INTO billing_audit_log (
          tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())`,
        [
          tenantId,
          'subscription_status_override',
          adminId,
          'admin',
          JSON.stringify({ newStatus: parsed.status, reason: parsed.reason }),
        ]
      );

      if (auditResult.rowCount !== 1) {
        throw new Error('Failed to write audit log');
      }
    });

    if (!txResult.ok) {
      logger.error('Admin operation failed', { error: String(txResult.error), operation: 'subscriptionStatusOverride' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ success: true, message: 'Subscription status updated' });
  });

  // Reset dunning state
  router.post('/tenants/:tenantId/dunning/reset', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      reason: z.string(),
    });

    const parsed = schema.parse(body);
    const adminId = c.get('adminId');
    
    // Reset dunning by recording a successful payment
    const result = await ctx.dunning.recordSuccessfulPayment(tenantId);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'dunningReset' }); return c.json({ error: "Operation failed" }, 500);
    }

    await ctx.db.query(
      `INSERT INTO billing_audit_log (
        tenant_id, action, actor_id, actor_type, details, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())`,
      [
        tenantId,
        'dunning_reset',
        adminId,
        'admin',
        JSON.stringify({ reason: parsed.reason }),
      ]
    );

    return c.json({ success: true, message: 'Dunning state reset' });
  });

  // Generate invoice for tenant
  router.post('/tenants/:tenantId/invoices', async (c) => {
    // SEC-005 FIX: Check tenant-specific access
    const accessDenied = await requireTenantAccess(c);
    if (accessDenied) return accessDenied;
    
    const tenantId = c.req.param('tenantId');
    const body = await c.req.json();

    const schema = z.object({
      periodStart: z.string().datetime(),
      periodEnd: z.string().datetime(),
      lineItems: z.array(z.object({
        description: z.string(),
        quantity: z.number(),
        unitPrice: z.number(),
      })),
      notes: z.string().optional(),
    });

    const parsed = schema.parse(body);

    /**
     * E-181: Invoice generation error handling.
     *
     * 1. Check for existing invoice for the same tenant + period to prevent
     *    double-charging if the request is retried after a transient failure.
     * 2. Log errors with full context for operational triage.
     * 3. Return a clear error so the caller can retry safely.
     *
     * The underlying createInvoice uses a DB-generated UUID and sequential
     * invoice number (nextval), so a duplicate INSERT would get a new ID —
     * the period overlap check below is the idempotency guard.
     */
    const periodStart = new Date(parsed.periodStart);
    const periodEnd = new Date(parsed.periodEnd);

    // E-181: Guard against double-invoicing for the same period
    const existingCheck = await ctx.db.query(
      `SELECT id, invoice_number, status FROM invoices
       WHERE tenant_id = $1
         AND period_start = $2
         AND period_end = $3
         AND status NOT IN ('void')
       LIMIT 1`,
      [tenantId, periodStart, periodEnd]
    );

    if (existingCheck.ok && existingCheck.value.rows.length > 0) {
      const existing = existingCheck.value.rows[0] as { id: string; invoice_number: string; status: string };
      return c.json({
        error: 'Invoice already exists for this period',
        existingInvoiceId: existing.id,
        invoiceNumber: existing.invoice_number,
        status: existing.status,
      }, 409);
    }

    const result = await ctx.invoices.createInvoice({
      tenantId,
      periodStart,
      periodEnd,
      lineItems: parsed.lineItems,
      notes: parsed.notes,
    });

    if (!result.ok) {
      // E-181: Log with context so operators can triage and retry
      logger.error('E-181: Invoice generation failed', {
        tenantId,
        periodStart: parsed.periodStart,
        periodEnd: parsed.periodEnd,
        lineItemCount: parsed.lineItems.length,
        error: result.error.message,
      });
      return c.json({
        error: 'Invoice generation failed — please retry',
        retryable: true,
        detail: result.error.message,
      }, 500);
    }

    return c.json(result.value, 201);
  });

  // Get revenue report
  router.get('/reports/revenue', async (c) => {
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    if (!startDate || !endDate) {
      return c.json({ error: 'startDate and endDate required' }, 400);
    }

    const parsedStartDate = parseQueryDate(startDate);
    const parsedEndDate = parseQueryDate(endDate);
    if (!parsedStartDate || !parsedEndDate) {
      return c.json({ error: 'Invalid startDate or endDate' }, 400);
    }

    // FIX-500-361: DATE_TRUNC intervals are all hardcoded string literals (never user-input).
    // If granularity ever becomes user-selectable, validate against:
    // const ALLOWED_DATE_TRUNC_INTERVALS = new Set(['hour', 'day', 'week', 'month', 'quarter', 'year']);
    const result = await ctx.db.query(
      `SELECT 
        DATE_TRUNC('day', paid_at) as date,
        SUM(total) as total_revenue,
        COUNT(*) as invoice_count,
        SUM(tax_amount) as total_tax,
        currency
      FROM invoices
      WHERE status = 'paid' AND paid_at >= $1 AND paid_at < $2
      GROUP BY DATE_TRUNC('day', paid_at), currency
      ORDER BY date`,
      [parsedStartDate, parsedEndDate]
    );

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'revenueReport' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get MRR report
  router.get('/reports/mrr', async (c) => {
    const result = await ctx.db.query(`
      SELECT 
        DATE_TRUNC('month', created_at) as month,
        COUNT(DISTINCT tenant_id) as active_subscriptions,
        SUM(
          CASE 
            WHEN billing_interval = 'month' THEN amount
            WHEN billing_interval = 'year' THEN amount / 12
            ELSE 0
          END
        ) as mrr
      FROM stripe_subscriptions
      WHERE status = 'active'
      GROUP BY DATE_TRUNC('month', created_at)
      ORDER BY month DESC
      LIMIT 12
    `);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'mrrReport' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get churn report
  router.get('/reports/churn', async (c) => {
    const result = await ctx.db.query(`
      WITH churned AS (
        SELECT
          DATE_TRUNC('month', canceled_at) as month,
          COUNT(*) as churned_count,
          SUM(
            CASE
              WHEN billing_interval = 'month' THEN amount
              WHEN billing_interval = 'year' THEN amount / 12
              ELSE 0
            END
          ) as churned_mrr
        FROM stripe_subscriptions
        WHERE status = 'canceled' AND canceled_at IS NOT NULL
        GROUP BY DATE_TRUNC('month', canceled_at)
      ),
      starting AS (
        SELECT
          c.month,
          COUNT(DISTINCT s.tenant_id) as starting_count
        FROM churned c
        LEFT JOIN stripe_subscriptions s
          ON s.status = 'active'
         AND s.created_at < c.month
        GROUP BY c.month
      )
      SELECT
        c.month,
        c.churned_count,
        c.churned_mrr,
        COALESCE(s.starting_count, 0) as starting_count
      FROM churned c
      LEFT JOIN starting s ON s.month = c.month
      ORDER BY c.month DESC
      LIMIT 12
    `);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'churnReport' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get dunning report
  router.get('/reports/dunning', async (c) => {
    const result = await ctx.db.query(`
      SELECT 
        dunning_state,
        COUNT(*) as tenant_count,
        SUM(amount_owed) as total_owed
      FROM dunning_states
      WHERE dunning_state != 'healthy'
      GROUP BY dunning_state
    `);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'dunningReport' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Get cost report
  router.get('/reports/costs', async (c) => {
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    if (!startDate || !endDate) {
      return c.json({ error: 'startDate and endDate required' }, 400);
    }

    const parsedStartDate = parseQueryDate(startDate);
    const parsedEndDate = parseQueryDate(endDate);
    if (!parsedStartDate || !parsedEndDate) {
      return c.json({ error: 'Invalid startDate or endDate' }, 400);
    }

    const result = await ctx.db.query(
      `SELECT 
        DATE_TRUNC('day', recorded_at) as date,
        SUM(storage_cost) as storage_cost,
        SUM(bandwidth_cost) as bandwidth_cost,
        SUM(compute_cost) as compute_cost,
        SUM(dedicated_ip_cost) as dedicated_ip_cost,
        SUM(total_cost) as total_cost,
        SUM(revenue) as revenue,
        (SUM(revenue) - SUM(total_cost)) / NULLIF(SUM(revenue), 0) * 100 as margin_percent
      FROM tenant_costs
      WHERE recorded_at >= $1 AND recorded_at < $2
      GROUP BY DATE_TRUNC('day', recorded_at)
      ORDER BY date`,
      [parsedStartDate, parsedEndDate]
    );

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'costReport' }); return c.json({ error: "Operation failed" }, 500);
    }

    return c.json({ report: result.value.rows });
  });

  // Export billing data
  router.get('/export', async (c) => {
    const type = c.req.query('type');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const format = c.req.query('format') ?? 'csv';

    if (!type || !startDate || !endDate) {
      return c.json({ error: 'type, startDate, and endDate required' }, 400);
    }

    const parsedStartDate = parseQueryDate(startDate);
    const parsedEndDate = parseQueryDate(endDate);
    if (!parsedStartDate || !parsedEndDate) {
      return c.json({ error: 'Invalid startDate or endDate' }, 400);
    }

    let query: string;
    const params: Date[] = [parsedStartDate, parsedEndDate];

    switch (type) {
      case 'invoices':
        query = `
          SELECT 
            i.invoice_number, i.tenant_id, t.name as tenant_name,
            i.subtotal, i.tax_amount, i.total, i.currency,
            i.status, i.issued_at, i.paid_at, i.due_date
          FROM invoices i
          JOIN tenants t ON i.tenant_id = t.id
          WHERE i.issued_at >= $1 AND i.issued_at < $2
          ORDER BY i.issued_at
        `;
        break;
      case 'subscriptions':
        query = `
          SELECT 
            s.tenant_id, t.name as tenant_name,
            p.name as plan_name, s.status,
            s.amount, s.currency, s.billing_interval,
            s.current_period_start, s.current_period_end,
            s.created_at, s.canceled_at
          FROM stripe_subscriptions s
          JOIN tenants t ON s.tenant_id = t.id
          JOIN plans p ON s.plan_id = p.id
          WHERE s.created_at >= $1 AND s.created_at < $2
          ORDER BY s.created_at
        `;
        break;
      case 'transactions':
        query = `
          SELECT 
            w.tenant_id, t.name as tenant_name,
            w.type, w.amount, w.balance_after,
            w.description, w.reference, w.created_at
          FROM wallet_transactions w
          JOIN tenants t ON w.tenant_id = t.id
          WHERE w.created_at >= $1 AND w.created_at < $2
          ORDER BY w.created_at
        `;
        break;
      default:
        return c.json({ error: 'Invalid export type' }, 400);
    }

    const result = await ctx.db.query(query, params);

    if (!result.ok) {
      logger.error('Admin operation failed', { error: String(result.error), operation: 'export' }); return c.json({ error: "Operation failed" }, 500);
    }

    if (format === 'json') {
      return c.json({ data: result.value.rows });
    }

    // CSV format
    if (result.value.rows.length === 0) {
      return c.text('', 200, { 'Content-Type': 'text/csv' });
    }

    const headers = Object.keys(result.value.rows[0]!);
    // Sanitize CSV values to prevent formula injection (=, +, -, @, \t, \r)
    const sanitizeCsvValue = (val: unknown): string => {
      if (val === null || val === undefined) return '';
      let s = String(val);
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      if (s.includes(',') || s.includes('"') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    };
    const csvRows = [
      headers.join(','),
      ...result.value.rows.map((row: Record<string, unknown>) =>
        headers.map(h => sanitizeCsvValue(row[h])).join(',')
      ),
    ];

    const safeDate = (d: string) => d.replace(/[^0-9\-]/g, '');
    return c.text(csvRows.join('\n'), 200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${type}_${safeDate(startDate)}_${safeDate(endDate)}.csv"`,
    });
  });

  return router;
}
