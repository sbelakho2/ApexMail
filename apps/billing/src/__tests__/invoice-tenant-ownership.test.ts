import { describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';

vi.mock('@apexmail/db', () => ({
  withTransaction: vi.fn(),
}));

vi.mock('../services/plans.js', () => ({
  calculateOverageCost: vi.fn(),
  calculatePaygCost: vi.fn(),
  PAYG_PRICING: {},
}));

vi.mock('../lib/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  },
}));

import type { BillingContext, BillingEnv } from '../app.js';
import { billingRoutes } from '../routes/billing.js';

type Invoice = {
  id: string;
  tenantId: string;
  stripeInvoiceId: string | null;
  invoiceNumber: string;
  status: 'draft' | 'pending' | 'paid' | 'void' | 'uncollectible';
  currency: string;
  subtotal: number;
  vatTotal: number;
  total: number;
  lineItems: unknown[];
  billingAddress: {
    companyName: string;
    vatNumber: string | null;
    addressLine1: string;
    addressLine2: string | null;
    city: string;
    state: string | null;
    postalCode: string;
    country: string;
    email: string;
  };
  issuedAt: Date;
  dueAt: Date;
  paidAt: Date | null;
  periodStart: Date;
  periodEnd: Date;
  purchaseOrderNumber: string | null;
  notes: string | null;
  pdfUrl: string | null;
  xmlUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
};

function buildBillingRouteApp(
  ctx: Partial<BillingContext>,
  tenantId = 'tenant_123',
) {
  const app = new Hono<BillingEnv>();

  app.use('*', async (c, next) => {
    c.set('tenantId', tenantId);
    c.set('userId', 'user_123');
    c.set('isAdmin', false);
    c.set('adminId', '');
    await next();
  });

  app.route('/', billingRoutes(ctx as BillingContext));
  return app;
}

function buildInvoice(overrides: Partial<Invoice> = {}): Invoice {
  return {
    id: 'inv_123',
    tenantId: 'tenant_123',
    stripeInvoiceId: null,
    invoiceNumber: '2026-TEST-000001',
    status: 'pending',
    currency: 'EUR',
    subtotal: 1000,
    vatTotal: 220,
    total: 1220,
    lineItems: [],
    billingAddress: {
      companyName: 'ApexMail',
      vatNumber: null,
      addressLine1: 'Sakala 7-2',
      addressLine2: null,
      city: 'Tallinn',
      state: null,
      postalCode: '10141',
      country: 'EE',
      email: 'billing@apexmail.ee',
    },
    issuedAt: new Date('2026-01-01T00:00:00Z'),
    dueAt: new Date('2026-01-15T00:00:00Z'),
    paidAt: null,
    periodStart: new Date('2025-12-01T00:00:00Z'),
    periodEnd: new Date('2025-12-31T23:59:59Z'),
    purchaseOrderNumber: null,
    notes: null,
    pdfUrl: null,
    xmlUrl: null,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

describe('billing invoice tenant ownership', () => {
  it('passes the authenticated tenant into invoice detail lookups', async () => {
    const getInvoice = vi.fn().mockResolvedValue({ ok: true, value: buildInvoice() });
    const app = buildBillingRouteApp({
      invoices: {
        getInvoice,
      },
    });

    const response = await app.request('http://billing.local/invoices/inv_123');

    expect(response.status).toBe(200);
    expect(getInvoice).toHaveBeenCalledWith('inv_123', 'tenant_123');
  });

  it('returns 404 when the invoice service does not find a tenant-scoped invoice', async () => {
    const getInvoice = vi.fn().mockResolvedValue({ ok: true, value: null });
    const app = buildBillingRouteApp({
      invoices: {
        getInvoice,
      },
    }, 'tenant_abc');

    const response = await app.request('http://billing.local/invoices/inv_other');

    expect(response.status).toBe(404);
    expect(getInvoice).toHaveBeenCalledWith('inv_other', 'tenant_abc');
  });
});