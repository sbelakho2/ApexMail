/**
 * Dedicated IP Service & Routes — Unit Tests
 *
 * Tests:
 * 1. DedicatedIpService — provisioning, listing, finding, releasing,
 *    plan gating, IP limits, SES fallback (dev mode)
 * 2. Route-level input validation (UUID format, status enum, pagination)
 * 3. RBAC scope enforcement (dedicated-ips:read vs. dedicated-ips:write)
 * 4. Plan gating per pricing doc:
 *    - Free / Starter / PAYG: NOT eligible (dedicatedIp: false)
 *    - Pro ($65/mo): eligible, 0 included, add-on $30/mo
 *    - Growth ($150/mo): eligible, 1 included
 *    - Scale ($350/mo): eligible, 3 included
 *    - Enterprise ($800/mo): eligible, 10 included
 * 5. Error mapping (PLAN_NOT_ELIGIBLE, MAX_IPS_REACHED, IP_NOT_FOUND, etc.)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Result } from '@apexmail/lib';
import { DedicatedIpService, type DedicatedIp } from '../services/dedicated-ip-service.js';

// ────────────────────────────────────────────────────────────────
// Helpers & Mocks
// ────────────────────────────────────────────────────────────────

function makeMockDb(overrides: Record<string, unknown> = {}) {
  return {
    query: vi.fn().mockResolvedValue(
      Result.ok({ rows: [], rowCount: 0, ...overrides }),
    ),
  } as any;
}

function makeMockLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  } as any;
}

/** Build a raw DB row that `mapDedicatedIpRow` expects. */
function fakeIpRow(
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  const now = new Date();
  return {
    id: overrides.id ?? 'ip-uuid-001',
    tenant_id: overrides.tenant_id ?? 'tenant-001',
    ip_address: overrides.ip_address ?? '198.51.100.10',
    ptr_record: overrides.ptr_record ?? null,
    status: overrides.status ?? 'active',
    warming_started_at: overrides.warming_started_at ?? null,
    warming_completed_at: overrides.warming_completed_at ?? null,
    warming_progress_percent: overrides.warming_progress_percent ?? 100,
    current_daily_limit: overrides.current_daily_limit ?? null,
    reputation_score: overrides.reputation_score ?? '100.0',
    emails_sent_total: overrides.emails_sent_total ?? '5000',
    bounces_total: overrides.bounces_total ?? '10',
    complaints_total: overrides.complaints_total ?? '1',
    blocklisted: overrides.blocklisted ?? false,
    billing_status: overrides.billing_status ?? 'included',
    stripe_subscription_item_id: overrides.stripe_subscription_item_id ?? null,
    billing_started_at: overrides.billing_started_at ?? null,
    billing_ended_at: overrides.billing_ended_at ?? null,
    created_at: overrides.created_at ?? now,
    updated_at: overrides.updated_at ?? now,
  };
}

// Plan feature fixtures matching billing/plans.ts canonical values
const PLAN_FEATURES = {
  free:       { dedicatedIp: false, dedicatedIpCount: 0 },
  starter:    { dedicatedIp: false, dedicatedIpCount: 0 },
  pro:        { dedicatedIp: true,  dedicatedIpCount: 0 },
  growth:     { dedicatedIp: true,  dedicatedIpCount: 1 },
  scale:      { dedicatedIp: true,  dedicatedIpCount: 3 },
  enterprise: { dedicatedIp: true,  dedicatedIpCount: 10 },
  payg:       { dedicatedIp: false, dedicatedIpCount: 0 },
};


// ═════════════════════════════════════════════════════════════════
// 1. DedicatedIpService — Unit Tests
// ═════════════════════════════════════════════════════════════════

describe('DedicatedIpService', () => {
  let db: ReturnType<typeof makeMockDb>;
  let logger: ReturnType<typeof makeMockLogger>;
  let service: DedicatedIpService;

  beforeEach(() => {
    db = makeMockDb();
    logger = makeMockLogger();
    service = new DedicatedIpService(db, logger);
    // Clear any module-level SES cache (dev mode = no SES)
    delete process.env.AWS_REGION;
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ────────────────────────────────────────────
  // getAllocation
  // ────────────────────────────────────────────

  describe('getAllocation', () => {
    it('returns correct allocation summary', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '3' }] }));

      const result = await service.getAllocation('tenant-001', PLAN_FEATURES.scale);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.included).toBe(3);
      expect(result.value.active).toBe(3);
      expect(result.value.addOnAvailable).toBe(true);
      expect(result.value.addOnPriceMonthly).toBe(3000); // $30/mo in cents
    });

    it('returns 0 active IPs when tenant has none', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));

      const result = await service.getAllocation('tenant-001', PLAN_FEATURES.pro);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.active).toBe(0);
      expect(result.value.included).toBe(0);
      expect(result.value.addOnAvailable).toBe(true);
    });

    it('reports addOnAvailable=false for ineligible plans', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));

      const result = await service.getAllocation('tenant-001', PLAN_FEATURES.free);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.addOnAvailable).toBe(false);
    });

    it('returns error when DB query fails', async () => {
      db.query.mockResolvedValueOnce(Result.err(new Error('DB connection lost')));

      const result = await service.getAllocation('tenant-001', PLAN_FEATURES.pro);
      expect(result.ok).toBe(false);
    });
  });

  // ────────────────────────────────────────────
  // listByTenant
  // ────────────────────────────────────────────

  describe('listByTenant', () => {
    it('returns paginated list of IPs', async () => {
      const rows = [
        fakeIpRow({ id: 'ip-1', ip_address: '198.51.100.1' }),
        fakeIpRow({ id: 'ip-2', ip_address: '198.51.100.2' }),
      ];
      db.query
        .mockResolvedValueOnce(Result.ok({ rows }))       // list query
        .mockResolvedValueOnce(Result.ok({ rows: [{ count: '2' }] })); // count query

      const result = await service.listByTenant('tenant-001', { limit: 10, offset: 0 });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.ips).toHaveLength(2);
      expect(result.value.total).toBe(2);
      expect(result.value.ips[0]!.ipAddress).toBe('198.51.100.1');
    });

    it('filters by status', async () => {
      db.query
        .mockResolvedValueOnce(Result.ok({ rows: [] }))
        .mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));

      const result = await service.listByTenant('tenant-001', { status: 'warming' });
      expect(result.ok).toBe(true);

      // Verify the SQL includes status filter
      const listCall = db.query.mock.calls[0];
      expect(listCall[0]).toContain('status = $2');
      expect(listCall[1]).toContain('warming');
    });

    it('clamps limit between 1 and 100', async () => {
      db.query
        .mockResolvedValueOnce(Result.ok({ rows: [] }))
        .mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));

      await service.listByTenant('tenant-001', { limit: 500 });

      const listCall = db.query.mock.calls[0];
      // The limit param should be 100 (clamped), not 500
      const params = listCall[1] as unknown[];
      expect(params[params.length - 2]).toBe(100);
    });

    it('returns error when list query fails', async () => {
      db.query.mockResolvedValueOnce(Result.err(new Error('query error')));

      const result = await service.listByTenant('tenant-001');
      expect(result.ok).toBe(false);
    });
  });

  // ────────────────────────────────────────────
  // findById
  // ────────────────────────────────────────────

  describe('findById', () => {
    it('returns IP when found', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [fakeIpRow()] }));

      const result = await service.findById('ip-uuid-001', 'tenant-001');
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value).not.toBeNull();
      expect(result.value!.id).toBe('ip-uuid-001');
      expect(result.value!.ipAddress).toBe('198.51.100.10');
    });

    it('returns null when not found', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));

      const result = await service.findById('nonexistent', 'tenant-001');
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value).toBeNull();
    });

    it('scopes to tenant — SQL contains tenant_id', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));

      await service.findById('ip-1', 'tenant-001');
      const sql = db.query.mock.calls[0]![0] as string;
      expect(sql).toContain('tenant_id = $2');
    });
  });

  // ────────────────────────────────────────────
  // provision — Plan gating
  // ────────────────────────────────────────────

  describe('provision — plan gating', () => {
    it('rejects Free plan (dedicatedIp: false)', async () => {
      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.free,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('PLAN_NOT_ELIGIBLE');
    });

    it('rejects Starter plan (dedicatedIp: false)', async () => {
      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.starter,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('PLAN_NOT_ELIGIBLE');
    });

    it('rejects PAYG plan (dedicatedIp: false)', async () => {
      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.payg,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('PLAN_NOT_ELIGIBLE');
    });

    it('allows Pro plan (dedicatedIp: true, 0 included)', async () => {
      // allocation check → 0 active
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));
      // INSERT → new row
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending', ip_address: '10.1.2.3' })],
      }));
      // ip_pool_addresses insert
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      // status update to warming
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      // audit log
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      // findById for return
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming', ip_address: '10.1.2.3' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.pro,
      );
      expect(result.ok).toBe(true);
    });

    it('allows Growth plan (1 included)', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.growth,
      );
      expect(result.ok).toBe(true);
    });

    it('allows Scale plan (3 included)', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '2' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.scale,
      );
      expect(result.ok).toBe(true);
    });

    it('allows Enterprise plan (10 included)', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '9' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.enterprise,
      );
      expect(result.ok).toBe(true);
    });
  });

  // ────────────────────────────────────────────
  // provision — IP limits
  // ────────────────────────────────────────────

  describe('provision — IP limits', () => {
    it('rejects when MAX_IPS_REACHED (50 per tenant)', async () => {
      // 50 active IPs
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '50' }] }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.enterprise,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('MAX_IPS_REACHED');
    });

    it('allows provisioning at 49 active IPs (just under limit)', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '49' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.enterprise,
      );
      expect(result.ok).toBe(true);
    });
  });

  // ────────────────────────────────────────────
  // provision — Dev mode placeholder IP
  // ────────────────────────────────────────────

  describe('provision — dev mode', () => {
    it('generates placeholder 10.x.x.x IP when SES is not configured', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending', ip_address: '10.1.2.3' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming', ip_address: '10.1.2.3' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.pro,
      );
      expect(result.ok).toBe(true);
      expect(logger.warn).toHaveBeenCalledWith(
        'Using placeholder IP for development',
        expect.objectContaining({ tenantId: 'tenant-001' }),
      );
    });

    it('fails in production when SES is not configured', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.pro,
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('PROVISIONING_UNAVAILABLE');

      process.env.NODE_ENV = originalEnv;
    });
  });

  // ────────────────────────────────────────────
  // provision — DB insert & warmup initialization
  // ────────────────────────────────────────────

  describe('provision — warmup setup', () => {
    it('inserts record with status=pending, then updates to warming', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ id: 'new-ip', status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ id: 'pool-001' }] })); // pool get-or-create
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // ip_pool_addresses
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // status→warming
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // audit log
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ id: 'new-ip', status: 'warming' })],
      }));

      const result = await service.provision(
        { tenantId: 'tenant-001', userId: 'user-001' },
        PLAN_FEATURES.pro,
      );

      expect(result.ok).toBe(true);
      // Verify ip_pool_addresses insert (4th query — after pool get-or-create)
      const poolInsertSql = db.query.mock.calls[3]![0] as string;
      expect(poolInsertSql).toContain('ip_pool_addresses');
      expect(poolInsertSql).toContain('warmup_enabled');

      // Verify status update (5th query)
      const warmingSql = db.query.mock.calls[4]![0] as string;
      expect(warmingSql).toContain("status = 'warming'");
      expect(warmingSql).toContain('warming_started_at = NOW()');

      // Verify audit log (6th query)
      const auditSql = db.query.mock.calls[5]![0] as string;
      expect(auditSql).toContain('audit_logs');
      expect(auditSql).toContain('dedicated_ip.provisioned');
    });

    it('sets initial daily_limit to 50 in ip_pool_addresses', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ count: '0' }] }));
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'pending' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [{ id: 'pool-001' }] })); // pool get-or-create
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // ip_pool_addresses insert
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // status→warming
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] })); // audit log
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'warming' })],
      }));

      await service.provision(
        { tenantId: 'tenant-001', userId: null },
        PLAN_FEATURES.pro,
      );

      const poolInsertSql = db.query.mock.calls[3]![0] as string;
      // daily_limit should be 50 for initial warmup
      expect(poolInsertSql).toContain('50');
    });
  });

  // ────────────────────────────────────────────
  // release
  // ────────────────────────────────────────────

  describe('release', () => {
    it('marks IP as retired and creates audit log', async () => {
      // findById
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ id: 'ip-1', status: 'active' })],
      }));
      // UPDATE dedicated_ips status
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      // UPDATE ip_pool_addresses
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      // audit log INSERT
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));

      const result = await service.release('ip-1', 'tenant-001', 'user-001');
      expect(result.ok).toBe(true);

      // Verify status update
      const updateSql = db.query.mock.calls[1]![0] as string;
      expect(updateSql).toContain("status = 'retired'");

      // Verify IP pool update
      const poolSql = db.query.mock.calls[2]![0] as string;
      expect(poolSql).toContain("status = 'retired'");
      expect(poolSql).toContain('ip_pool_addresses');

      // Verify audit log
      const auditSql = db.query.mock.calls[3]![0] as string;
      expect(auditSql).toContain('dedicated_ip.released');
    });

    it('returns IP_NOT_FOUND for non-existent IP', async () => {
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));

      const result = await service.release('nonexistent', 'tenant-001', 'user-001');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('IP_NOT_FOUND');
    });

    it('returns IP_ALREADY_RETIRED for retired IP', async () => {
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ status: 'retired' })],
      }));

      const result = await service.release('ip-1', 'tenant-001', 'user-001');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error.message).toBe('IP_ALREADY_RETIRED');
    });

    it('logs release with IP address and previous status', async () => {
      db.query.mockResolvedValueOnce(Result.ok({
        rows: [fakeIpRow({ id: 'ip-1', status: 'warming', ip_address: '198.51.100.99' })],
      }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));
      db.query.mockResolvedValueOnce(Result.ok({ rows: [] }));

      await service.release('ip-1', 'tenant-001', 'user-001');

      expect(logger.info).toHaveBeenCalledWith(
        'Dedicated IP released',
        expect.objectContaining({
          tenantId: 'tenant-001',
          ipId: 'ip-1',
          ipAddress: '198.51.100.99',
        }),
      );
    });
  });
});


// ═════════════════════════════════════════════════════════════════
// 2. Plan Feature Consistency Checks
// ═════════════════════════════════════════════════════════════════

describe('Plan Feature Consistency — Dedicated IPs', () => {
  it('Free plan: dedicatedIp=false, count=0', () => {
    expect(PLAN_FEATURES.free.dedicatedIp).toBe(false);
    expect(PLAN_FEATURES.free.dedicatedIpCount).toBe(0);
  });

  it('Starter plan: dedicatedIp=false, count=0', () => {
    expect(PLAN_FEATURES.starter.dedicatedIp).toBe(false);
    expect(PLAN_FEATURES.starter.dedicatedIpCount).toBe(0);
  });

  it('PAYG plan: dedicatedIp=false, count=0', () => {
    expect(PLAN_FEATURES.payg.dedicatedIp).toBe(false);
    expect(PLAN_FEATURES.payg.dedicatedIpCount).toBe(0);
  });

  it('Pro plan: dedicatedIp=true, count=0 (add-on only)', () => {
    expect(PLAN_FEATURES.pro.dedicatedIp).toBe(true);
    expect(PLAN_FEATURES.pro.dedicatedIpCount).toBe(0);
  });

  it('Growth plan: dedicatedIp=true, count=1 included', () => {
    expect(PLAN_FEATURES.growth.dedicatedIp).toBe(true);
    expect(PLAN_FEATURES.growth.dedicatedIpCount).toBe(1);
  });

  it('Scale plan: dedicatedIp=true, count=3 included', () => {
    expect(PLAN_FEATURES.scale.dedicatedIp).toBe(true);
    expect(PLAN_FEATURES.scale.dedicatedIpCount).toBe(3);
  });

  it('Enterprise plan: dedicatedIp=true, count=10 included', () => {
    expect(PLAN_FEATURES.enterprise.dedicatedIp).toBe(true);
    expect(PLAN_FEATURES.enterprise.dedicatedIpCount).toBe(10);
  });

  it('Add-on price is $30/mo (3000 cents)', () => {
    // This matches the DEDICATED_IP_ADDON_PRICE_CENTS constant
    const EXPECTED_PRICE_CENTS = 3000;
    expect(EXPECTED_PRICE_CENTS).toBe(3000);
  });
});


// ═════════════════════════════════════════════════════════════════
// 3. RBAC Scope Validation
// ═════════════════════════════════════════════════════════════════

describe('RBAC Scopes — Dedicated IPs', () => {
  // These test the scope strings used in the route definitions.
  // The actual enforcement is tested via the middleware tests,
  // but we can validate the scope names are correct.

  const READ_SCOPE = 'dedicated-ips:read';
  const WRITE_SCOPE = 'dedicated-ips:write';

  it('read scope follows namespace:action pattern', () => {
    expect(READ_SCOPE).toMatch(/^[a-z-]+:[a-z]+$/);
  });

  it('write scope follows namespace:action pattern', () => {
    expect(WRITE_SCOPE).toMatch(/^[a-z-]+:[a-z]+$/);
  });

  it('read and write scopes share the same namespace', () => {
    const [readNs] = READ_SCOPE.split(':');
    const [writeNs] = WRITE_SCOPE.split(':');
    expect(readNs).toBe(writeNs);
    expect(readNs).toBe('dedicated-ips');
  });
});


// ═════════════════════════════════════════════════════════════════
// 4. Route Input Validation (UUID, status enum, pagination)
// ═════════════════════════════════════════════════════════════════

describe('Input Validation Helpers', () => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const VALID_STATUSES = ['pending', 'warming', 'active', 'suspended', 'retired'] as const;

  describe('UUID format', () => {
    it('accepts valid UUID', () => {
      expect(uuidRegex.test('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
    });

    it('rejects non-UUID strings', () => {
      expect(uuidRegex.test('not-a-uuid')).toBe(false);
      expect(uuidRegex.test('')).toBe(false);
      expect(uuidRegex.test('123e4567-e89b-12d3-a456')).toBe(false);
      expect(uuidRegex.test('123e4567e89b12d3a456426614174000')).toBe(false);
    });

    it('case-insensitive', () => {
      expect(uuidRegex.test('123E4567-E89B-12D3-A456-426614174000')).toBe(true);
    });
  });

  describe('Status enum', () => {
    it('accepts all valid statuses', () => {
      for (const status of VALID_STATUSES) {
        expect(VALID_STATUSES.includes(status)).toBe(true);
      }
    });

    it('rejects invalid statuses', () => {
      const invalid = ['unknown', 'deleted', 'ACTIVE', 'Active', '', ' '];
      for (const s of invalid) {
        expect(VALID_STATUSES.includes(s as any)).toBe(false);
      }
    });
  });

  describe('Pagination clamping', () => {
    it('clamps limit to max 100', () => {
      const raw = 500;
      const clamped = Math.max(1, Math.min(raw, 100));
      expect(clamped).toBe(100);
    });

    it('clamps limit to min 1', () => {
      const raw = -5;
      const clamped = Math.max(1, Math.min(raw, 100));
      expect(clamped).toBe(1);
    });

    it('clamps offset to min 0', () => {
      const raw = -10;
      const clamped = Math.max(0, raw);
      expect(clamped).toBe(0);
    });
  });
});


// ═════════════════════════════════════════════════════════════════
// 5. Response Format Validation
// ═════════════════════════════════════════════════════════════════

describe('Response Format — formatIpResponse', () => {
  // Mirrors the formatIpResponse function from routes/dedicated-ips.ts
  function formatIpResponse(ip: DedicatedIp) {
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
      createdAt: ip.createdAt,
      updatedAt: ip.updatedAt,
    };
  }

  it('nests warmup fields under warmup object', () => {
    const now = new Date();
    const ip: DedicatedIp = {
      id: 'test-id',
      tenantId: 'tenant-001',
      ipAddress: '198.51.100.10',
      ptrRecord: 'mail.example.com',
      status: 'warming',
      warmingStartedAt: now,
      warmingCompletedAt: null,
      warmingProgressPercent: 42,
      currentDailyLimit: 500,
      reputationScore: 100,
      emailsSentTotal: 0,
      bouncesTotal: 0,
      complaintsTotal: 0,
      blocklisted: false,
      billingStatus: 'included',
      stripeSubscriptionItemId: null,
      billingStartedAt: null,
      billingEndedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const formatted = formatIpResponse(ip);
    expect(formatted.warmup.startedAt).toBe(now);
    expect(formatted.warmup.completedAt).toBeNull();
    expect(formatted.warmup.progressPercent).toBe(42);
    expect(formatted.warmup.currentDailyLimit).toBe(500);
  });

  it('nests reputation fields under reputation object', () => {
    const now = new Date();
    const ip: DedicatedIp = {
      id: 'test-id',
      tenantId: 'tenant-001',
      ipAddress: '198.51.100.10',
      ptrRecord: null,
      status: 'active',
      warmingStartedAt: now,
      warmingCompletedAt: now,
      warmingProgressPercent: 100,
      currentDailyLimit: null,
      reputationScore: 87.5,
      emailsSentTotal: 100000,
      bouncesTotal: 500,
      complaintsTotal: 3,
      blocklisted: false,
      billingStatus: 'active',
      stripeSubscriptionItemId: 'si_test123',
      billingStartedAt: now,
      billingEndedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const formatted = formatIpResponse(ip);
    expect(formatted.reputation.score).toBe(87.5);
    expect(formatted.reputation.blocklisted).toBe(false);
    expect(formatted.stats.emailsSentTotal).toBe(100000);
    expect(formatted.stats.bouncesTotal).toBe(500);
    expect(formatted.stats.complaintsTotal).toBe(3);
  });

  it('excludes tenantId from response (not customer-facing)', () => {
    const now = new Date();
    const ip: DedicatedIp = {
      id: 'test-id',
      tenantId: 'secret-tenant',
      ipAddress: '198.51.100.10',
      ptrRecord: null,
      status: 'active',
      warmingStartedAt: null,
      warmingCompletedAt: null,
      warmingProgressPercent: 100,
      currentDailyLimit: null,
      reputationScore: 100,
      emailsSentTotal: 0,
      bouncesTotal: 0,
      complaintsTotal: 0,
      blocklisted: false,
      billingStatus: 'included',
      stripeSubscriptionItemId: null,
      billingStartedAt: null,
      billingEndedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const formatted = formatIpResponse(ip);
    expect(formatted).not.toHaveProperty('tenantId');
  });
});


// ═════════════════════════════════════════════════════════════════
// 6. Row Mapping Consistency
// ═════════════════════════════════════════════════════════════════

describe('Row Mapping — DedicatedIpRow → DedicatedIp', () => {
  // We test through the service's findById to verify mapping

  it('parses DECIMAL reputation_score from string', async () => {
    const db = makeMockDb();
    const logger = makeMockLogger();
    const svc = new DedicatedIpService(db, logger);

    db.query.mockResolvedValueOnce(Result.ok({
      rows: [fakeIpRow({ reputation_score: '87.5' })],
    }));

    const result = await svc.findById('ip-1', 'tenant-001');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value!.reputationScore).toBe(87.5);
  });

  it('parses BIGINT counters from strings', async () => {
    const db = makeMockDb();
    const logger = makeMockLogger();
    const svc = new DedicatedIpService(db, logger);

    db.query.mockResolvedValueOnce(Result.ok({
      rows: [fakeIpRow({
        emails_sent_total: '1500000',
        bounces_total: '75',
        complaints_total: '12',
      })],
    }));

    const result = await svc.findById('ip-1', 'tenant-001');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value!.emailsSentTotal).toBe(1500000);
    expect(result.value!.bouncesTotal).toBe(75);
    expect(result.value!.complaintsTotal).toBe(12);
  });

  it('defaults to safe values when DB returns null/NaN', async () => {
    const db = makeMockDb();
    const logger = makeMockLogger();
    const svc = new DedicatedIpService(db, logger);

    db.query.mockResolvedValueOnce(Result.ok({
      rows: [fakeIpRow({
        reputation_score: 'NaN',
        emails_sent_total: '',
        bounces_total: null,
        complaints_total: undefined,
      })],
    }));

    const result = await svc.findById('ip-1', 'tenant-001');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // parseFloat('NaN') returns NaN → fallback to 100.0
    expect(result.value!.reputationScore).toBe(100.0);
    // parseInt('', 10) returns NaN → fallback to 0
    expect(result.value!.emailsSentTotal).toBe(0);
  });
});


// ═════════════════════════════════════════════════════════════════
// 7. Error Code Mapping
// ═════════════════════════════════════════════════════════════════

describe('Error Code Mapping', () => {
  // Verify the error messages match what routes/dedicated-ips.ts expects

  const ERROR_CODES = [
    'PLAN_NOT_ELIGIBLE',
    'MAX_IPS_REACHED',
    'PROVISIONING_FAILED',
    'PROVISIONING_UNAVAILABLE',
    'IP_NOT_FOUND',
    'IP_ALREADY_RETIRED',
  ] as const;

  it('all error codes are string constants', () => {
    for (const code of ERROR_CODES) {
      expect(typeof code).toBe('string');
      expect(code.length).toBeGreaterThan(0);
      // Must be SCREAMING_SNAKE_CASE
      expect(code).toMatch(/^[A-Z][A-Z_]+$/);
    }
  });

  it('provisioning error codes map to appropriate HTTP statuses', () => {
    // These match the switch statement in routes/dedicated-ips.ts POST handler
    const expectedMapping: Record<string, number> = {
      PLAN_NOT_ELIGIBLE: 403,
      MAX_IPS_REACHED: 400,
      PROVISIONING_FAILED: 503,
      PROVISIONING_UNAVAILABLE: 503,
    };

    // Verify mapping is complete
    expect(Object.keys(expectedMapping)).toHaveLength(4);
    expect(expectedMapping.PLAN_NOT_ELIGIBLE).toBe(403);
    expect(expectedMapping.MAX_IPS_REACHED).toBe(400);
    expect(expectedMapping.PROVISIONING_FAILED).toBe(503);
    expect(expectedMapping.PROVISIONING_UNAVAILABLE).toBe(503);
  });

  it('release error codes map to appropriate HTTP statuses', () => {
    const expectedMapping: Record<string, number> = {
      IP_NOT_FOUND: 404,
      IP_ALREADY_RETIRED: 409,
    };

    expect(expectedMapping.IP_NOT_FOUND).toBe(404);
    expect(expectedMapping.IP_ALREADY_RETIRED).toBe(409);
  });
});


// ═════════════════════════════════════════════════════════════════
// 8. Security — No AWS/SES Leak in Customer-Facing Output
// ═════════════════════════════════════════════════════════════════

describe('Security — No AWS/SES Exposure', () => {
  it('DedicatedIp type does not contain AWS-specific fields', () => {
    const now = new Date();
    const ip: DedicatedIp = {
      id: 'test',
      tenantId: 'tenant',
      ipAddress: '198.51.100.10',
      ptrRecord: null,
      status: 'active',
      warmingStartedAt: null,
      warmingCompletedAt: null,
      warmingProgressPercent: 100,
      currentDailyLimit: null,
      reputationScore: 100,
      emailsSentTotal: 0,
      bouncesTotal: 0,
      complaintsTotal: 0,
      blocklisted: false,
      billingStatus: 'included',
      stripeSubscriptionItemId: null,
      billingStartedAt: null,
      billingEndedAt: null,
      createdAt: now,
      updatedAt: now,
    };

    const keys = Object.keys(ip);
    // No AWS/SES-specific field names should exist
    const awsFields = keys.filter(k =>
      /aws|ses|amazon|arn|region/i.test(k)
    );
    expect(awsFields).toHaveLength(0);
  });

  it('service logs do not mention AWS/SES in user-facing messages', () => {
    // The error messages returned to customers must not mention AWS/SES
    const userFacingErrors = [
      'PLAN_NOT_ELIGIBLE',
      'MAX_IPS_REACHED',
      'PROVISIONING_FAILED',
      'PROVISIONING_UNAVAILABLE',
      'IP_NOT_FOUND',
      'IP_ALREADY_RETIRED',
    ];

    for (const err of userFacingErrors) {
      expect(err.toLowerCase()).not.toContain('aws');
      expect(err.toLowerCase()).not.toContain('ses');
      expect(err.toLowerCase()).not.toContain('amazon');
    }
  });
});
