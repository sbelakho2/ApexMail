/**
 * Inbox Placement Service — Comprehensive Unit Tests
 *
 * Tests seed-list management, placement test execution, summary calculation,
 * provider analysis, trend detection, and recommendation generation.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { InboxPlacementService } from '../inbox-placement.js';
import type { PlacementTestResult } from '../inbox-placement.js';

// ─── Mocks ───────────────────────────────────────────────────────────────────

function createMockPool() {
  return {
    query: vi.fn().mockResolvedValue({ rows: [] }),
  } as any;
}

function createMockRedis() {
  const store = new Map<string, string>();
  return {
    get: vi.fn(async (key: string) => store.get(key) || null),
    setex: vi.fn(async (key: string, _ttl: number, val: string) => { store.set(key, val); }),
    zadd: vi.fn(async () => {}),
    del: vi.fn(async (key: string) => { store.delete(key); }),
  } as any;
}

function createMockLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  } as any;
}

function createMockSendEmail() {
  return vi.fn().mockResolvedValue(undefined);
}

function createMockCheckMailbox() {
  return vi.fn().mockResolvedValue({
    seedAccountId: 'seed-1',
    provider: 'gmail',
    placement: 'inbox' as const,
    deliveredAt: new Date(),
    checkedAt: new Date(),
  });
}

describe('InboxPlacementService', () => {
  let service: InboxPlacementService;
  let mockDb: ReturnType<typeof createMockPool>;
  let mockRedis: ReturnType<typeof createMockRedis>;
  let mockSend: ReturnType<typeof createMockSendEmail>;
  let mockCheck: ReturnType<typeof createMockCheckMailbox>;

  beforeEach(() => {
    mockDb = createMockPool();
    mockRedis = createMockRedis();
    mockSend = createMockSendEmail();
    mockCheck = createMockCheckMailbox();
    service = new InboxPlacementService({
      db: mockDb,
      redis: mockRedis,
      logger: createMockLogger(),
      sendEmail: mockSend,
      checkMailbox: mockCheck,
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. Test Execution
  // ═══════════════════════════════════════════════════════════════════════════

  describe('runPlacementTest', () => {
    it('sends test emails to all active seed accounts', async () => {
      // Mock active seed accounts
      mockDb.query
        // getAllActiveSeedAccounts
        .mockResolvedValueOnce({
          rows: [
            { id: 'seed-1', email: 'test@gmail.com', provider: 'gmail', imap_host: 'imap.gmail.com', imap_port: 993, imap_user: 'test', imap_password_encrypted: 'enc', status: 'active' },
            { id: 'seed-2', email: 'test@outlook.com', provider: 'outlook', imap_host: 'imap.outlook.com', imap_port: 993, imap_user: 'test', imap_password_encrypted: 'enc', status: 'active' },
          ],
        })
        // saveTest (INSERT)
        .mockResolvedValueOnce({ rows: [] })
        // saveTest (UPDATE status)
        .mockResolvedValueOnce({ rows: [] });

      const test = await service.runPlacementTest('tenant-001', {
        testName: 'Weekly Test',
        subject: 'Test Email',
        htmlBody: '<p>Hello</p>',
        fromAddress: 'test@apexmail.com',
      });

      expect(test).toBeDefined();
      expect(test.tenantId).toBe('tenant-001');
      expect(test.testName).toBe('Weekly Test');
      expect(test.status).toBe('checking');
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('handles send failures gracefully', async () => {
      mockDb.query
        .mockResolvedValueOnce({
          rows: [
            { id: 'seed-1', email: 'test@gmail.com', provider: 'gmail', imap_host: 'imap.gmail.com', imap_port: 993, imap_user: 'test', imap_password_encrypted: 'enc', status: 'active' },
          ],
        })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      mockSend.mockRejectedValueOnce(new Error('SMTP error'));

      // Should not throw
      const test = await service.runPlacementTest('tenant-001', {
        testName: 'Fail Test',
        subject: 'Test Email',
        htmlBody: '<p>Hello</p>',
        fromAddress: 'test@apexmail.com',
      });

      expect(test).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Summary Calculation
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Summary calculation', () => {
    it('correctly computes inbox rate', async () => {
      // Setup a test and then check results
      mockDb.query
        // getTest
        .mockResolvedValueOnce({
          rows: [{
            id: 'test-1',
            tenant_id: 'tenant-001',
            campaign_id: null,
            test_name: 'Test',
            subject: 'Subject',
            from_address: 'from@test.com',
            status: 'checking',
            results: '[]',
            summary: '{}',
            created_at: new Date(),
            completed_at: null,
          }],
        })
        // getAllActiveSeedAccounts
        .mockResolvedValueOnce({
          rows: [
            { id: 'seed-1', email: 'g1@gmail.com', provider: 'gmail', status: 'active' },
            { id: 'seed-2', email: 'g2@gmail.com', provider: 'gmail', status: 'active' },
            { id: 'seed-3', email: 'o1@outlook.com', provider: 'outlook', status: 'active' },
            { id: 'seed-4', email: 'y1@yahoo.com', provider: 'yahoo', status: 'active' },
          ],
        })
        // saveTest (final update)
        .mockResolvedValueOnce({ rows: [] });

      // Mock mailbox checks: 2 inbox, 1 spam, 1 missing
      mockCheck
        .mockResolvedValueOnce({ seedAccountId: 'seed-1', provider: 'gmail', placement: 'inbox', deliveredAt: new Date(), checkedAt: new Date() })
        .mockResolvedValueOnce({ seedAccountId: 'seed-2', provider: 'gmail', placement: 'inbox', deliveredAt: new Date(), checkedAt: new Date() })
        .mockResolvedValueOnce({ seedAccountId: 'seed-3', provider: 'outlook', placement: 'spam', deliveredAt: new Date(), checkedAt: new Date() })
        .mockResolvedValueOnce({ seedAccountId: 'seed-4', provider: 'yahoo', placement: 'missing', deliveredAt: null, checkedAt: new Date() });

      const result = await service.checkTestResults('test-1');

      expect(result.status).toBe('completed');
      expect(result.summary.totalSent).toBe(4);
      expect(result.summary.inboxCount).toBe(2);
      expect(result.summary.spamCount).toBe(1);
      expect(result.summary.missingCount).toBe(1);
      expect(result.summary.inboxRate).toBe(50); // 2/4 * 100
      expect(result.summary.deliveryRate).toBe(75); // 3/4 * 100

      // Provider breakdown
      expect(result.summary.byProvider.gmail.inbox).toBe(2);
      expect(result.summary.byProvider.gmail.inboxRate).toBe(100);
      expect(result.summary.byProvider.outlook.spam).toBe(1);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. Placement Trends
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getPlacementTrends', () => {
    it('returns trend data with period granularity', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: '2024-01-01', avg_inbox_rate: '85.5', avg_spam_rate: '8.2', test_count: '4' },
          { period: '2024-01-08', avg_inbox_rate: '88.0', avg_spam_rate: '6.5', test_count: '3' },
          { period: '2024-01-15', avg_inbox_rate: '91.2', avg_spam_rate: '4.1', test_count: '5' },
        ],
      });

      const result = await service.getPlacementTrends('tenant-001', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        granularity: 'week',
      });

      expect(result.periods.length).toBe(3);
      expect(result.overallTrend).toBe('improving'); // 91.2 - 85.5 = +5.7
      expect(result.recommendation).toBeTruthy();
    });

    it('detects declining trend', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: '2024-01-01', avg_inbox_rate: '92.0', avg_spam_rate: '3.0', test_count: '4' },
          { period: '2024-02-01', avg_inbox_rate: '85.0', avg_spam_rate: '8.0', test_count: '4' },
        ],
      });

      const result = await service.getPlacementTrends('tenant-001', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-02-28'),
        granularity: 'month',
      });

      expect(result.overallTrend).toBe('declining'); // 85 - 92 = -7
    });

    it('returns stable for flat trends', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: '2024-01-01', avg_inbox_rate: '90.0', avg_spam_rate: '5.0', test_count: '4' },
          { period: '2024-02-01', avg_inbox_rate: '91.0', avg_spam_rate: '4.5', test_count: '4' },
        ],
      });

      const result = await service.getPlacementTrends('tenant-001', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-02-28'),
        granularity: 'month',
      });

      expect(result.overallTrend).toBe('stable'); // +1 is within ±5 threshold
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Provider Analysis
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getProviderAnalysis', () => {
    it('returns per-provider stats with tips', async () => {
      // Mock provider queries (one per provider)
      const providers = ['gmail', 'outlook', 'yahoo', 'aol', 'icloud', 'other'];
      for (const provider of providers) {
        if (provider === 'gmail') {
          mockDb.query.mockResolvedValueOnce({
            rows: [
              { inbox_rate: '72.0', spam_rate: '18.0', test_count: '10', week_num: '1' },
              { inbox_rate: '78.0', spam_rate: '14.0', test_count: '8', week_num: '2' },
            ],
          });
        } else {
          mockDb.query.mockResolvedValueOnce({ rows: [] });
        }
      }

      const result = await service.getProviderAnalysis('tenant-001', 30);

      expect(result.gmail).toBeDefined();
      expect(result.gmail.avgInboxRate).toBeCloseTo(75); // avg of 72 and 78
      expect(result.gmail.tips.length).toBeGreaterThan(0);
      expect(result.gmail.tips.some(t => t.includes('Gmail') || t.includes('Google'))).toBe(true);
    });

    it('provides helpful tips for providers with no data', async () => {
      const providers = ['gmail', 'outlook', 'yahoo', 'aol', 'icloud', 'other'];
      for (const _provider of providers) {
        mockDb.query.mockResolvedValueOnce({ rows: [] });
      }

      const result = await service.getProviderAnalysis('new-tenant', 30);

      expect(result.gmail.testCount).toBe(0);
      expect(result.gmail.tips).toBeDefined();
      expect(result.gmail.tips.length).toBeGreaterThan(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Recommendations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Recommendations', () => {
    it('generates critical recommendation for very low inbox rate', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: '2024-01-01', avg_inbox_rate: '55.0', avg_spam_rate: '30.0', test_count: '4' },
        ],
      });

      const result = await service.getPlacementTrends('tenant-001', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        granularity: 'month',
      });

      expect(result.recommendation.toLowerCase()).toMatch(/critical|below|improve/);
    });

    it('gives positive recommendation for healthy placement', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: '2024-01-01', avg_inbox_rate: '95.0', avg_spam_rate: '2.0', test_count: '4' },
        ],
      });

      const result = await service.getPlacementTrends('tenant-001', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31'),
        granularity: 'month',
      });

      expect(result.recommendation.toLowerCase()).toMatch(/good|healthy|monitoring/);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. Migration SQL
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Database migration', () => {
    it('exports a valid migration SQL string', async () => {
      const { INBOX_PLACEMENT_MIGRATION } = await import('../inbox-placement.js');

      expect(INBOX_PLACEMENT_MIGRATION).toBeDefined();
      expect(INBOX_PLACEMENT_MIGRATION).toContain('CREATE TABLE');
      expect(INBOX_PLACEMENT_MIGRATION).toContain('seed_accounts');
      expect(INBOX_PLACEMENT_MIGRATION).toContain('inbox_placement_tests');
      expect(INBOX_PLACEMENT_MIGRATION).toContain('CREATE INDEX');
    });
  });
});
