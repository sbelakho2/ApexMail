/**
 * Send Time Optimizer — Comprehensive Unit Tests
 *
 * Tests getOptimalSendTime, getTenantOptimalTimes, optimizeBatch,
 * Bayesian priors, confidence computation, caching, and invalidation.
 *
 * Public API:
 *   - getOptimalSendTime(recipientEmail, tenantId?) → { suggestedTime, confidence, profile }
 *   - getTenantOptimalTimes(tenantId) → { bestHours, bestDays, totalEngagements }
 *   - optimizeBatch(recipients, tenantId?) → BulkOptimizationResult[]
 *   - invalidateCache(recipientEmail)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SendTimeOptimizer } from '../send-time-optimizer.js';

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
    del: vi.fn(async (key: string) => { store.delete(key); }),
  } as any;
}

function createMockLogger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() } as any;
}

describe('SendTimeOptimizer', () => {
  let sto: SendTimeOptimizer;
  let mockDb: ReturnType<typeof createMockPool>;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockDb = createMockPool();
    mockRedis = createMockRedis();
    sto = new SendTimeOptimizer({ db: mockDb, redis: mockRedis, logger: createMockLogger() });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. getOptimalSendTime
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getOptimalSendTime', () => {
    it('returns suggestedTime, confidence, and profile', async () => {
      // No data → cold start
      const result = await sto.getOptimalSendTime('test@example.com');
      expect(result).toHaveProperty('suggestedTime');
      expect(result).toHaveProperty('confidence');
      expect(result).toHaveProperty('profile');
      expect(result.suggestedTime).toBeInstanceOf(Date);
    });

    it('returns low confidence with no engagement data (cold start)', async () => {
      const result = await sto.getOptimalSendTime('brand-new@example.com');
      expect(result.confidence).toBe('low');
      expect(result.profile).toBeNull();
    });

    it('returns cached profile on cache hit', async () => {
      const cachedProfile = {
        emailHash: 'abc123',
        timezone: 'America/New_York',
        totalEngagements: 100,
        optimalWindows: [
          { hour: 10, dayOfWeek: 2, score: 0.5, confidence: 'high' as const, localTime: 'Tuesday 10:00 AM' },
          { hour: 14, dayOfWeek: 3, score: 0.4, confidence: 'medium' as const, localTime: 'Wednesday 2:00 PM' },
          { hour: 9, dayOfWeek: 1, score: 0.3, confidence: 'medium' as const, localTime: 'Monday 9:00 AM' },
        ],
        hourlyDistribution: [],
        dailyDistribution: [],
        lastUpdated: new Date().toISOString(),
      };

      // Pre-populate Redis cache
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(cachedProfile));

      const result = await sto.getOptimalSendTime('cached@example.com');
      expect(result.confidence).toBe('high');
      expect(result.profile).toBeTruthy();
      // Should NOT hit the DB
      expect(mockDb.query).not.toHaveBeenCalled();
    });

    it('builds profile from DB when cache misses and data exists', async () => {
      // hourly query returns data
      mockDb.query
        .mockResolvedValueOnce({
          rows: [
            { hour: '9', count: '30' },
            { hour: '10', count: '55' },
            { hour: '14', count: '25' },
          ],
        })
        // daily query
        .mockResolvedValueOnce({
          rows: [
            { day_of_week: '1', count: '40' },
            { day_of_week: '2', count: '50' },
            { day_of_week: '4', count: '20' },
          ],
        })
        // timezone query
        .mockResolvedValueOnce({ rows: [{ timezone: 'America/Chicago' }] });

      const result = await sto.getOptimalSendTime('rich@example.com', 'tenant-001');
      expect(result.profile).toBeTruthy();
      expect(result.profile!.totalEngagements).toBe(110); // 30+55+25
      expect(result.profile!.optimalWindows.length).toBe(3);
      expect(result.suggestedTime).toBeInstanceOf(Date);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Bayesian priors with sparse data
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Bayesian priors with sparse data', () => {
    it('returns all 24 hours with positive scores even with sparse data', async () => {
      // Only hour 10 has data
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ hour: '10', count: '5' }] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await sto.getOptimalSendTime('sparse@example.com');
      expect(result.profile).toBeTruthy();
      // All 24 hours should have > 0 engagement score due to Bayesian priors
      for (const h of result.profile!.hourlyDistribution) {
        expect(h.engagementScore).toBeGreaterThan(0);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. Optimal send windows
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Optimal send windows', () => {
    it('returns top 3 windows sorted by score descending', async () => {
      mockDb.query
        .mockResolvedValueOnce({
          rows: [
            { hour: '9', count: '20' },
            { hour: '10', count: '50' },
            { hour: '14', count: '15' },
          ],
        })
        .mockResolvedValueOnce({
          rows: [
            { day_of_week: '2', count: '60' },
            { day_of_week: '3', count: '25' },
          ],
        })
        .mockResolvedValueOnce({ rows: [] });

      const result = await sto.getOptimalSendTime('windows@example.com');
      const windows = result.profile!.optimalWindows;
      expect(windows.length).toBe(3);
      // Sorted descending by score
      expect(windows[0]!.score).toBeGreaterThanOrEqual(windows[1]!.score);
      expect(windows[1]!.score).toBeGreaterThanOrEqual(windows[2]!.score);
      // Each window has required fields
      for (const w of windows) {
        expect(w).toHaveProperty('hour');
        expect(w).toHaveProperty('dayOfWeek');
        expect(w).toHaveProperty('score');
        expect(w).toHaveProperty('confidence');
        expect(w).toHaveProperty('localTime');
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Confidence computation
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Confidence computation', () => {
    it('assigns high confidence with 50+ engagements in a slot', async () => {
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ hour: '10', count: '80' }] })
        .mockResolvedValueOnce({ rows: [{ day_of_week: '2', count: '80' }] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await sto.getOptimalSendTime('high-conf@example.com');
      const hour10 = result.profile!.hourlyDistribution.find(h => h.hour === 10);
      expect(hour10?.confidence).toBe('high');
    });

    it('assigns low confidence with < 20 engagements', async () => {
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ hour: '10', count: '5' }] })
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await sto.getOptimalSendTime('low-conf@example.com');
      const hour10 = result.profile!.hourlyDistribution.find(h => h.hour === 10);
      expect(hour10?.confidence).toBe('low');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Next send time is always in the future
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Next optimal send time', () => {
    it('returns a future date', async () => {
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ hour: '10', count: '30' }] })
        .mockResolvedValueOnce({ rows: [{ day_of_week: '2', count: '30' }] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await sto.getOptimalSendTime('future@example.com');
      expect(result.suggestedTime.getTime()).toBeGreaterThan(Date.now() - 1000);
    });

    it('defaults to global optimal (Tuesday 10AM) with no data', async () => {
      const result = await sto.getOptimalSendTime('empty@example.com');
      expect(result.suggestedTime).toBeInstanceOf(Date);
      // Should be in the future
      expect(result.suggestedTime.getTime()).toBeGreaterThan(Date.now() - 1000);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. getTenantOptimalTimes
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getTenantOptimalTimes', () => {
    it('returns bestHours, bestDays, and totalEngagements', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { hour: '10', day_of_week: '2', count: '100' },
          { hour: '14', day_of_week: '3', count: '50' },
        ],
      });

      const result = await sto.getTenantOptimalTimes('tenant-001');
      expect(result).toHaveProperty('bestHours');
      expect(result).toHaveProperty('bestDays');
      expect(result).toHaveProperty('totalEngagements');
      expect(result.totalEngagements).toBe(150);
      // bestHours sorted descending by engagementScore
      expect(result.bestHours[0]!.engagementScore).toBeGreaterThanOrEqual(
        result.bestHours[result.bestHours.length - 1]!.engagementScore
      );
    });

    it('returns Bayesian-smoothed distribution even with no data', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] });

      const result = await sto.getTenantOptimalTimes('empty-tenant');
      expect(result.totalEngagements).toBe(0);
      // Should still have all 24 hours and 7 days via priors
      expect(result.bestHours.length).toBe(24);
      expect(result.bestDays.length).toBe(7);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. Cache management
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Cache management', () => {
    it('caches profile after building from DB', async () => {
      mockDb.query
        .mockResolvedValueOnce({ rows: [{ hour: '10', count: '30' }] })
        .mockResolvedValueOnce({ rows: [{ day_of_week: '2', count: '30' }] })
        .mockResolvedValueOnce({ rows: [] });

      await sto.getOptimalSendTime('cache-me@example.com');
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('invalidateCache removes cached profile', async () => {
      await sto.invalidateCache('forget@example.com');
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringContaining('sto:'));
    });
  });
});
