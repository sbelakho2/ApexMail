/**
 * Query Engine — Comprehensive Unit Tests
 *
 * The QueryEngine imports config.ts (which calls process.exit on invalid env)
 * and duckdb (native module). Both are mocked.
 *
 * Public API:
 *   - getTimeSeries(query: AnalyticsQuery) → TimeSeriesPoint[]
 *   - getAggregation(query, dimension) → AggregationResult[]
 *   - getFunnelAnalysis(query) → { stages }
 *   - getDeliverabilityMetrics(query) → rates
 *   - getRealtimeStats(tenantId) → { today, thisHour }
 *   - close()
 *
 * All queries take AnalyticsQuery: { tenantId, startDate, endDate, eventTypes?, groupBy?, dimensions?, limit? }
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// ─── Module mocks (must be before import) ────────────────────────────────────

vi.mock('../config.js', () => ({
  config: {
    env: 'development',
    server: { port: 3000, host: '0.0.0.0' },
    duckdb: { memoryLimit: '32GB', threads: 24, dataDir: '/tmp/test-duckdb' },
    db: { host: 'localhost', port: 5432, database: 'test', user: 'test', password: 'test', maxConnections: 10 },
    redis: { url: 'redis://localhost:6379' },
    compaction: { intervalMinutes: 60, batchSize: 100000, retentionDays: 90 },
  },
}));

vi.mock('duckdb', () => ({
  default: {
    Database: vi.fn().mockImplementation(() => ({
      run: vi.fn(),
      all: vi.fn((_q: string, cb: (err: null, rows: never[]) => void) => cb(null, [])),
      close: vi.fn((cb?: () => void) => cb?.()),
      connect: vi.fn().mockReturnValue({ run: vi.fn(), all: vi.fn() }),
    })),
  },
  Database: vi.fn().mockImplementation(() => ({
    run: vi.fn(),
    all: vi.fn((_q: string, cb: (err: null, rows: never[]) => void) => cb(null, [])),
    close: vi.fn((cb?: () => void) => cb?.()),
    connect: vi.fn().mockReturnValue({ run: vi.fn(), all: vi.fn() }),
  })),
}));

import { QueryEngine } from '../query-engine.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createMockPool() {
  return { query: vi.fn().mockResolvedValue({ rows: [] }) };
}

function createMockRedis() {
  return {
    get: vi.fn(async () => null),
    setex: vi.fn(async () => {}),
    del: vi.fn(async () => {}),
    hgetall: vi.fn(async () => ({})),
    pipeline: vi.fn(() => {
      const results: Array<[null, string | null]> = [];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- self-referencing mock pipe
      const pipe: Record<string, any> = {};
      pipe.get = vi.fn(() => { results.push([null, '42']); return pipe; });
      pipe.hgetall = vi.fn(() => pipe);
      pipe.exec = vi.fn(async () => results);
      return pipe;
    }),
  };
}

function createMockLogger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), child: vi.fn().mockReturnThis() };
}

function baseQuery(tenantId = 'tenant-001') {
  return {
    tenantId,
    startDate: new Date('2024-01-01'),
    endDate: new Date('2024-01-31'),
  };
}

describe('QueryEngine', () => {
  let engine: QueryEngine;
  let mockDb: ReturnType<typeof createMockPool>;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockDb = createMockPool();
    mockRedis = createMockRedis();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- mock objects are partial implementations
    engine = new QueryEngine({ db: mockDb as any, redis: mockRedis as any, logger: createMockLogger() as any });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. Construction
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Construction', () => {
    it('creates an instance without throwing', () => {
      expect(engine).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. getTimeSeries
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getTimeSeries', () => {
    it('returns timestamp+value array from Postgres', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { period: new Date('2024-01-01T00:00:00Z'), count: '100' },
          { period: new Date('2024-01-02T00:00:00Z'), count: '120' },
        ],
      });

      const result = await engine.getTimeSeries(baseQuery());
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(2);
      expect(result[0]).toHaveProperty('timestamp');
      expect(result[0]).toHaveProperty('value');
      const first = result[0];
      expect(first).toBeDefined();
      expect(first?.value).toBe(100);
    });

    it('calls DB with correct tenant query', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] });
      await engine.getTimeSeries(baseQuery('t-abc'));
      expect(mockDb.query).toHaveBeenCalledTimes(1);
      // First positional param should be the tenant ID
      const params = mockDb.query.mock.calls[0]?.[1] as unknown[];
      expect(params[0]).toBe('t-abc');
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. getAggregation
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getAggregation', () => {
    it('returns dimension + count + percentage', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { dimension: 'opened', count: '300' },
          { dimension: 'clicked', count: '100' },
        ],
      });

      const result = await engine.getAggregation(baseQuery(), 'event_type');
      expect(result.length).toBe(2);
      expect(result[0]).toHaveProperty('dimension');
      expect(result[0]).toHaveProperty('count');
      expect(result[0]).toHaveProperty('percentage');
      const firstAgg = result[0];
      expect(firstAgg).toBeDefined();
      expect(firstAgg?.percentage).toBeCloseTo(75); // 300/(300+100)
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. getDeliverabilityMetrics
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getDeliverabilityMetrics', () => {
    it('returns rate metrics', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { event_type: 'sent', count: '1000' },
          { event_type: 'delivered', count: '950' },
          { event_type: 'bounced', count: '30' },
          { event_type: 'complained', count: '2' },
          { event_type: 'opened', count: '300' },
          { event_type: 'clicked', count: '80' },
          { event_type: 'unsubscribed', count: '5' },
        ],
      });

      const result = await engine.getDeliverabilityMetrics(baseQuery());
      expect(result.deliveryRate).toBe(95);
      expect(result.bounceRate).toBe(3);
      expect(result.openRate).toBe(32); // 300/950 ≈ 31.6 → 32
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. getFunnelAnalysis
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getFunnelAnalysis', () => {
    it('returns funnel stages with dropoff', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [
          { event_type: 'queued', count: '10000' },
          { event_type: 'sent', count: '9800' },
          { event_type: 'delivered', count: '9500' },
          { event_type: 'opened', count: '3000' },
          { event_type: 'clicked', count: '800' },
        ],
      });

      const result = await engine.getFunnelAnalysis(baseQuery());
      expect(result.stages.length).toBe(5);
      const firstStage = result.stages[0];
      expect(firstStage).toBeDefined();
      expect(firstStage?.stage).toBe('queued');
      expect(firstStage?.count).toBe(10000);
      // Dropoff from delivered→opened should be significant
      const openedStage = result.stages.find(s => s.stage === 'opened');
      expect(openedStage).toBeDefined();
      expect(openedStage?.dropoff).toBeGreaterThan(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. getRealtimeStats from Redis pipeline
  // ═══════════════════════════════════════════════════════════════════════════

  describe('getRealtimeStats', () => {
    it('returns today and thisHour stats from Redis', async () => {
      const result = await engine.getRealtimeStats('tenant-001');
      expect(result).toHaveProperty('today');
      expect(result).toHaveProperty('thisHour');
      expect(mockRedis.pipeline).toHaveBeenCalled();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. close() without DuckDB initialized
  // ═══════════════════════════════════════════════════════════════════════════

  describe('close', () => {
    it('closes without error when DuckDB was never initialized', async () => {
      await engine.close();
    });
  });
});
