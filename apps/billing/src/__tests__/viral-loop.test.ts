import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@apexmail/lib', () => ({
  Result: {
    ok: <T>(value: T) => ({ ok: true, value }),
    err: <T extends Error>(error: T) => ({ ok: false, error }),
  },
}));

vi.mock('@apexmail/lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

import { ViralLoopService } from '../services/viral-loop.js';

function createRedisMock() {
  return {
    incr: vi.fn(),
    expire: vi.fn(),
    lpush: vi.fn(),
    ltrim: vi.fn(),
    rpoplpush: vi.fn(),
    lrem: vi.fn(),
    setex: vi.fn(),
  };
}

describe('ViralLoopService', () => {
  let redis: ReturnType<typeof createRedisMock>;

  beforeEach(() => {
    redis = createRedisMock();
  });

  it('queues impression counters when Redis increment fails', async () => {
    redis.incr.mockRejectedValueOnce(new Error('redis down'));
    redis.lpush.mockResolvedValueOnce(1);
    redis.ltrim.mockResolvedValueOnce(1);
    redis.expire.mockResolvedValue(1);

    const db = { query: vi.fn() } as never;
    const service = new ViralLoopService(db, redis as never, 'https://apexmail.ee', '0123456789abcdef');

    await service.recordImpression('tenant-1');

    expect(redis.lpush).toHaveBeenCalledTimes(1);
    const [, payload] = redis.lpush.mock.calls[0] ?? [];
    expect(typeof payload).toBe('string');
    expect(JSON.parse(payload as string)).toMatchObject({
      tenantId: 'tenant-1',
      metric: 'impressions',
      retries: 0,
    });
  });

  it('replays queued counters successfully', async () => {
    const queuedEvent = JSON.stringify({
      tenantId: 'tenant-1',
      metric: 'clicks',
      retries: 0,
      queuedAt: new Date().toISOString(),
    });

    redis.rpoplpush.mockResolvedValueOnce(queuedEvent).mockResolvedValueOnce(null);
    redis.incr.mockResolvedValue(1);
    redis.expire.mockResolvedValue(1);
    redis.lrem.mockResolvedValue(1);

    const db = { query: vi.fn() } as never;
    const service = new ViralLoopService(db, redis as never, 'https://apexmail.ee', '0123456789abcdef');

    const flushed = await service.flushPendingCounters(10);

    expect(flushed).toBe(1);
    expect(redis.lrem).toHaveBeenCalledWith('viral:processing:counters', 1, queuedEvent);

    const [key] = redis.incr.mock.calls[0] ?? [];
    expect(key).toMatch(/^viral:clicks:tenant-1:\d{4}-\d{2}$/);
  });
});