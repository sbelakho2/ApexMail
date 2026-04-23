import { describe, expect, it, vi } from 'vitest';

vi.mock('@apexmail/lib', () => ({
  Result: {
    ok: <T>(value: T) => ({ ok: true, value }),
    err: (error: unknown) => ({ ok: false, error: error instanceof Error ? error : new Error(String(error)) }),
  },
}));

vi.mock('@apexmail/lib/logger', () => ({
  getLogger: () => ({
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  }),
}));

const { withAdvisoryLock } = await import('../transaction.js');

describe('Fix 15: advisory lock bigint conversion stays in int32 domain', () => {
  it('converts large bigint lock keys into safe 32-bit signed parts', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [{ acquired: true }], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [{ unlocked: true }], rowCount: 1 });

    const client = {
      query,
      release: vi.fn(),
    };

    const db = {
      getPool: () => ({
        connect: vi.fn(async () => client),
      }),
    };

    const hugeLockKey = (BigInt(1) << BigInt(120)) + BigInt('0x12345678');

    const result = await withAdvisoryLock(db as never, hugeLockKey, async () => 'ok');

    expect(result.ok).toBe(true);

    const lockParams = query.mock.calls[0]?.[1] as number[];
    expect(lockParams).toHaveLength(2);

    for (const part of lockParams) {
      expect(Number.isSafeInteger(part)).toBe(true);
      expect(part).toBeGreaterThanOrEqual(-2147483648);
      expect(part).toBeLessThanOrEqual(2147483647);
    }
  });
});
