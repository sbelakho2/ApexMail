import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@apexmail/lib', () => {
  return {
    Result: {
      ok(value: unknown) {
        return { ok: true, value };
      },
      err(error: Error) {
        return { ok: false, error };
      },
    },
  };
});

vi.mock('@apexmail/lib/logger', () => {
  return {
    createLogger() {
      return {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
      };
    },
  };
});

import { WalletService } from '../services/wallet.js';

describe('WalletService', () => {
  const redis = {
    setex: vi.fn(),
    del: vi.fn(),
  };

  beforeEach(() => {
    redis.setex.mockReset();
    redis.del.mockReset();
  });

  it('creates a wallet using the tenant billing currency when missing', async () => {
    const updatedAt = new Date('2026-01-01T00:00:00.000Z');
    const db = {
      query: vi
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          value: { rows: [] },
        })
        .mockResolvedValueOnce({
          ok: true,
          value: { rows: [{ billing_currency: 'eur' }] },
        })
        .mockResolvedValueOnce({
          ok: true,
          value: {
            rows: [
              {
                tenant_id: 'tenant_123',
                balance: 0,
                reserved: 0,
                currency: 'EUR',
                updated_at: updatedAt,
              },
            ],
          },
        }),
    };

    const service = new WalletService(db as never, redis as never);
    const result = await service.getBalance('tenant_123');

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.currency).toBe('EUR');
    expect(redis.setex).toHaveBeenCalledTimes(1);
  });

  it('returns insufficient balance when atomic debit affects no rows', async () => {
    const db = {
      query: vi.fn().mockResolvedValue({
        ok: true,
        value: { rows: [] },
      }),
    };

    const service = new WalletService(db as never, redis as never);
    const result = await service.debit('tenant_123', 500, 'Usage charge');

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.message).toContain('Insufficient balance');
    expect(redis.del).not.toHaveBeenCalled();
  });

  it('rejects non-positive credits before touching the database', async () => {
    const db = {
      query: vi.fn(),
    };

    const service = new WalletService(db as never, redis as never);
    const result = await service.credit('tenant_123', 0, 'Invalid top-up');

    expect(result.ok).toBe(false);
    expect(db.query).not.toHaveBeenCalled();
  });

  it('returns an error when capturing an unknown reservation', async () => {
    const db = {
      query: vi.fn().mockResolvedValue({
        ok: true,
        value: { rows: [] },
      }),
    };

    const service = new WalletService(db as never, redis as never);
    const result = await service.captureReservation('00000000-0000-0000-0000-000000000000');

    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }

    expect(result.error.message).toContain('Reservation already processed or invalid');
  });
});