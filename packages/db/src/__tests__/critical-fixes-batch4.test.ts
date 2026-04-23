import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

vi.mock('@apexmail/lib', () => ({
  Result: {
    ok: <T>(value: T) => ({ ok: true, value }),
    err: (error: unknown) => ({ ok: false, error: error instanceof Error ? error : new Error(String(error)) }),
  },
  createLogger: () => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
  parseJsonOrDefault: <T>(raw: unknown, fallback: T): T => {
    if (raw === null || raw === undefined) {
      return fallback;
    }
    if (typeof raw !== 'string') {
      return raw as T;
    }
    try {
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  },
}));

const withTransactionMock = vi.fn(async (db: { __txClient?: unknown }, fn: (ctx: { client: unknown }) => Promise<unknown>) => {
  const client = db.__txClient;
  if (!client) {
    throw new Error('Test setup missing tx client');
  }
  try {
    const value = await fn({ client });
    return { ok: true, value };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
});

vi.mock('../transaction.js', () => ({
  withTransaction: withTransactionMock,
}));

const { TenantsRepository } = await import('../repositories/tenants.js');
const { MessagesRepository } = await import('../repositories/messages.js');

describe('Fix 16: tenant suspend verifies row count', () => {
  it('returns an error when suspend target tenant does not exist', async () => {
    const txClient = {
      query: vi.fn(async () => ({ rowCount: 0 })),
    };

    const repo = new TenantsRepository({ __txClient: txClient } as never);
    const result = await repo.suspend('tenant_missing', 'abuse');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.message.toLowerCase()).toContain('tenant');
      expect(result.error.message.toLowerCase()).toContain('not found');
    }
  });
});

describe('Fix 17: db pool default config avoids DEFAULT_CONFIG non-null assertions', () => {
  it('does not use non-null assertion on DEFAULT_CONFIG values', () => {
    const source = readFileSync(resolve(__dirname, '../pool.ts'), 'utf-8');
    expect(source).not.toMatch(/DEFAULT_CONFIG\.[a-zA-Z_][a-zA-Z0-9_]*!/);
  });
});

describe('Fix 20: message stats uses canonical date option names', () => {
  it('rejects deprecated since/until options to avoid dual-API ambiguity', async () => {
    const db = {
      query: vi.fn().mockResolvedValue({
        ok: true,
        value: { rows: [], rowCount: 0 },
      }),
    };

    const repo = new MessagesRepository(db as never);
    const result = await repo.getStats('tenant_1', {
      since: new Date('2026-01-01T00:00:00.000Z'),
    });

    expect(result.ok).toBe(false);
    expect(db.query).not.toHaveBeenCalled();
  });
});
