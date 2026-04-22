import { describe, expect, it, vi } from 'vitest';

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

const verifyPasswordMock = vi.fn(async () => true);
const hashPasswordMock = vi.fn(async () => 'hash');

vi.mock('@apexmail/lib/crypto', () => ({
  verifyPassword: verifyPasswordMock,
  hashPassword: hashPasswordMock,
  sha256: () => 'hash',
}));

vi.mock('@apexmail/lib/id', () => ({
  generateUserId: () => 'usr_test',
  generateUuid: () => 'uuid_test',
  generateApiKey: () => ({ key: 'am_testprefix_secret', prefix: 'testprefix' }),
  parseApiKey: (key: string) => {
    if (!key.startsWith('am_')) {
      return { valid: false };
    }
    return { valid: true, prefix: 'testprefix', legacyPrefix: null };
  },
}));

const { withTransaction } = await import('../transaction.js');
const { UsersRepository } = await import('../repositories/users.js');
const { ApiKeysRepository } = await import('../repositories/api-keys.js');
const { calculateSchemaFingerprint } = await import('../fingerprint.js');

describe('Fix 1: withTransaction uses tracked getClient()', () => {
  it('acquires clients through db.getClient instead of pool.connect', async () => {
    const client = {
      query: vi.fn(async () => ({ rows: [], rowCount: 0 })),
      release: vi.fn(),
    };
    const poolConnect = vi.fn(async () => client);

    const db = {
      getClient: vi.fn(async () => client),
      getPool: vi.fn(() => ({ connect: poolConnect })),
    };

    const result = await withTransaction(
      db as never,
      async ({ client: txClient }: { client: typeof client }) => {
        await txClient.query('SELECT 1');
        return 'ok';
      },
      { retries: 0, timeout: 1000 },
    );

    expect(result.ok).toBe(true);
    expect(db.getClient).toHaveBeenCalledTimes(1);
    expect(poolConnect).not.toHaveBeenCalled();
  });
});

describe('Fix 2: verifyCredentials selects metadata', () => {
  it('includes metadata in credential lookup SQL', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        value: {
          rowCount: 1,
          rows: [
            {
              id: 'usr_1',
              tenant_id: 'ten_1',
              email: 'user@example.com',
              name: 'User',
              password_hash: 'hash',
              role: 'member',
              status: 'active',
              email_verified: true,
              last_login_at: null,
              mfa_enabled: false,
              metadata: '{"preferences":{"theme":"dark"}}',
              created_at: new Date('2026-01-01T00:00:00.000Z'),
              updated_at: new Date('2026-01-01T00:00:00.000Z'),
            },
          ],
        },
      })
      .mockResolvedValueOnce({ ok: true, value: { rowCount: 1, rows: [] } });

    const repo = new UsersRepository({ query } as never);
    const result = await repo.verifyCredentials('user@example.com', 'password', 'ten_1');

    expect(result.ok).toBe(true);
    const sql = String(query.mock.calls[0]?.[0] ?? '');
    expect(sql).toMatch(/\bmetadata\b/i);
  });
});

describe('Fix 4: API key verify query includes IP/domain restriction fields', () => {
  it('selects allowed_ips and allowed_domains in verify()', async () => {
    verifyPasswordMock.mockResolvedValueOnce(false);

    const query = vi.fn().mockResolvedValue({
      ok: true,
      value: {
        rowCount: 1,
        rows: [
          {
            id: 'key_1',
            tenant_id: 'ten_1',
            user_id: 'usr_1',
            name: 'Key 1',
            prefix: 'testprefix',
            key_hash: 'hash',
            scopes: ['messages:read'],
            rate_limit: 60,
            allowed_ips: ['203.0.113.10'],
            allowed_domains: ['api.example.com'],
            expires_at: null,
            last_used_at: null,
            last_used_ip: null,
            usage_count: 0,
            is_active: true,
            metadata: '{}',
            created_at: new Date('2026-01-01T00:00:00.000Z'),
            updated_at: new Date('2026-01-01T00:00:00.000Z'),
          },
        ],
      },
    });

    const repo = new ApiKeysRepository({ query } as never);
    const result = await repo.verify('am_testprefix_secret', '198.51.100.4');

    expect(result.ok).toBe(true);
    const sql = String(query.mock.calls[0]?.[0] ?? '');
    expect(sql).toMatch(/\ballowed_ips\b/i);
    expect(sql).toMatch(/\ballowed_domains\b/i);
  });
});

describe('Fix 5: schema fingerprint query timeout is applied with a transaction-local setting', () => {
  it('uses an acquired client and local statement_timeout, not unsupported query options', async () => {
    const client = {
      query: vi.fn(async (text: string) => {
        if (text.includes('schema_migrations')) {
          return { rows: [] };
        }
        return { rows: [] };
      }),
      release: vi.fn(),
    };

    const pool = {
      connect: vi.fn(async () => client),
      query: vi.fn(async () => ({ rows: [] })),
    };

    const db = {
      getPool: () => pool,
    };

    const result = await calculateSchemaFingerprint(db as never);

    expect(result.ok).toBe(true);
    expect(pool.connect).toHaveBeenCalledTimes(1);
    const allQueries = client.query.mock.calls.map((call) => String(call[0]));
    expect(allQueries.some((text) => text.includes('SET LOCAL statement_timeout'))).toBe(true);
  });
});
