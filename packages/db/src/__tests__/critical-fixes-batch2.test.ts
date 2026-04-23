import { describe, expect, it, vi, beforeEach } from 'vitest';

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
}));

vi.mock('@apexmail/lib/id', () => ({
  generateUuid: () => 'uuid_new',
  generateApiKey: () => ({ key: 'am_newprefix_secret', prefix: 'newprefix' }),
  parseApiKey: () => ({ valid: true, prefix: 'testprefix', legacyPrefix: null }),
}));

const withTransactionMock = vi.fn(async (db: { __txClient?: unknown }, fn: (ctx: { client: unknown }) => Promise<unknown>) => {
  const client = db.__txClient;
  if (!client) {
    throw new Error('Test setup missing tx client');
  }
  const value = await fn({ client });
  return { ok: true, value };
});

vi.mock('../transaction.js', () => ({
  withTransaction: withTransactionMock,
}));

const { ApiKeysRepository } = await import('../repositories/api-keys.js');
const { MessagesRepository } = await import('../repositories/messages.js');

function buildMessageRow(status: 'queued' | 'sending' | 'deferred' = 'queued') {
  const now = new Date('2026-01-01T00:00:00.000Z');
  return {
    id: 'msg_1',
    tenant_id: 'ten_1',
    user_id: 'usr_1',
    idempotency_key: null,
    message_id: '<msg_1@apexmail.test>',
    status,
    from_email: 'sender@example.com',
    from_name: null,
    reply_to: null,
    recipients: '[{"email":"recipient@example.com"}]',
    subject: 'Subject',
    html_body: null,
    text_body: 'Body',
    headers: '{}',
    attachments: '[]',
    template_id: null,
    template_data: null,
    campaign_id: null,
    tags: [],
    priority: 'normal',
    scheduled_at: null,
    sent_at: null,
    delivered_at: null,
    bounced_at: null,
    bounce_type: null,
    bounce_reason: null,
    mta_message_id: null,
    ip_address: null,
    sending_domain: 'example.com',
    attempts: 1,
    max_attempts: 5,
    last_attempt_at: null,
    next_attempt_at: null,
    metadata: '{}',
    created_at: now,
    updated_at: now,
  };
}

beforeEach(() => {
  withTransactionMock.mockClear();
  hashPasswordMock.mockClear();
  verifyPasswordMock.mockClear();
});

describe('Fix 6: API key rotate uses withTransaction helper', () => {
  it('routes rotation through withTransaction instead of manual BEGIN/COMMIT handling', async () => {
    const now = new Date('2026-01-01T00:00:00.000Z');

    const existingRow = {
      id: 'key_old',
      tenant_id: 'ten_1',
      user_id: 'usr_1',
      name: 'Old key',
      prefix: 'testprefix',
      key_hash: 'hash_old',
      scopes: ['messages:read'],
      rate_limit: 100,
      allowed_ips: ['203.0.113.10'],
      allowed_domains: ['api.example.com'],
      expires_at: null,
      last_used_at: null,
      last_used_ip: null,
      usage_count: 0,
      is_active: true,
      metadata: '{}',
      created_at: now,
      updated_at: now,
    };

    const createdRow = {
      ...existingRow,
      id: 'key_new',
      prefix: 'newprefix',
      key_hash: 'hash_new',
      metadata: '{"rotatedFromKeyId":"key_old"}',
      updated_at: new Date('2026-01-01T00:01:00.000Z'),
    };

    const txQuery = vi.fn(async (text: string) => {
      if (text.includes('SELECT * FROM api_keys WHERE id = $1 AND tenant_id = $2')) {
        return { rows: [existingRow], rowCount: 1 };
      }
      if (text.includes('INSERT INTO api_keys')) {
        return { rows: [createdRow], rowCount: 1 };
      }
      if (text.includes("UPDATE api_keys SET is_active = false")) {
        return { rows: [{ id: 'key_old' }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    });

    const client = {
      query: txQuery,
      release: vi.fn(),
    };

    const db = {
      __txClient: client,
      getClient: vi.fn(async () => client),
    };

    const repo = new ApiKeysRepository(db as never);
    const result = await repo.rotate('key_old', 'ten_1');

    expect(result.ok).toBe(true);
    expect(withTransactionMock).toHaveBeenCalledTimes(1);
    expect(db.getClient).not.toHaveBeenCalled();
  });
});

describe('Fix 7: updateLastUsed interval is parameterized', () => {
  it('avoids interpolated INTERVAL literals in SQL', async () => {
    const query = vi.fn().mockResolvedValue({ ok: true, value: { rows: [], rowCount: 1 } });
    const repo = new ApiKeysRepository({ query } as never);

    await (repo as { updateLastUsed: (id: string, ip?: string) => Promise<void> }).updateLastUsed('key_1', '198.51.100.7');

    expect(query).toHaveBeenCalledTimes(1);
    const sql = String(query.mock.calls[0]?.[0] ?? '');
    const params = query.mock.calls[0]?.[1] as unknown[];

    expect(sql).not.toMatch(/INTERVAL '\d+ seconds'/);
    expect(sql).toMatch(/INTERVAL '1 second'/i);
    expect(params?.[2]).toBe(300);
  });
});

describe('Fix 10: message state-machine guard rails for bulk updates', () => {
  it('markDeferred constrains transition to sending -> deferred only', async () => {
    const query = vi.fn().mockResolvedValue({
      ok: true,
      value: { rowCount: 1, rows: [buildMessageRow('deferred')] },
    });

    const repo = new MessagesRepository({ query } as never);
    await repo.markDeferred('msg_1', 'temporary', new Date('2026-01-01T00:30:00.000Z'));

    const sql = String(query.mock.calls[0]?.[0] ?? '');
    expect(sql).toMatch(/status\s*=\s*'sending'/i);
  });

  it('claimForSending keeps status transition guard in both selector and updater', async () => {
    const query = vi.fn().mockResolvedValue({
      ok: true,
      value: { rowCount: 1, rows: [buildMessageRow('sending')] },
    });

    const repo = new MessagesRepository({ query } as never);
    await repo.claimForSending(5, '198.51.100.8');

    const sql = String(query.mock.calls[0]?.[0] ?? '');
    const matches = sql.match(/status\s+IN\s*\('queued', 'deferred'\)/gi) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });
});
