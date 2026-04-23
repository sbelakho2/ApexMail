import { describe, expect, it, vi } from 'vitest';

const requestMock = vi.fn(async () => ({
  statusCode: 200,
  headers: { 'content-type': 'application/json' },
  body: {
    text: async () => JSON.stringify({ ok: true }),
  },
}));

vi.mock('undici', () => ({
  request: requestMock,
}));

vi.mock('../logger/index.js', () => ({
  getLogger: () => ({
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  }),
}));

const { HttpClient } = await import('../http/index.js');

describe('Fix 11: HTTP client uses a single timeout mechanism', () => {
  it('does not pass undici headersTimeout/bodyTimeout when AbortController timeout is active', async () => {
    const client = new HttpClient({ defaultTimeout: 1234 });

    const result = await client.get<{ ok: boolean }>('https://example.com/test');

    expect(result.ok).toBe(true);
    expect(requestMock).toHaveBeenCalledTimes(1);

    const options = requestMock.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(options).not.toHaveProperty('headersTimeout');
    expect(options).not.toHaveProperty('bodyTimeout');
    expect(options).toHaveProperty('signal');
  });
});
