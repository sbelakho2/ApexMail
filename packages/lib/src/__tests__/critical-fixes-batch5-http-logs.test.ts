import { describe, expect, it, vi } from 'vitest';

const requestMock = vi.fn(async () => {
  throw new Error('network failure');
});

const warnMock = vi.fn();

vi.mock('undici', () => ({
  request: requestMock,
}));

vi.mock('../logger/index.js', () => ({
  getLogger: () => ({
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: warnMock,
      error: vi.fn(),
    }),
  }),
}));

const { HttpClient } = await import('../http/index.js');

describe('Fix 22: HTTP error logs redact query strings', () => {
  it('logs sanitized URL without sensitive query parameters on request failure', async () => {
    const client = new HttpClient({ defaultTimeout: 10 });

    const result = await client.get('https://api.example.com/v1/resource?token=secret&apiKey=topsecret', {
      retries: 0,
    });

    expect(result.ok).toBe(false);
    expect(warnMock).toHaveBeenCalledTimes(1);

    const logData = warnMock.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(String(logData.url)).toBe('https://api.example.com/v1/resource');
    expect(String(logData.url)).not.toContain('?');
  });
});
