import { afterEach, describe, expect, it, vi } from 'vitest';

const ORIGINAL_ENV = { ...process.env };

function applyRequiredBillingEnv(): void {
  process.env.NODE_ENV = 'test';
  process.env.DATABASE_URL = 'http://localhost:5432';
  process.env.REDIS_URL = 'http://localhost:6379';
  process.env.STRIPE_SECRET_KEY = 'sk_test_123456789012345678901234';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_123456789012345678901234';
  process.env.SERVICE_AUTH_TOKEN = 'service-auth-token-1234567890123456';
}

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  vi.resetModules();
});

describe('Fix 12 and Fix 14: billing config fallback hardening', () => {
  it('uses schema-aligned default port (4100) when PORT is not numeric', async () => {
    applyRequiredBillingEnv();
    process.env.PORT = 'not-a-number';

    const { loadConfig, config } = await import('../config.js');
    loadConfig();

    expect(config.port).toBe(4100);
  });

  it('does not use the public hardcoded telemetry salt fallback', async () => {
    applyRequiredBillingEnv();
    delete process.env.VIRAL_TELEMETRY_HASH_SALT;

    const { loadConfig, config } = await import('../config.js');
    loadConfig();

    expect(config.viralTelemetryHashSalt).not.toBe('apexmail-telemetry');
  });
});
