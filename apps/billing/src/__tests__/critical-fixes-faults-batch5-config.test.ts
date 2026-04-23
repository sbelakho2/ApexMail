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

describe('Fix 23: billing company phone fallback is not a fake production-looking number', () => {
  it('does not default to +37200000000 when no phone is configured', async () => {
    applyRequiredBillingEnv();
    delete process.env.BILLING_COMPANY_PHONE;

    const { loadConfig, config } = await import('../config.js');
    loadConfig();

    expect(config.billingCompanyPhone).not.toBe('+37200000000');
  });
});
