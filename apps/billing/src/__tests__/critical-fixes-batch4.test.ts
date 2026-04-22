import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 4 tests: Fixes 16-20
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

// ── Fix 16: DB migration uses tenants instead of organizations ───────────────
describe('Fix 16: DB migration schema matches code', () => {
  const schema = readFileSync(
    resolve(root, 'packages/db/src/migrations/001_initial_schema.sql'),
    'utf-8'
  );

  it('creates tenants table, not organizations', () => {
    expect(schema).toContain('CREATE TABLE IF NOT EXISTS tenants');
    expect(schema).not.toContain('CREATE TABLE IF NOT EXISTS organizations');
  });

  it('uses tenant_id foreign keys', () => {
    expect(schema).toContain('tenant_id');
    expect(schema).not.toContain('organization_id');
  });
});

// ── Fix 17: Webhook dead letter does not store raw payload ───────────────────
describe('Fix 17: No sensitive data in dead letter queue', () => {
  const webhooks = readFileSync(
    resolve(root, 'apps/billing/src/routes/webhooks.ts'),
    'utf-8'
  );

  it('does not store payloadPreview', () => {
    expect(webhooks).not.toContain('payloadPreview');
  });

  it('stores payloadLength instead', () => {
    expect(webhooks).toContain('payloadLength');
  });
});

// ── Fix 18: Internal API uses auth token ─────────────────────────────────────
describe('Fix 18: Internal API call uses proper auth', () => {
  const stripeInt = readFileSync(
    resolve(root, 'apps/billing/src/services/stripe-integration.ts'),
    'utf-8'
  );

  it('includes Authorization Bearer header', () => {
    expect(stripeInt).toMatch(/Authorization.*Bearer.*serviceAuthToken/);
  });
});

// ── Fix 19: Transaction type query param validated ───────────────────────────
describe('Fix 19: Billing type query param validation', () => {
  const billing = readFileSync(
    resolve(root, 'apps/billing/src/routes/billing.ts'),
    'utf-8'
  );

  it('does not use unsafe type assertion', () => {
    expect(billing).not.toMatch(/as\s*['"]credit['"].*['"]debit['"]/);
    expect(billing).not.toContain("as 'credit' | 'debit'");
  });

  it('validates type against allowed values', () => {
    expect(billing).toMatch(/rawType\s*===\s*'credit'\s*\|\|\s*rawType\s*===\s*'debit'/);
  });
});

// ── Fix 20: poll_instance.sh has timeout and proper error handling ───────────
describe('Fix 20: poll_instance.sh hardened', () => {
  const poll = readFileSync(resolve(root, 'tools/poll_instance.sh'), 'utf-8');

  it('no longer has hardcoded instance ID', () => {
    expect(poll).not.toContain('31553904');
  });

  it('uses environment variable for instance ID', () => {
    expect(poll).toContain('VAST_INSTANCE_ID');
  });

  it('has maximum attempts limit', () => {
    expect(poll).toContain('MAX_ATTEMPTS');
    expect(poll).toContain('exit 1');
  });

  it('has set -euo pipefail', () => {
    expect(poll).toContain('set -euo pipefail');
  });
});
