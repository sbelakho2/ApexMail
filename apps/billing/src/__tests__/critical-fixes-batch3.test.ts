import { describe, expect, it } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 3 tests: Fixes 11-15 (Infrastructure, legal, security)
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

// ── Fix 11: Redis password escaping in prod docker-compose ───────────────────
describe('Fix 11: Redis password escaping in production', () => {
  const prodCompose = readFileSync(resolve(root, 'docker-compose.prod.yml'), 'utf-8');

  it('uses $$ escaping for REDIS_PASSWORD in prod', () => {
    expect(prodCompose).toContain('$$REDIS_PASSWORD');
    // Single $ without $$ must not appear in requirepass
    expect(prodCompose).not.toMatch(/requirepass.*[^$]\$REDIS_PASSWORD/);
  });
});

// ── Fix 12: Marketing Terms — correct registry code ─────────────────────────
describe('Fix 12: Terms of Service has correct registry code', () => {
  const terms = readFileSync(resolve(root, 'apps/marketing-zola/content/terms/index.md'), 'utf-8');

  it('does not contain placeholder registry code', () => {
    expect(terms).not.toContain('16XXXXXX');
  });

  it('contains correct registry code 16192499', () => {
    expect(terms).toContain('16192499');
  });

  it('uses correct legal entity name', () => {
    expect(terms).toContain('Bel Consulting OÜ');
  });
});

// ── Fix 13: Privacy policy legal entity matches config.toml ──────────────────
describe('Fix 13: Privacy policy correct legal entity', () => {
  const privacy = readFileSync(resolve(root, 'apps/marketing-zola/content/privacy/index.md'), 'utf-8');

  it('does not use "ApexMail OÜ" as entity name', () => {
    expect(privacy).not.toMatch(/ApexMail OÜ/);
  });

  it('uses "Bel Consulting OÜ" as entity name', () => {
    expect(privacy).toContain('Bel Consulting OÜ');
  });
});

// ── Fix 14: MTA NetworkPolicy restricts SMTP ingress ─────────────────────────
describe('Fix 14: MTA NetworkPolicy has from: selector', () => {
  const netpol = readFileSync(
    resolve(root, 'deploy/helm/apexmail/templates/networkpolicy.yaml'),
    'utf-8'
  );

  it('has from: selector on SMTP ingress', () => {
    // Extract the MTA section
    const mtaSection = netpol.match(/# SMTP ports[\s\S]*?---/);
    expect(mtaSection).not.toBeNull();
    expect(mtaSection![0]).toContain('from:');
    expect(mtaSection![0]).toContain('namespaceSelector');
  });
});

// ── Fix 15: dev-start.sh hardening ───────────────────────────────────────────
describe('Fix 15: dev-start.sh security improvements', () => {
  const devStart = readFileSync(resolve(root, 'tools/dev-start.sh'), 'utf-8');

  it('has set -u for unset variable detection', () => {
    expect(devStart).toMatch(/set -eu/);
  });

  it('uses umask before generating JWT keys', () => {
    expect(devStart).toContain('umask 077');
  });
});
