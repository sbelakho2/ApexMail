import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 8 tests: Fixes 41-45
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

describe('Fix 41: Marketing CTA uses full signup URL', () => {
  const cta = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/pricing/cta.html'),
    'utf-8'
  );
  const plans = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/pricing/plans.html'),
    'utf-8'
  );
  it('CTA button uses full https URL', () => {
    expect(cta).toContain('https://app.apexmail.ee/signup');
    expect(cta).not.toMatch(/href="\/signup"/);
  });
  it('PAYG button uses full https URL', () => {
    expect(plans).toContain('https://app.apexmail.ee/signup?plan=payg');
    expect(plans).not.toMatch(/href="\/signup\?plan=payg"/);
  });
});

describe('Fix 42: Rate tracker cleanup is wired up', () => {
  const session = readFileSync(
    resolve(root, 'services/mail-server/crates/smtp-edge/src/session.rs'),
    'utf-8'
  );
  it('no #[allow(dead_code)] on rate tracker constants', () => {
    // Check area around MAX_RATE_TRACKER_ENTRIES and RATE_TRACKER_EVICTION_INTERVAL
    const maxLine = session.indexOf('MAX_RATE_TRACKER_ENTRIES');
    const preceding = session.slice(Math.max(0, maxLine - 50), maxLine);
    expect(preceding).not.toContain('#[allow(dead_code)]');
  });
  it('cleanup is auto-spawned via Once::call_once', () => {
    expect(session).toContain('CLEANUP_INIT.call_once(spawn_rate_tracker_cleanup)');
  });
  it('no #[allow(dead_code)] on spawn_rate_tracker_cleanup', () => {
    const fnLine = session.indexOf('pub fn spawn_rate_tracker_cleanup');
    const preceding = session.slice(Math.max(0, fnLine - 50), fnLine);
    expect(preceding).not.toContain('#[allow(dead_code)]');
  });
});

describe('Fix 43: CSP no unsafe-inline for scripts', () => {
  const headers = readFileSync(
    resolve(root, 'apps/marketing-zola/static/_headers'),
    'utf-8'
  );
  it('script-src does not contain unsafe-inline', () => {
    const cspLine = headers.split('\n').find(l => l.includes('Content-Security-Policy'));
    expect(cspLine).toBeDefined();
    const scriptSrc = cspLine!.match(/script-src\s+([^;]+)/);
    expect(scriptSrc).not.toBeNull();
    expect(scriptSrc![1]).not.toContain('unsafe-inline');
  });
});

describe('Fix 44: HotConfig update uses rcu for atomicity', () => {
  const hotConfig = readFileSync(
    resolve(root, 'services/mail-server/crates/mail-common/src/hot_config.rs'),
    'utf-8'
  );
  it('uses rcu instead of load+store', () => {
    expect(hotConfig).toContain('.rcu(');
  });
  it('update closure is Fn (not FnOnce) for retry safety', () => {
    expect(hotConfig).toMatch(/F:\s*Fn\(&T\)\s*->\s*T/);
  });
});

describe('Fix 45: generate_bigfix.py has shebang', () => {
  const bigfix = readFileSync(
    resolve(root, 'tools/generate_bigfix.py'),
    'utf-8'
  );
  it('starts with python3 shebang', () => {
    expect(bigfix.startsWith('#!/usr/bin/env python3')).toBe(true);
  });
});
