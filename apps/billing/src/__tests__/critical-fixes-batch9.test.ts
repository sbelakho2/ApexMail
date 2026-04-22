import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 9 tests: Fixes 46-55
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

describe('Fix 46: Node SDK enforces HTTPS for non-localhost', () => {
  const sdk = readFileSync(resolve(root, 'packages/sdk-node/src/index.ts'), 'utf-8');
  it('checks for http:// with non-localhost host', () => {
    expect(sdk).toContain('HTTPS is required for production API URLs');
  });
  it('allows HTTP for localhost', () => {
    expect(sdk).toContain("host !== 'localhost'");
  });
});

describe('Fix 47: SSH uses StrictHostKeyChecking=accept-new', () => {
  const upload = readFileSync(resolve(root, 'apps/ai/training/upload.sh'), 'utf-8');
  it('does not disable host key checking', () => {
    expect(upload).not.toContain('StrictHostKeyChecking=no');
  });
  it('uses accept-new for first-connect trust', () => {
    expect(upload).toContain('StrictHostKeyChecking=accept-new');
  });
});

describe('Fix 49: ESLint plugin v4 for ESLint 9', () => {
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf-8'));
  it('eslint-plugin-unused-imports is v4+', () => {
    const version = pkg.devDependencies['eslint-plugin-unused-imports'];
    expect(version).toMatch(/^\^4\./);
  });
});

describe('Fix 50: SMTP sender defaults to require_starttls: true', () => {
  const sender = readFileSync(
    resolve(root, 'services/mail-server/crates/outbound-queue/src/smtp_sender.rs'),
    'utf-8'
  );
  it('require_starttls defaults to true', () => {
    expect(sender).toContain('require_starttls: true,');
  });
});

describe('Fix 51: Helm deployments have autoscaling guard', () => {
  const web = readFileSync(
    resolve(root, 'deploy/helm/apexmail/templates/web-deployment.yaml'),
    'utf-8'
  );
  const enterprise = readFileSync(
    resolve(root, 'deploy/helm/apexmail/templates/enterprise-deployment.yaml'),
    'utf-8'
  );
  it('web deployment has autoscaling guard', () => {
    expect(web).toContain('if not .Values.web.autoscaling.enabled');
  });
  it('enterprise deployment has autoscaling guard', () => {
    expect(enterprise).toContain('if not .Values.enterprise.autoscaling.enabled');
  });
});

describe('Fix 52: Helm ConfigMap supports separate tracking/web URLs', () => {
  const cm = readFileSync(
    resolve(root, 'deploy/helm/apexmail/templates/configmap.yaml'),
    'utf-8'
  );
  it('tracking-base-url can be configured independently', () => {
    expect(cm).toContain('.Values.tracking.baseUrl');
  });
  it('web-base-url can be configured independently', () => {
    expect(cm).toContain('.Values.web.baseUrl');
  });
});

describe('Fix 53: crypto-native timing_safe_equal handles length mismatch', () => {
  const crypto = readFileSync(
    resolve(root, 'packages/crypto-native/src/lib.rs'),
    'utf-8'
  );
  it('does not truncate length XOR to u8', () => {
    expect(crypto).not.toContain('(a.len() ^ b.len()) as u8');
  });
  it('explicitly checks length inequality', () => {
    expect(crypto).toContain('a.len() != b.len()');
  });
  it('returns false for length mismatch', () => {
    const fnBlock = crypto.match(/fn timing_safe_equal[\s\S]*?^}/m);
    expect(fnBlock).not.toBeNull();
    expect(fnBlock![0]).toContain('return false');
  });
});

describe('Fix 54: Marketing package.json uses pnpm', () => {
  const pkg = readFileSync(
    resolve(root, 'apps/marketing-zola/package.json'),
    'utf-8'
  );
  it('does not use bare npm run (only pnpm run)', () => {
    // Replace all pnpm occurrences, then check no npm remains
    const withoutPnpm = pkg.replace(/pnpm run/g, '');
    expect(withoutPnpm).not.toContain('npm run');
  });
  it('uses pnpm run', () => {
    expect(pkg).toContain('pnpm run');
  });
});

describe('Fix 55: README PostgreSQL version matches docker-compose', () => {
  const readme = readFileSync(resolve(root, 'README.md'), 'utf-8');
  it('says PostgreSQL 16+', () => {
    expect(readme).toContain('PostgreSQL 16+');
  });
});
