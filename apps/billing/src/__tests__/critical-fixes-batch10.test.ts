import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

// ──────────────────────────────────────────────────────────────────────────────
// Batch 10 tests: Fixes 56-61
// ──────────────────────────────────────────────────────────────────────────────

const root = resolve(__dirname, '../../../..');

describe('Fix 56: Feature docs links point to external docs site', () => {
  const details = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/features/details.html'),
    'utf-8'
  );
  it('API docs link uses external URL', () => {
    expect(details).toContain('https://docs.apexmail.ee/api');
    expect(details).not.toMatch(/href="\/docs\/api"/);
  });
  it('Analytics docs link uses external URL', () => {
    expect(details).toContain('https://docs.apexmail.ee/analytics');
    expect(details).not.toMatch(/href="\/docs\/analytics"/);
  });
});

describe('Fix 57: Compliance CTA links to existing page', () => {
  const cta = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/compliance/cta.html'),
    'utf-8'
  );
  it('does not link to non-existent /contact/compliance', () => {
    expect(cta).not.toContain('/contact/compliance');
  });
  it('links to /compliance', () => {
    expect(cta).toContain('href="/compliance"');
  });
});

describe('Fix 58: DPA sub-processors link is valid', () => {
  const dpa = readFileSync(
    resolve(root, 'apps/marketing-zola/content/dpa/index.md'),
    'utf-8'
  );
  it('does not link to non-existent /sub-processors', () => {
    expect(dpa).not.toMatch(/\(\/sub-processors\)/);
  });
  it('links to /compliance#sub-processors', () => {
    expect(dpa).toContain('/compliance#sub-processors');
  });
});

describe('Fix 59: Cookie consent has Reject option', () => {
  const consent = readFileSync(
    resolve(root, 'apps/marketing-zola/templates/partials/generated/cookie-consent-island.html'),
    'utf-8'
  );
  it('has a Necessary Only option', () => {
    expect(consent).toContain('Necessary Only');
  });
  it('has Accept All label', () => {
    expect(consent).toContain('Accept All');
  });
});

describe('Fix 60: listsError is displayed in campaign pages', () => {
  const newPage = readFileSync(
    resolve(root, 'apps/web/src/app/(dashboard)/campaigns/new/page.tsx'),
    'utf-8'
  );
  const editPage = readFileSync(
    resolve(root, 'apps/web/src/app/(dashboard)/campaigns/[id]/edit/page.tsx'),
    'utf-8'
  );
  it('new campaign page shows listsError message', () => {
    expect(newPage).toContain('listsError');
    expect(newPage).toContain('Failed to load audience lists');
  });
  it('edit campaign page shows listsError message', () => {
    expect(editPage).toContain('listsError');
    expect(editPage).toContain('Failed to load audience lists');
  });
});

describe('Fix 61: Turbo lint task has dependsOn', () => {
  const turbo = JSON.parse(readFileSync(resolve(root, 'turbo.json'), 'utf-8'));
  it('lint task depends on ^build', () => {
    expect(turbo.tasks?.lint?.dependsOn ?? turbo.pipeline?.lint?.dependsOn).toContain('^build');
  });
});
