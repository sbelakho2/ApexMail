import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(__dirname, '../../../..');

describe('Fix 26: billing route error handling formatting readability', () => {
  it('does not keep logger.error and return c.json compressed onto a single line', () => {
    const source = readFileSync(resolve(root, 'apps/billing/src/routes/billing.ts'), 'utf-8');
    const compressedPattern = /logger\.error\([^\n]*\);[ \t]*return[ \t]+c\.json/g;
    const matches = source.match(compressedPattern) ?? [];
    expect(matches.length).toBe(0);
  });
});

describe('Fix 27: mail-server src path includes intent documentation', () => {
  it('contains a README explaining why Rust implementation lives in crates/', () => {
    const readmePath = resolve(root, 'services/mail-server/src/README.md');
    expect(existsSync(readmePath)).toBe(true);

    const content = readFileSync(readmePath, 'utf-8');
    expect(content.toLowerCase()).toContain('rust');
    expect(content.toLowerCase()).toContain('crates');
  });
});
