import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Fix 24: api-keys repository uses shared ApiKeyRow type', () => {
  it('does not repeat the full allowed_ips/allowed_domains row field block many times', () => {
    const source = readFileSync(resolve(__dirname, '../repositories/api-keys.ts'), 'utf-8');
    const allowedIpsOccurrences = (source.match(/allowed_ips:\s*string\[\]\s*\|\s*null;/g) ?? []).length;
    const allowedDomainsOccurrences = (source.match(/allowed_domains:\s*string\[\]\s*\|\s*null;/g) ?? []).length;

    expect(allowedIpsOccurrences).toBeLessThanOrEqual(2);
    expect(allowedDomainsOccurrences).toBeLessThanOrEqual(2);
  });
});

describe('Fix 25: message column lists derive from a canonical array', () => {
  it('defines message columns through a single list source rather than duplicated long strings', () => {
    const source = readFileSync(resolve(__dirname, '../repositories/messages.ts'), 'utf-8');
    expect(source).toContain('MESSAGE_COLUMN_LIST');
    expect(source).toContain('MESSAGE_COLUMNS = MESSAGE_COLUMN_LIST.join');
    expect(source).toContain('MESSAGE_COLUMNS_NO_BODY = MESSAGE_COLUMN_LIST');
  });
});
