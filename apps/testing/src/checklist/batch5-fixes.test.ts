/**
 * Batch 5 — Runtime Performance (#61–80)
 *
 * Targeted tests verifying each code change in this batch.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '../../../../');

function readSrc(relPath: string): string {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf-8');
}

describe('Batch 5 — Runtime Performance (#61–80)', () => {
  // #61: Suppression cache insertion-order eviction instead of sorting
  it('#61 — suppression cache uses insertion-order eviction (no sort)', () => {
    const src = readSrc('apps/worker/src/processors/email.ts');
    // Should NOT have the old sort-based eviction
    expect(src).not.toMatch(/\.sort\(\(a, b\) => a\[1\]\.expiresAt/);
    // Should iterate keys in insertion order
    expect(src).toContain('for (const key of this.suppressionCache.keys())');
  });

  // #62: Pre-computed pixel headers
  it('#62 — tracking pixel headers are pre-computed at module level', () => {
    const src = readSrc('apps/tracking/src/routes.ts');
    // Should have a pre-computed PIXEL_HEADERS constant
    expect(src).toMatch(/const PIXEL_HEADERS[:\s]/);
    // Should use PIXEL_HEADERS in the response
    expect(src).toContain('PIXEL_HEADERS');
    // The constant should have Content-Type
    expect(src).toMatch(/PIXEL_HEADERS[\s\S]*?'Content-Type':\s*'image\/gif'/);
  });

  // #63: Single combined bot detection regex
  it('#63 — bot detection uses single combined regex instead of 18 patterns', () => {
    const src = readSrc('apps/tracking/src/routes.ts');
    // Should NOT have an array of patterns
    expect(src).not.toContain('BOT_UA_PATTERNS: RegExp[]');
    expect(src).not.toContain('.some(pattern => pattern.test');
    // Should have a single combined regex
    expect(src).toMatch(/BOT_UA_PATTERN\s*=\s*\//);
    // The regex should include multiple patterns with alternation
    expect(src).toMatch(/GoogleImageProxy\|YahooMailProxy/);
  });

  // #64: Consolidated Redis pipeline in recordClick
  it('#64 — recordClick uses single pipeline instead of sequential awaits', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    // The recordClick section should use a pipeline with rpush + incr + set
    const clickSection = src.split('recordClick')[1]?.split('recordUnsubscribe')[0] ?? '';
    // Should have pipeline.rpush, pipeline.incr, pipeline.set in one pipeline
    expect(clickSection).toContain('pipeline.rpush');
    expect(clickSection).toContain('pipeline.incr');
    expect(clickSection).toContain('pipeline.set');
    // Should NOT have sequential await this.enqueueEvent followed by await this.incrementCounter
    expect(clickSection).not.toContain('await this.enqueueEvent(event)');
    expect(clickSection).not.toMatch(/await this\.incrementCounter\(data\.tenantId, 'clicks'\)/);
  });

  // #65: Single serialization (no double JSON.stringify)
  it('#65 — envelope uses string concat instead of double JSON.stringify', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    // The enqueueEvent method should use string concatenation for envelope
    const enqueueSection = src.split('enqueueEvent')[1]?.split('private async flush')[0] ?? '';
    expect(enqueueSection).toContain('`{"v":${EventProcessor.WAL_VERSION}');
    // Should NOT have the old nested JSON.stringify pattern in enqueueEvent
    expect(enqueueSection).not.toMatch(/JSON\.stringify\(\{\s*v:\s*EventProcessor\.WAL_VERSION[\s\S]*?d:\s*event/);
  });

  // #66: WAL checksum verification without re-serialization
  it('#66 — flush checksum verification extracts raw payload from string', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    // Should extract the raw payload substring from the envelope
    expect(src).toContain("raw.indexOf(',\"d\":')");
    // Should use rawPayload for checksum verification
    expect(src).toContain('sha256(rawPayload)');
  });

  // #67: CORS removed from pixel path
  it('#67 — CORS middleware removed from pixel path', () => {
    const src = readSrc('apps/tracking/src/routes.ts');
    // Should NOT have cors middleware on pixel path
    expect(src).not.toMatch(/cors\(\{[\s\S]*?origin:\s*'\*'/);
    // Should NOT import cors
    expect(src).not.toContain("import { cors }");
    // Should have a comment explaining removal
    expect(src).toContain('FIX-067');
  });

  // #68: Lua script uses defineCommand (EVALSHA) instead of raw eval
  it('#68 — Lua script registered via defineCommand for EVALSHA', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    // Should have defineCommand call
    expect(src).toContain("defineCommand('atomicDrain'");
    // Should use atomicDrain instead of redis.eval
    expect(src).toContain('.atomicDrain(');
    // Should NOT have the old redis.eval call for the drain script
    expect(src).not.toMatch(/this\.redis\.eval\(\s*EventProcessor\.ATOMIC_DRAIN/);
  });

  // #69: Reuse Date in recordOpen
  it('#69 — recordOpen reuses single Date object', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    const openSection = src.split('recordOpen')[1]?.split('async recordClick')[0] ?? '';
    // Should have a reused now variable
    expect(openSection).toContain('const now = new Date()');
    expect(openSection).toContain('now.toISOString()');
    expect(openSection).toContain('now.getUTCHours()');
    // Should NOT have multiple new Date() calls for date/hour
    const dateInstances = openSection.match(/new Date\(\)/g);
    // Should only have the event timestamp and the reused now
    expect(dateInstances?.length ?? 0).toBeLessThanOrEqual(2);
  });

  // #70: Reuse Date in incrementCounter
  it('#70 — incrementCounter reuses single Date object', () => {
    const src = readSrc('apps/tracking/src/processor.ts');
    // Find the incrementCounter method definition
    const match = src.match(/private async incrementCounter\([\s\S]*?(?=\n  private |\n  \/\/ @ts-expect)/);
    const counterSection = match?.[0] ?? '';
    expect(counterSection).toContain('const now = new Date()');
    expect(counterSection).toContain('now.toISOString()');
    expect(counterSection).toContain('now.getUTCHours()');
  });

  // #71: Metrics endpoint uses Redis pipeline
  it('#71 — metrics endpoint uses Redis pipeline instead of sequential gets', () => {
    const src = readSrc('apps/tracking/src/index.ts');
    const metricsSection = src.split("'/metrics'")[1]?.split('return c.text')[0] ?? '';
    // Should use pipeline
    expect(metricsSection).toContain('pipeline');
    // Should NOT have sequential await redis.get calls
    expect(metricsSection).not.toContain('await redis.get(');
    expect(metricsSection).not.toContain('await redis.llen(');
  });

  // #72: Fire-and-forget audit log writes
  it('#72 — suppression audit log writes are fire-and-forget', () => {
    const src = readSrc('apps/api/src/routes/suppressions.ts');
    // Should NOT await audit log writes for single suppression
    expect(src).toMatch(/auditRepo\.create\(\{[\s\S]*?action: 'suppression\.created'[\s\S]*?\}\)\.catch/);
    // Should NOT await audit log writes for bulk
    expect(src).toMatch(/auditRepo\.create\(\{[\s\S]*?action: 'suppression\.bulk_created'[\s\S]*?\}\)\.catch/);
  });

  // #73: Parallel domain lookups in batch
  it('#73 — batch send uses Promise.all for domain lookups', () => {
    const src = readSrc('apps/api/src/routes/messages.ts');
    // Should use Promise.all for domain lookups
    expect(src).toMatch(/Promise\.all\(\s*uniqueDomains\.map/);
    // Should NOT have sequential for loop with await
    expect(src).not.toMatch(/for \(const domain of uniqueDomains\)\s*\{\s*domainCache\.set\(domain, await/);
  });

  // #74: Parallel domain + suppression check in single send
  it('#74 — single send uses Promise.all for domain + suppression check', () => {
    const src = readSrc('apps/api/src/routes/messages.ts');
    // Should have Promise.all with both domain and suppression
    expect(src).toMatch(/Promise\.all\(\[[\s\S]*?findByDomain[\s\S]*?checkBulkSuppression[\s\S]*?\]\)/);
  });

  // #75: Parallel message + events queries
  it('#75 — message detail uses Promise.all for message + events', () => {
    const src = readSrc('apps/api/src/routes/messages.ts');
    // Should have Promise.all with findById and findByMessageId
    expect(src).toMatch(/Promise\.all\(\[[\s\S]*?findById[\s\S]*?findByMessageId[\s\S]*?\]\)/);
  });

  // #76: Parallel domain verify + audit log
  it('#76 — domain verify uses Promise.all for verify + audit', () => {
    const src = readSrc('apps/api/src/routes/domains.ts');
    // Should have Promise.all after verification
    expect(src).toMatch(/Promise\.all\(\[[\s\S]*?domainsRepo\.verify[\s\S]*?auditRepo\.create[\s\S]*?\]\)/);
  });

  // #77: Parallel preference queries in tracking
  it('#77 — preferences page uses Promise.all for 3 DB queries', () => {
    const src = readSrc('apps/tracking/src/routes.ts');
    // Should have Promise.all with preferences, categories, and suppression
    expect(src).toMatch(/Promise\.all\(\[[\s\S]*?subscription_preferences[\s\S]*?email_categories[\s\S]*?suppressions[\s\S]*?\]\)/);
  });

  // #78: Parallel readiness probe
  it('#78 — readiness probe uses Promise.all for DB + Redis', () => {
    const src = readSrc('apps/tracking/src/routes.ts');
    // Should have Promise.all with db.query and redis.ping
    expect(src).toMatch(/Promise\.all\(\[db\.query\('SELECT 1'\),\s*redis\.ping\(\)\]\)/);
  });

  // #79: Warmup day cache with TTL
  it('#79 — warmup day calculation is cached with 1h TTL', () => {
    const src = readSrc('apps/worker/src/processors/email.ts');
    // Should have a warmupDayCache Map
    expect(src).toContain('warmupDayCache');
    expect(src).toContain('WARMUP_DAY_CACHE_TTL_MS');
    // Should check cache before querying DB
    const calcSection = src.split('calculateWarmupDay')[2] ?? '';
    expect(calcSection).toContain('warmupDayCache.get(');
    expect(calcSection).toContain('warmupDayCache.set(');
  });

  // #80: Batch completions — multi-row DB operations in single transaction
  it('#80 — batch completions flush pending successes in single transaction', () => {
    const src = readSrc('apps/worker/src/processors/email.ts');
    // Should have flushPendingSuccesses method
    expect(src).toContain('flushPendingSuccesses');
    // Should have pendingSuccesses array
    expect(src).toContain('pendingSuccesses');
    // Should use unnest for multi-row UPDATE
    expect(src).toContain('unnest($1::text[])');
    // Should batch DELETE from queue
    expect(src).toContain('DELETE FROM email_queue WHERE id = ANY($1::text[])');
    // Should have fallback to individual completion
    expect(src).toContain('handleSuccessIndividual');
    // Should be called after Promise.allSettled
    expect(src).toContain('flushPendingSuccesses()');
  });
});
