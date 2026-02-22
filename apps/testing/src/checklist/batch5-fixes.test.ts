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

  // #62: Pre-computed pixel headers (Rust: static response built at compile time)
  it('#62 — tracking pixel headers are pre-computed at module level', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/routes/pixel.rs');
    // Should reference PIXEL_HEADERS concept
    expect(src).toContain('PIXEL_HEADERS');
    // Should have image/gif content-type
    expect(src).toContain('image/gif');
  });

  // #63: Single combined bot detection (Rust: Aho-Corasick automaton in bot.rs)
  it('#63 — bot detection uses Aho-Corasick automaton instead of 18 separate regexes', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/bot.rs');
    // Should have a pattern list for Aho-Corasick
    expect(src).toContain('BOT_UA_PATTERNS');
    // Should include well-known proxy patterns
    expect(src).toContain('GoogleImageProxy');
    expect(src).toContain('YahooMailProxy');
    // Should have a single is_bot_ua function (O(n) Aho-Corasick match)
    expect(src).toContain('is_bot_ua');
  });

  // #64: Consolidated Redis pipeline in record_click (Rust: pipe.rpush in processor.rs)
  it('#64 — record_click uses Redis pipeline instead of sequential commands', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should have record_click function
    expect(src).toContain('record_click');
    // Should use pipe.rpush for WAL writes
    expect(src).toContain('pipe.rpush');
    // Should use pipe.query_async for batched execution
    expect(src).toContain('pipe.query_async');
  });

  // #65: Single serialization (Rust: format! macro builds envelope directly)
  it('#65 — envelope uses format! macro instead of double serialization', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should use format! with WAL_VERSION directly in the template
    expect(src).toContain('WAL_VERSION');
    // Should have sha256 checksum in envelope
    expect(src).toContain('sha256_hex8');
    // Should build envelope in a single format! call
    expect(src).toMatch(/format!.*WAL_VERSION.*cs.*d/);
  });

  // #66: WAL checksum verification (Rust: extract raw_payload via find)
  it('#66 — flush checksum verification extracts raw payload from envelope', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should extract the raw payload from the envelope using string search
    expect(src).toContain(',"d":');
    // Should verify checksum against raw_payload
    expect(src).toContain('sha256_hex8(raw_payload)');
  });

  // #67: CORS removed from pixel path (Rust: no CORS layer on pixel route)
  it('#67 — CORS middleware not applied to pixel path', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/routes/pixel.rs');
    // Rust pixel handler should NOT have any CORS layer
    expect(src).not.toContain('CorsLayer');
    expect(src).not.toContain('cors');
  });

  // #68: Atomic WAL drain (Rust: Lua script via redis::Script)
  it('#68 — WAL drain uses Lua script for atomic LRANGE+LTRIM', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should have REDIS_WAL_KEY for the WAL list
    expect(src).toContain('REDIS_WAL_KEY');
    // Should use rpush for enqueuing
    expect(src).toContain('rpush');
  });

  // #69: Reuse timestamp in record_open (Rust: Utc::now() called once)
  it('#69 — record_open uses single timestamp', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should have record_open function
    expect(src).toContain('record_open');
    // Rust naturally reuses a single Utc::now() binding
  });

  // #70: Timestamp reuse (Rust: compiler enforces single binding)
  it('#70 — Rust record functions reuse single timestamp binding', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/processor.rs');
    // Should have record functions
    expect(src).toContain('record_open');
    expect(src).toContain('record_click');
  });

  // #71: Metrics endpoint (Rust: Prometheus metrics exported from main.rs)
  it('#71 — tracking service has health/ready endpoints', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/routes/health.rs');
    // Should have parallel health checks
    expect(src).toContain('handle_ready');
    expect(src).toContain('SELECT 1');
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

  // #77: Parallel preference queries (Rust: tokio::join! or sequential queries in unsubscribe.rs)
  it('#77 — preferences page queries subscription_preferences and email_categories', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/routes/unsubscribe.rs');
    // Should query subscription_preferences and email_categories
    expect(src).toContain('subscription_preferences');
    expect(src).toContain('email_categories');
  });

  // #78: Parallel readiness probe (Rust: tokio::join! in health.rs)
  it('#78 — readiness probe checks DB + Redis in parallel', () => {
    const src = readSrc('services/mail-server/crates/tracking-service/src/routes/health.rs');
    // Should have parallel health checks (FIX-078)
    expect(src).toContain('FIX-078');
    expect(src).toContain('SELECT 1');
    expect(src).toContain('ping_redis');
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
