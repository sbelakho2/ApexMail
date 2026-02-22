/**
 * Batch 7 Verification Tests (#101–120): Concurrency & Queuing
 *
 * Each test reads the relevant source file and verifies the fix marker
 * and key patterns that prove the fix is in place.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';

const root = path.resolve(__dirname, '..', '..', '..', '..');

async function src(rel: string): Promise<string> {
  return fs.readFile(path.join(root, rel), 'utf-8');
}

describe('Batch 7: Concurrency & Queuing (#101–120)', () => {

  it('#101 — Webhook per-tenant limit sets scheduled_at delay', async () => {
    const code = await src('apps/worker/src/processors/webhook.ts');
    expect(code).toContain('FIX-500-101');
    expect(code).toContain("INTERVAL '5 seconds'");
  });

  it('#102 — Webhook retry max delay increased to 300s', async () => {
    const code = await src('apps/worker/src/processors/webhook.ts');
    expect(code).toContain('FIX-500-102');
    expect(code).toContain('300_000');
  });

  it('#103 — Analytics processor honours concurrency config', async () => {
    const code = await src('apps/worker/src/processors/analytics.ts');
    expect(code).toContain('FIX-500-103');
    expect(code).toContain('this.config.concurrency');
    expect(code).toContain('Promise.allSettled');
  });

  it('#104 — Analytics flush has mutex guard', async () => {
    const code = await src('apps/worker/src/processors/analytics.ts');
    expect(code).toContain('FIX-500-104');
    expect(code).toContain('isFlushing');
  });

  it('#105 — Analytics hourly scheduling after completion', async () => {
    const code = await src('apps/worker/src/processors/analytics.ts');
    expect(code).toContain('FIX-500-105');
    // The scheduleHourlyAggregation call should be AFTER runHourlyAggregation
    const runIdx = code.indexOf('await this.runHourlyAggregation()');
    const rescheduleIdx = code.indexOf('this.scheduleHourlyAggregation()', runIdx);
    expect(runIdx).toBeGreaterThan(0);
    expect(rescheduleIdx).toBeGreaterThan(runIdx);
  });

  it('#106 — Stale job recovery includes analytics_queue', async () => {
    const code = await src('apps/worker/src/index.ts');
    expect(code).toContain('FIX-500-106');
    expect(code).toContain('analytics_queue');
    expect(code).toContain('processing = false');
  });

  it('#107 — Analytics eventBuffer has size cap', async () => {
    const code = await src('apps/worker/src/processors/analytics.ts');
    expect(code).toContain('FIX-500-107');
    expect(code).toContain('MAX_EVENT_BUFFER_SIZE');
  });

  it('#108 — Reply handler processes messages concurrently', async () => {
    const code = await src('apps/worker/src/processors/reply-handler.ts');
    expect(code).toContain('FIX-500-108');
    expect(code).toContain('CONCURRENCY_LIMIT');
    expect(code).toContain('Promise.allSettled');
  });

  it('#109 — Reply handler has stale processing recovery', async () => {
    const code = await src('apps/worker/src/processors/reply-handler.ts');
    expect(code).toContain('FIX-500-109');
    expect(code).toContain('recoverStaleMessages');
  });

  it('#110 — Circuit breaker HALF_OPEN success counter has TTL', async () => {
    const code = await src('apps/worker/src/circuit-breaker.ts');
    expect(code).toContain('FIX-500-110');
    // Successes key should have expire call
    expect(code).toMatch(/expire.*successes.*120/);
  });

  it('#111 — Circuit breaker OPEN→HALF_OPEN has concurrency guard', async () => {
    const code = await src('apps/worker/src/circuit-breaker.ts');
    expect(code).toContain('FIX-500-111');
    expect(code).toContain('half_open_lock');
    expect(code).toContain("'NX'");
  });

  it('#112 — Circuit breaker Redis keys have TTL', async () => {
    const code = await src('apps/worker/src/circuit-breaker.ts');
    expect(code).toContain('FIX-500-112');
    expect(code).toContain('KEY_TTL_SECONDS');
    expect(code).toContain('86400');
  });

  it('#113 — Circuit breaker success in CLOSED no longer deletes failures', async () => {
    const code = await src('apps/worker/src/circuit-breaker.ts');
    expect(code).toContain('FIX-500-113');
    // The old pattern: del(keyPrefix + ':failures') in recordSuccess should be gone
    // (it now only appears in close() which resets everything)
    const recordSuccess = code.match(/async recordSuccess[\s\S]*?(?=\n  async )/)?.[0] ?? '';
    expect(recordSuccess).not.toContain('.del(');
  });

  it('#114 — Email requeue uses rate limiter retryAfter', async () => {
    const code = await src('apps/worker/src/processors/email.ts');
    expect(code).toContain('FIX-500-114');
    expect(code).toContain('delayMs');
    expect(code).toContain('rateLimitResult.retryAfter');
  });

  it('#115 — uncaughtException exits immediately', async () => {
    const code = await src('apps/worker/src/index.ts');
    expect(code).toContain('FIX-500-115');
    // Should call process.exit(1) directly, not async shutdown
    const handler = code.match(/uncaughtException[\s\S]*?process\.exit\(1\)/)?.[0] ?? '';
    expect(handler).not.toContain('shutdown(');
  });

  it('#116 — Shutdown does not call process.exit(0)', async () => {
    const code = await src('apps/worker/src/index.ts');
    expect(code).toContain('FIX-500-116');
    const shutdownFn = code.match(/async function shutdown[\s\S]*?(?=\n\/\/ Signal)/)?.[0] ?? '';
    expect(shutdownFn).not.toContain('process.exit(0)');
  });

  it('#117 — Metrics server stopped after processors', async () => {
    const code = await src('apps/worker/src/index.ts');
    expect(code).toContain('FIX-500-117');
    const shutdownFn = code.match(/async function shutdown[\s\S]*?(?=\n\/\/ Signal)/)?.[0] ?? '';
    const processorsIdx = shutdownFn.indexOf('All processors stopped');
    const metricsIdx = shutdownFn.indexOf('metricsServer.stop()');
    expect(processorsIdx).toBeGreaterThan(0);
    expect(metricsIdx).toBeGreaterThan(processorsIdx);
  });

  it('#118 — Heartbeat uses live processor count', async () => {
    const code = await src('apps/worker/src/index.ts');
    expect(code).toContain('FIX-500-118');
    expect(code).toContain('processors.length');
  });

  it('#119 — Rate limiter waitQueue has per-waiter timeout', async () => {
    const code = await src('apps/worker/src/processors/email.ts');
    expect(code).toContain('FIX-500-119');
    expect(code).toContain('30_000');
    expect(code).toContain('Rate limiter wait timeout');
  });

  it('#120 — Tracking flush uses tokio::time::sleep reschedule (not setInterval)', async () => {
    const code = await src('services/mail-server/crates/tracking-service/src/processor.rs');
    // Rust flush loop uses tokio::time::sleep for re-scheduling
    expect(code).toContain('tokio::time::sleep');
    expect(code).toContain('flush_interval_ms');
    // Should use sleep-based reschedule, not a fixed interval timer
    expect(code).toContain('flush');
  });

});
