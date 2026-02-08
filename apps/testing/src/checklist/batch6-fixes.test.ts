/**
 * Batch 6 fixes verification tests (#81–100): Runtime Performance
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..', '..', '..', '..');

function readSource(relPath: string): string {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf-8');
}

describe('Batch 6: Runtime Performance (#81–100)', () => {

  // ── #81: Webhook batch completions ───────────────────────────────────
  it('#81 — Webhook processor uses batch completions instead of per-job PG client', () => {
    const src = readSource('apps/worker/src/processors/webhook.ts');
    expect(src).toContain('pendingSuccesses');
    expect(src).toContain('flushPendingSuccesses');
    expect(src).toContain('handleSuccessIndividual');
    expect(src).toContain('DELETE FROM webhook_queue WHERE id = ANY');
    expect(src).toContain('FIX-500-081');
  });

  // ── #82: DNS resolver reuse ──────────────────────────────────────────
  it('#82 — Webhook processor reuses a single DNS Resolver instance', () => {
    const src = readSource('apps/worker/src/processors/webhook.ts');
    expect(src).toContain('dnsResolver');
    expect(src).toContain('new dns.Resolver()');
    expect(src).toContain('this.dnsResolver.resolve4');
    expect(src).toContain('this.dnsResolver.resolve6');
    expect(src).toContain('FIX-500-082');
  });

  // ── #83: DNS cache ───────────────────────────────────────────────────
  it('#83 — Webhook processor caches DNS results with 60s TTL', () => {
    const src = readSource('apps/worker/src/processors/webhook.ts');
    expect(src).toContain('dnsCache');
    expect(src).toContain('DNS_CACHE_TTL_MS');
    expect(src).toContain('60_000');
    expect(src).toContain('expiresAt');
    expect(src).toContain('FIX-500-083');
  });

  // ── #84: Response body streaming ─────────────────────────────────────
  it('#84 — Webhook response body is streamed with byte limit', () => {
    const src = readSource('apps/worker/src/processors/webhook.ts');
    expect(src).toContain('MAX_RESPONSE_BYTES');
    expect(src).toContain('getReader');
    expect(src).toContain('reader.cancel');
    expect(src).toContain('FIX-500-084');
    // Should NOT contain response.text() for the response body
    expect(src).not.toMatch(/await\s+response\.text\(\)/);
  });

  // ── #85: AI tokenizer O(n×k) ────────────────────────────────────────
  it('#85 — AI tokenizer uses startsWith with offset instead of slice', () => {
    const src = readSource('apps/ai/src/inference/engine.ts');
    expect(src).toContain('text.startsWith(token, i)');
    expect(src).not.toContain('text.slice(i).startsWith');
    expect(src).toContain('FIX-500-085');
  });

  // ── #86: AI vector search bounded heap ───────────────────────────────
  it('#86 — AI vector search uses bounded min-heap for topK', () => {
    const src = readSource('apps/ai/src/inference/embeddings.ts');
    expect(src).toContain('heapMinScore');
    expect(src).toContain('pushHeap');
    expect(src).toContain('popHeap');
    expect(src).toContain('FIX-500-086');
    // Should NOT contain results.sort for the search method
  });

  // ── #87: AI exportStore NDJSON ───────────────────────────────────────
  it('#87 — AI embeddings service supports NDJSON export/import', () => {
    const src = readSource('apps/ai/src/inference/embeddings.ts');
    expect(src).toContain('exportStoreNDJSON');
    expect(src).toContain('importStoreNDJSON');
    expect(src).toContain('FIX-500-087');
  });

  // ── #88: AI LRU eviction O(1) ───────────────────────────────────────
  it('#88 — AI LRU eviction uses Map insertion order instead of O(n) scan', () => {
    const src = readSource('apps/ai/src/inference/embeddings.ts');
    expect(src).toContain('FIX-500-088');
    expect(src).toContain('accessOrder.keys().next()');
    // Delete+re-insert pattern for MRU
    expect(src).toContain('accessOrder.delete(id)');
  });

  // ── #89: AI Monte Carlo ──────────────────────────────────────────────
  it('#89 — AI Monte Carlo getProbabilityBest is async, reduced default, yields', () => {
    const src = readSource('apps/ai/src/bandits/thompson.ts');
    expect(src).toContain('async getProbabilityBest');
    expect(src).toContain('numSamples: number = 1000');
    expect(src).toContain('setImmediate');
    expect(src).toContain('YIELD_INTERVAL');
    expect(src).toContain('FIX-500-089');
    // hasSignificantWinner should be async too
    expect(src).toContain('async hasSignificantWinner');
  });

  // ── #90: Sales top-leads N+1 ────────────────────────────────────────
  it('#90 — Sales top-leads uses Map lookup instead of N+1 crm.getLead calls', () => {
    const src = readSource('apps/sales-autopilot/src/routes.ts');
    expect(src).toContain('leadById');
    expect(src).toContain('FIX-500-090');
    // Should NOT have Promise.all with crm.getLead per top lead
    expect(src).not.toMatch(/topLeads\.map\(async/);
  });

  // ── #91: Sales getReadyEnrollments ───────────────────────────────────
  it('#91 — Sales getReadyEnrollments avoids Array.from().filter()', () => {
    const src = readSource('apps/sales-autopilot/src/campaigns/drip-engine.ts');
    expect(src).toContain('FIX-500-091');
    // Should iterate directly, not Array.from(enrollments.values()).filter
    const fnMatch = src.match(/function getReadyEnrollments[\s\S]*?^}/m);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      expect(fnMatch[0]).not.toContain('Array.from');
    }
  });

  // ── #92: Sales enrichment cache ──────────────────────────────────────
  it('#92 — Sales enrichment caches results with 24h TTL', () => {
    const src = readSource('apps/sales-autopilot/src/enrichment/company.ts');
    expect(src).toContain('enrichmentCache');
    expect(src).toContain('ENRICHMENT_CACHE_TTL_MS');
    expect(src).toContain('24 * 60 * 60 * 1000');
    expect(src).toContain('FIX-500-092');
    expect(src).toContain('cache hit');
  });

  // ── #93: Observability multi-row log INSERT ──────────────────────────
  it('#93 — Observability logging uses multi-row INSERT', () => {
    const src = readSource('apps/observability/src/services/logging.ts');
    expect(src).toContain('FIX-500-093');
    expect(src).toContain('valueTuples');
    expect(src).toContain('COLS_PER_ROW');
    // Should not have per-row loop with individual INSERTs
    const flushMatch = src.match(/flushBuffer[\s\S]*?^  \}/m);
    expect(flushMatch).toBeTruthy();
  });

  // ── #94: Observability multi-row span INSERT ─────────────────────────
  it('#94 — Observability tracing uses multi-row INSERT for spans', () => {
    const src = readSource('apps/observability/src/services/tracing.ts');
    expect(src).toContain('FIX-500-094');
    expect(src).toContain('valueTuples');
    expect(src).toContain('COLS_PER_ROW');
  });

  // ── #95: Levenshtein two-row rolling ─────────────────────────────────
  it('#95 — Levenshtein distance uses two-row rolling array with early termination', () => {
    const src = readSource('packages/lib/src/validation/index.ts');
    expect(src).toContain('FIX-500-095');
    expect(src).toContain('MAX_THRESHOLD');
    expect(src).toContain('Swap rows');
    // Should NOT allocate full matrix
    expect(src).not.toContain('const matrix: number[][]');
  });

  // ── #96: formatDate Intl caching ─────────────────────────────────────
  it('#96 — Control plane caches Intl formatters at module level', () => {
    const src = readSource('apps/control-plane/src/lib/utils.ts');
    expect(src).toContain('FIX-500-096');
    expect(src).toContain('const dateFormatter = new Intl.DateTimeFormat');
    expect(src).toContain('const numberFormatter = new Intl.NumberFormat');
    expect(src).toContain('currencyFormatters');
    expect(src).toContain('getCurrencyFormatter');
  });

  // ── #97: API readiness pool check ────────────────────────────────────
  it('#97 — API readiness uses pool counters instead of pg_stat_activity', () => {
    const src = readSource('apps/api/src/routes/health.ts');
    expect(src).toContain('FIX-500-097');
    expect(src).toContain('totalCount');
    expect(src).toContain('waitingCount');
    expect(src).not.toContain('pg_stat_activity');
  });

  // ── #98: API webhook list SQL filters ────────────────────────────────
  it('#98 — API webhook list pushes filters to SQL via findByTenantFiltered', () => {
    const src = readSource('apps/api/src/routes/webhooks.ts');
    expect(src).toContain('FIX-500-098');
    expect(src).toContain('findByTenantFiltered');
    // Should NOT filter in JS after fetch
    expect(src).not.toMatch(/webhooks\s*=\s*webhooks\.filter/);

    // Repo should have the new method
    const repo = readSource('packages/db/src/repositories/webhooks.ts');
    expect(repo).toContain('findByTenantFiltered');
    expect(repo).toContain('FIX-500-098');
  });

  // ── #99: AI InferenceEngine singleton ────────────────────────────────
  it('#99 — AI services share InferenceEngine instances via getSharedEngine', () => {
    const idx = readSource('apps/ai/src/inference/index.ts');
    expect(idx).toContain('getSharedEngine');
    expect(idx).toContain('sharedEngines');
    expect(idx).toContain('FIX-500-099');

    const routes = readSource('apps/ai/src/routes.ts');
    expect(routes).toContain('getSharedEngine');
    expect(routes).not.toMatch(/const inference = new InferenceEngine\(\)/);

    const chatbot = readSource('apps/ai/src/chatbot/assistant.ts');
    expect(chatbot).toContain('getSharedEngine');

    const content = readSource('apps/ai/src/content/generator.ts');
    expect(content).toContain('getSharedEngine');
  });

  // ── #100: Sales pipeline secondary indexes ───────────────────────────
  it('#100 — Sales drip-engine uses secondary indexes for tenant/lead lookups', () => {
    const src = readSource('apps/sales-autopilot/src/campaigns/drip-engine.ts');
    expect(src).toContain('campaignsByTenant');
    expect(src).toContain('enrollmentsByLead');
    expect(src).toContain('FIX-500-100');

    // getTenantCampaigns should not use Array.from(...).filter
    const fnMatch = src.match(/function getTenantCampaigns[\s\S]*?^}/m);
    expect(fnMatch).toBeTruthy();
    if (fnMatch) {
      expect(fnMatch[0]).not.toContain('Array.from');
      expect(fnMatch[0]).toContain('campaignsByTenant');
    }

    // getLeadEnrollments should not use Array.from(...).filter
    const fnMatch2 = src.match(/function getLeadEnrollments[\s\S]*?^}/m);
    expect(fnMatch2).toBeTruthy();
    if (fnMatch2) {
      expect(fnMatch2[0]).not.toContain('Array.from');
      expect(fnMatch2[0]).toContain('enrollmentsByLead');
    }

    // Ads injection should also have secondary index
    const ads = readSource('apps/sales-autopilot/src/ads/injection.ts');
    expect(ads).toContain('promosByTenant');
    expect(ads).toContain('FIX-500-100');
  });
});
